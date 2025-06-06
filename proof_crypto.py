"""Classes to handle TLS crypto for the proof protocol"""
import socket
import time
from random import Random
from secrets import SystemRandom

from proof_common import VerifierError, ProverError
from proof_connections import ProverRecordReader
from spec import kwdict, Raw
from tls13_spec import HandshakeType, PskKeyExchangeMode, ExtensionType, Version, \
    ClientExtension, ECHClientHelloType, HpkeKdfId, HpkeAeadId, Handshake, ClientState, ContentType, Record
from tls_client import ClientHandshake, ClientSecrets, Client
from tls_common import TlsError, TlsTODO, logger
from tls_crypto import get_kex_alg, DEFAULT_KEX_GROUPS, DEFAULT_SIGNATURE_SCHEMES, DEFAULT_CIPHER_SUITES, get_hash_alg, \
    get_cipher_alg
from tls_keycalc import KeyCalc, HandshakeTranscript
from tls_records import HandshakeBuffer, RecordWriter, RecordReader, RecordTranscript, DataBuffer, Connection


class VerifierCrypto:
    """Performs the TLS crypto operations done by the verifier and stores the relevant data"""
    def __init__(self, num_servers, ciphersuite, group, rgen=None):
        self._num_servers = num_servers
        self._ciphersuite = ciphersuite
        self._group = group
        self._rgen = rgen

        self._kex = get_kex_alg(group)
        self._key_calcs = []

        self._dh_secrets = []
        self._twopc_dh_secret = None
        self.dh_shares = []
        self._dh_outputs = []
        self.twopc_dh_share = None

        self.hs_keys = []
        self.app_keys = []

    def gen_secrets(self):
        if len(self._dh_secrets) > 0 or self._twopc_dh_secret is not None:
            raise VerifierError('already generated secrets')
        self._dh_secrets = [self._kex.gen_private(self._rgen) for _ in range(self._num_servers)]
        self.dh_shares = [self._kex.get_public(secret) for secret in self._dh_secrets]
        self._twopc_dh_secret = self._kex.gen_private(self._rgen)
        self.twopc_dh_share = self._kex.get_public(self._twopc_dh_secret)

    def exchange_all(self, server_shares):
        if len(self._dh_secrets) == 0:
            raise VerifierError('need to generate secrets first')
        if len(self._dh_outputs) > 0:
            raise VerifierError('already did key exchange')
        assert len(server_shares) == self._num_servers
        self._dh_outputs = [self._kex.exchange(priv, pub) for (priv,pub) in zip(self._dh_secrets, server_shares)]

    def compute_handshake_keys(self, hashes):
        if len(self._dh_outputs) == 0:
            raise VerifierError('need to run key exchange first')
        if len(self._key_calcs) > 0:
            raise VerifierError('already computed handshake keys')
        assert len(hashes) == self._num_servers
        hs_keys = []
        for i, h in enumerate(hashes):
            trans = PartialHandshakeTranscript()
            key_calc = KeyCalc(trans)
            key_calc.cipher_suite = self._ciphersuite
            key_calc.psk = None
            trans.set_hash(HandshakeType.SERVER_HELLO, h)
            key_calc.kex_secret = self._dh_outputs[i]
            self._key_calcs.append(key_calc)
            hs_keys.append((key_calc.client_handshake_traffic_secret, key_calc.server_handshake_traffic_secret))
        return hs_keys

    def compute_application_keys(self, hashes):
        if len(self._key_calcs) == 0:
            raise VerifierError('need to compute handshake keys first')

        app_keys = []
        for key_calc, h in zip(self._key_calcs, hashes):
            key_calc._hs_trans.set_hash(HandshakeType.FINISHED, h)
            app_keys.append((key_calc.client_application_traffic_secret, key_calc.server_application_traffic_secret))
        return app_keys

class ProverClientPhase1(Connection):
    """Manages connection to a single TLS server from the prover."""
    def __init__(self, server_id, ciphersuite, group, rseed=None):

        self._server_id = server_id
        self._ciphersuite = ciphersuite
        self._group = group
        self._rseed = rseed

        self._host = server_id.hostname
        self._port = server_id.port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._transcript = RecordTranscript(None)
        self._app_data_in = DataBuffer()
        self._connected = False

        self._kex_share = None
        self._handshake = None
        self._ech = None

    def __del__(self):
        """Fallback way to close the socket. The expected use is to close the connection manually when it's no
        longer needed. If that doesn't happen, this closes the socket when the object is deleted."""
        self.close()

    def close(self):
        self._sock.close()

    def connect(self):
        if self._connected:
            raise ProverError("already connected, can't connect again")
        try:
            self._sock.connect((self._host, self._port))
        except ConnectionRefusedError:
            raise ProverError(f"couldn't connect to the server on {self._host}:{self._port}. Did you start the server?")

        rfile = self._sock.makefile('rb')
        wfile = self._sock.makefile('wb')
        self._rreader = ProverRecordReader(rfile, self._transcript, self._app_data_in)
        self._rwriter = RecordWriter(wfile, self._transcript)

        self._rreader.hs_buffer = HandshakeBuffer(self._handshake)
        self._handshake._rreader = self._rreader
        self._handshake._rwriter = self._rwriter

        self._connected = True
        logger.info(f'connected to server on port {self._port}')


    def set_kex_share(self, kex_share):
        self._kex_share = kex_share
        # TODO: make this ECH
        self._ech = build_prover_client_hello(kex_share=kex_share, ciphers=[self._ciphersuite], kex_groups=[self._group], rseed=self._rseed)[0]

        self._handshake = ProverHandshakePhase1(self._ech)

    def send_and_recv_hellos(self):
        if self._handshake is None:
            raise ProverError('key exchange share not provided')
        self.connect()
        self._handshake.send_hello()

        # get server hello and change cipher spec
        self._rreader.fetch()
        self._rreader.fetch()

        # get encrypted extensions, cert, cert verify, and server finished
        self._rreader.buffer_encrypted_records(4)

    def send_client_finished(self):
        self._handshake.send_finished()

    def get_encrypted_server_msgs(self):
        if len(self._rreader.buffered_records) == 0:
            raise ProverError('server messages not yet received')
        server_hello = self._transcript.records[2]
        return [Record.unpack(server_hello.raw)] + self._rreader.buffered_records

    def get_hash1(self):
        return self._handshake._hs_trans[HandshakeType.SERVER_HELLO, False]

    def get_hash4(self):
        return self._handshake._hs_trans[HandshakeType.FINISHED, False]

    def get_hash5(self):
        return self._handshake._hs_trans[HandshakeType.FINISHED, True]

    def set_handshake_secrets(self, chts, shts):
        self._handshake.set_handshake_secrets(chts, shts)

    def set_application_secrets(self, cats, sats):
        self._handshake.set_application_secrets(cats, sats)

    def process_ticket(self):
        self._handshake._rreader.fetch()
        if len(self._handshake.tickets) == 0:
            raise ProverError('did not receive any tickets')
        self.tickets = self._handshake.tickets

class ProverHandshakePhase1(ClientHandshake):
    """Modified TLS client for the prover"""
    """
    For the first phase, need to do the following:
    - Create (encrypted) client hello that uses a given DH share. Save the randomness used to encrypt!
    - Accept handshake keys to decrypt and verify handshake messages
    - Accept application keys 
    - Decrypt and store ticket
    For second phase (DO THIS IN A DIFFERENT CLASS):
    - Create another ECH with a given DH share
    - Derive resumption secrets from phase 1
    """
    def __init__(self, client_hello):
        super().__init__(client_hello, ClientSecrets())
        self._received_hs_secrets = False
        self._received_app_secrets = False

    def set_handshake_secrets(self, chts, shts):
        if self._received_hs_secrets:
            raise ProverError('handshake secrets already set')
        self._received_hs_secrets = True
        self._shts = shts
        self._chts = chts
        self._rreader.rekey(self._cipher, self._hash_alg, shts)
        self._key_calc.server_handshake_traffic_secret = shts
        self._key_calc.client_handshake_traffic_secret = chts
        self._rreader.process_buffered_records()

    def set_application_secrets(self, cats, sats):
        if self._received_app_secrets:
            raise ProverError('application secrets already set')
        self._sats = sats
        self._cats = cats
        self._rreader.rekey(self._cipher, self._hash_alg, sats)
        self._rwriter.rekey(self._cipher, self._hash_alg, cats)
        self._key_calc.server_application_traffic_secret = sats
        self._key_calc.client_application_traffic_secret = cats
        self._received_app_secrets = True

    def _process_server_hello(self, body):
        if body.server_random.hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
            # it's the sha256 hash of 'HelloRetryRequest'
            raise TlsTODO("HelloRetryRequest not yet implemented")

        self._cipher_suite = body.cipher_suite

        got_psk = False
        got_kex_share = False

        for ext in body.extensions:
            match ext.typ:
                case ExtensionType.KEY_SHARE:
                    got_kex_share = True
                    group = ext.data.group
                    try:
                        get_kex_alg(group)
                    except ValueError:
                        raise TlsError(f"no implementation for kex group {group}")
                    self.server_kex_share = ext.data.pubkey
                case ExtensionType.SUPPORTED_VERSIONS:
                    assert ext.data == Version.TLS_1_3
                case ExtensionType.PRE_SHARED_KEY:
                    if ext.data != 0:
                        raise TlsError(f'unexpected index in PRE_SHARED_KEY: {ext.body}')
                    got_psk = True
                case _:
                    logger.warning("Ignoring server extension", ext.typ)

        match (got_kex_share, (self._psk is not None), got_psk):
            case (True, True, True):
                if PskKeyExchangeMode.PSK_DHE_KE not in self._psk_modes:
                    raise TlsError("server wants PSK_DHE_KE but client didn't ask for it")
            case (False, True, True):
                if PskKeyExchangeMode.PSK_KE not in self._psk_modes:
                    raise TlsError("server wants PSK_KE but client didn't ask for it")
            case (True, False, False):
                pass
            case other:
                raise TlsError(f"unclear what PSK/DHE mode to use:; check triple is {other}")

        # inform components of the cipher suite implementation
        try:
            self._hash_alg = get_hash_alg(self._cipher_suite)
            self._cipher = get_cipher_alg(self._cipher_suite)
        except ValueError as e:
            raise TlsError(f"cipher suite {self._cipher_suite} not supported") from e
        self._key_calc.cipher_suite = self._cipher_suite
        self._key_calc.psk = self._psk

        logger.info(f"Finished processing server hello.")
        self._state = ClientState.WAIT_EE

    def _process_ee(self, body):
        if not self._received_hs_secrets:
            raise ProverError('need to get handshake secrets from verifier to process encrypted handshake messages')
        super()._process_ee(body)

    def _process_finished(self, body):
        if not self._received_hs_secrets:
            raise ProverError('need to get handshake secrets from verifier to process encrypted handshake messages')
        if body != self._key_calc.server_finished_verify:
            raise TlsError("verify data in server finished message doesn't match")
        logger.info(f"Received correct SERVER FINISHED.")

        logger.info(f"Sending change cipher spec to server")
        self._rwriter.send(
            typ     = ContentType.CHANGE_CIPHER_SPEC,
            payload = b'\x01',
        )

        self._rwriter.rekey(self._cipher, self._hash_alg, self._chts)

    def _process_ticket(self, body):
        self.tickets.append(body)
        logger.info('got and stored a reconnect ticket')

    def send_finished(self):
        if not self._received_hs_secrets:
            raise ProverError('need to get handshake secrets from verifier to process encrypted handshake messages')
        client_finished = Handshake.pack(
            typ  = HandshakeType.FINISHED,
            body = self._key_calc.client_finished_verify,
        )
        self._send_hs_msg(typ=HandshakeType.FINISHED, raw=client_finished)
        self._state = ClientState.CONNECTED

class ProverHandshakePhase2(ClientHandshake):
    pass

class PartialHandshakeTranscript(HandshakeTranscript):
    """Helper class to compute key derivation while only learning partial transcript hashes, not the full transcript"""
    def set_hash(self, typ, hash_val):
        match typ:
            case HandshakeType.SERVER_HELLO:
                self._lookup[typ, False] = hash_val
            case HandshakeType.FINISHED:
                self._lookup[typ, False] = hash_val
            case _:
                raise ValueError('adding unexpected hash value')
        self._history.append(hash_val)

    def add(self, typ, from_client, data):
        """stub: this method isn't needed"""
        pass

def build_prover_client_hello(
        sni = None, # server name indication
        ciphers = None, # default, replace with DEFAULT_CIPHER_SUITES or ticket.csuite
        kex_groups = DEFAULT_KEX_GROUPS,
        kex_share_groups = None, # defaults to the first one in kex_groups
        kex_share = None,  # key exchange share to be used
        sig_algs = DEFAULT_SIGNATURE_SCHEMES,
        ticket = None, # reconnect ticket to use as PSK for reconnect
        psk_modes = (PskKeyExchangeMode.PSK_DHE_KE,),
        send_time = None, # default to current time
        rseed = None, # optional seed for repeatability; NOT secure
        grease_ech = True, # send a GREASE ECH extension (to gather server parameters)
        ):
    """Returns (unpacked) ClientHello handshake struct and ClientSecrets tuple."""

    rgen = SystemRandom() if rseed is None else Random(rseed)

    if ciphers is None:
        if ticket is None:
            ciphers = DEFAULT_CIPHER_SUITES
        else:
            ciphers = (ticket.csuite,)
    elif ticket is not None:
        if ticket.csuite not in ciphers:
            raise ValueError("incompatible cipher suites for this ticket")

    if send_time is None:
        send_time = time.time()

    # generate key exchange secrets and shares
    kex_sks = []
    shares = []
    if kex_share_groups is None:
        kex_share_groups = kex_groups[:1]
    if kex_share is not None:
        if len(kex_share_groups) != 1:
            raise ValueError("when key exchange value is specified, only one group can be supported")
        shares = [{'group': kex_share_groups[0], 'pubkey': kex_share}]
    else:
        for group in kex_share_groups:
            kex = get_kex_alg(group)
            secret = kex.gen_private(rgen)
            share = kex.get_public(secret)
            kex_sks.append(secret)
            shares.append({'group': group, 'pubkey': share})

    if not shares and ticket is None:
        raise ValueError("need either DHE or PSK (or both), but got neither")

    # fill in client hello extension entries
    extensions = []
    if sni is not None:
        extensions.append((ExtensionType.SERVER_NAME,
                           [{'host_name': sni}]))

    # indicates all point formats are accepted (legacy)
    extensions.append((ExtensionType.LEGACY_EC_POINT_FORMATS, bytes.fromhex('03000102')))

    # which groups supported for key exchange
    extensions.append((ExtensionType.SUPPORTED_GROUPS, kex_groups))

    # more backwards compatibility empty info,
    # probably not necessary but who knows
    extensions.append((ExtensionType.LEGACY_SESSION_TICKET, b''))
    extensions.append((ExtensionType.LEGACY_ENCRYPT_THEN_MAC, b''))
    extensions.append((ExtensionType.LEGACY_EXTENDED_MASTER_SECRET, b''))

    # which signature algorithms allowed for CertificateVerify message
    extensions.append((ExtensionType.SIGNATURE_ALGORITHMS, sig_algs))

    # indicate only TLS 1.3 is supported
    extensions.append((ExtensionType.SUPPORTED_VERSIONS, [Version.TLS_1_3]))

    # indicate whether DHE must still be done on resumption with a ticket
    extensions.append((ExtensionType.PSK_KEY_EXCHANGE_MODES, list(psk_modes)))

    if shares:
        # send the DHE public key
        extensions.append((ExtensionType.KEY_SHARE, shares))

    # add GREASE ECH if requested
    extensions.append(ClientExtension.prepack(
        typ  = ExtensionType.ENCRYPTED_CLIENT_HELLO,
        data = kwdict(
            typ  = ECHClientHelloType.OUTER,
            data = kwdict(
                cipher_suite = kwdict(
                    kdf_id = HpkeKdfId.HKDF_SHA256,
                    aead_id = HpkeAeadId.CHACHA20_POLY1305,
                ),
                config_id = rgen.randrange(2**8),
                enc = rgen.randbytes(32),
                payload = rgen.randbytes(239),
            ),
        ),
    ))

    # calculate client hello handshake message
    ch = Handshake.prepack(
        typ  = HandshakeType.CLIENT_HELLO,
        body = kwdict(
            client_random = rgen.randbytes(32),
            session_id    = rgen.randbytes(32),
            ciphers       = ciphers,
            extensions    = extensions,
        ),
    )

    # add PRE_SHARED_KEY extension if using a ticket
    psk = None
    if ticket is not None:
        ch = ticket.add_psk_ext(ch, send_time)
        psk = ticket.secret

    return Handshake.prepack(ch), ClientSecrets(kex_sks=kex_sks, psk=psk)


