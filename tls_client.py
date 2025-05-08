"""High-level logic for TLS 1.3 client-side handshake."""

import time
from collections import namedtuple
from secrets import SystemRandom

from spec import kwdict
from tls_common import *
from tls13_spec import (
    Handshake,
    ClientState,
    HandshakeType,
    Record,
    ContentType,
    PskKeyExchangeMode,
    ExtensionType,
    Version,
)
from tls_crypto import (
    get_kex_alg,
    get_sig_alg,
    get_hash_alg,
    get_cipher_alg,
    extract_x509_pubkey,
    DEFAULT_KEX_GROUPS,
    DEFAULT_SIGNATURE_SCHEMES,
    DEFAULT_CIPHER_SUITES,
)
from tls_records import (
    RecordTranscript,
    DataBuffer,
    RecordReader,
    RecordWriter,
    HandshakeBuffer,
    Connection,
)
from tls_keycalc import KeyCalc, HandshakeTranscript


ClientSecrets = namedtuple(
        'ClientSecrets', 'psk kex_sks', defaults=[None, ()])


class Client(Connection):
    @classmethod
    def build(cls, *args, **kwargs):
        return cls(*build_client_hello(*args, **kwargs))

    def __init__(self, client_hello, client_secrets):
        super().__init__(client_secrets, _ClientHandshake(client_hello, client_secrets))

    @property
    def tickets(self):
        return tuple(self._handshake.tickets)


class _ClientHandshake:
    def __init__(self, client_hello, client_secrets):
        if isinstance(client_hello, bytes):
            client_hello = Handshake.unpack(Record.unpack(client_hello).payload)

        self._state = ClientState.START
        self._psk = client_secrets.psk

        # extract some data from the client hello
        self._sni = None
        self._kexes = {}

        need_kex_mode = need_psk = (self._psk is not None)
        self._psk_modes = set(PskKeyExchangeMode) # allow all modes if not specified

        for ext in client_hello.body.extensions:
            match ext.typ:
                case ExtensionType.SERVER_NAME:
                    if ext.data:
                        self._sni = ext.data[0].host_name
                case ExtensionType.KEY_SHARE:
                    for (group, _), private in zip(ext.data, client_secrets.kex_sks):
                        self._kexes[group] = private
                case ExtensionType.PSK_KEY_EXCHANGE_MODES:
                    self._psk_modes = set(ext.data)
                    need_kex_mode = False
                case ExtensionType.PRE_SHARED_KEY:
                    assert need_psk
                    need_psk = False
                case ExtensionType.EARLY_DATA:
                    raise TlsTODO('sending 0-RTT early data not supported yet')

        assert not need_kex_mode and not need_psk, "needed psk and psk exchange mode extensions in client hello but didn't get them"

        self._chello_payload = Handshake.pack(client_hello)
        self._hs_trans = HandshakeTranscript()
        self._key_calc = KeyCalc(self._hs_trans)
        self.tickets = []

    @property
    def started(self):
        return self._state != ClientState.START

    @property
    def connected(self):
        return self._state == ClientState.CONNECTED

    @property
    def can_send(self):
        return self._state == ClientState.CONNECTED

    @property
    def can_recv(self):
        return self._state == ClientState.CONNECTED

    def begin(self, rreader, rwriter):
        assert self._state == ClientState.START
        self._rreader = rreader
        self._rreader.hs_buffer = HandshakeBuffer(self)
        self._rwriter = rwriter
        self.send_hello()

    def _send_hs_msg(self, typ, vers=Version.TLS_1_2, raw=None):
        assert raw is not None
        logger.info(f"sending hs message {typ} to server")
        self._rwriter.send(
            typ     = ContentType.HANDSHAKE,
            vers    = vers,
            payload = raw,
        )
        self._hs_trans.add(
            typ         = typ,
            from_client = True,
            data        = raw,
        )

    def send_hello(self):
        assert self._state == ClientState.START
        self._send_hs_msg(
            typ  = HandshakeType.CLIENT_HELLO,
            vers = Version.TLS_1_0,
            raw  = self._chello_payload,
        )
        self._state = ClientState.WAIT_SH

    def process_hs_payload(self, raw):
        try:
            typ, body = Handshake.unpack(raw)
        except UnpackError as e:
            raise TlsError("Malformed handshake message") from e
        self._hs_trans.add(typ=typ, from_client=False, data=raw)
        logger.info(f"Received handshake message {typ} with length {len(raw)}")

        match (self._state, typ):
            case (ClientState.WAIT_SH, HandshakeType.SERVER_HELLO):
                self._process_server_hello(body)
            case (ClientState.WAIT_EE, HandshakeType.ENCRYPTED_EXTENSIONS):
                self._process_ee(body)
            case ((ClientState.WAIT_CERT_CR | ClientState.WAIT_CERT), HandshakeType.CERTIFICATE):
                self._process_cert(body)
            case (ClientState.WAIT_CERT_CR, HandshakeType.CERTIFICATE_REQUEST):
                raise TlsTODO("Not yet implemented handling cert request from server")
            case (ClientState.WAIT_CV, HandshakeType.CERTIFICATE_VERIFY):
                self._process_cv(body)
            case (ClientState.WAIT_FINISHED, HandshakeType.FINISHED):
                self._process_finished(body)
            case (ClientState.CONNECTED, HandshakeType.NEW_SESSION_TICKET):
                self._process_ticket(body)
            case (ClientState.CONNECTED, HandshakeType.KEY_UPDATE):
                raise TlsTODO("Not yet implemented handling key update request")
            case _:
                raise TlsError(f"Unexpected {typ} in state {self._state}")

    def _process_server_hello(self, body):
        if body.server_random.hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
            # it's the sha256 hash of 'HelloRetryRequest'
            raise TlsTODO("HelloRetryRequest not yet implemented")

        self._cipher_suite = body.cipher_suite

        kex_secret = None
        got_psk = False

        for ext in body.extensions:
            match ext.typ:
                case ExtensionType.KEY_SHARE:
                    group = ext.data.group
                    private = self._kexes[group]
                    try:
                        kex = get_kex_alg(group)
                    except ValueError:
                        raise TlsError(f"no implementation for kex group {group}")
                    kex_secret = kex.exchange(private, ext.data.pubkey)
                case ExtensionType.SUPPORTED_VERSIONS:
                    assert ext.data == Version.TLS_1_3
                case ExtensionType.PRE_SHARED_KEY:
                    if ext.data != 0:
                        raise TlsError(f'unexpected index in PRE_SHARED_KEY: {ext.body}')
                    got_psk = True
                case _:
                    logger.warning("Ignoring server extension", ext.typ)

        match ((kex_secret is not None), (self._psk is not None), got_psk):
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

        # set up handshake keys
        self._key_calc.psk = self._psk
        self._key_calc.kex_secret = kex_secret
        self._rreader.rekey(self._cipher, self._hash_alg, self._key_calc.server_handshake_traffic_secret)

        logger.info(f"Finished processing server hello")
        self._state = ClientState.WAIT_EE

    def _process_ee(self, body):
        for ext in body:
            match ext.typ:
                case ExtensionType.SERVER_NAME:
                    if ext.data:
                        raise TlsError(f"SERVER_NAME extension data should be empty, but got {ext.data}")
                case ExtensionType.SUPPORTED_GROUPS:
                    # only informational; ignore
                    pass
                case _:
                    logger.warning("Ignoring server extension extension", ext.typ)

        logger.info(f"Finished processing server encrypted extensions")
        if self._psk is None:
            self._state = ClientState.WAIT_CERT_CR
        else:
            self._state = ClientState.WAIT_FINISHED

    def _process_cert(self, body):
        if body.certificate_request_context:
            raise TlsError(f"certificate_request_context field should be empty")
        self._cert_chain = []
        for cert_data, exts in body.certificate_list:
            if exts:
                raise TlsError(f"certificate extensions should be empty")
            self._cert_chain.append(cert_data)
        logger.info(f"Received a length-{len(self._cert_chain)} certificate chain"
            f" with lengths {[len(x) for x in self._cert_chain]}")
        self._cert_pubkey = extract_x509_pubkey(self._cert_chain[0])

        self._state = ClientState.WAIT_CV

    def _process_cv(self, body):
        logger.info(f"Received a length-{len(body.signature)} sig of type {body.algorithm}")
        self._sig_alg = body.algorithm
        try:
            sigscheme = get_sig_alg(self._sig_alg)
        except ValueError as e:
            raise TlsError(f"signature algorithm {self._sig_alg} not supported") from e
        check = sigscheme.verify(
            pubkey    = self._cert_pubkey,
            signature = body.signature,
            data      = self._key_calc.server_cv_message,
        )
        if check:
            logger.info("certificate verify signature check passed")
        else:
            raise TlsError("signature check failed in CERTIFICATE_VERIFY")

        self._state = ClientState.WAIT_FINISHED

    def _process_finished(self, body):
        if body != self._key_calc.server_finished_verify:
            raise TlsError("verify data in server finished message doesn't match")
        logger.info(f"Received correct SERVER FINISHED.")

        logger.info(f"Sending change cipher spec to server")
        self._rwriter.send(
            typ     = ContentType.CHANGE_CIPHER_SPEC,
            payload = b'\x01',
        )

        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self._key_calc.client_handshake_traffic_secret)

        client_finished = Handshake.pack(
            typ  = HandshakeType.FINISHED,
            body = self._key_calc.client_finished_verify,
        )
        self._send_hs_msg(typ=HandshakeType.FINISHED, raw=client_finished)
        logger.info(f"Sent CLIENT FINISHED. Handshake complete!")

        self._rreader.rekey(self._cipher, self._hash_alg,
                            self._key_calc.server_application_traffic_secret)
        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self._key_calc.client_application_traffic_secret)

        self._state = ClientState.CONNECTED

    def _process_ticket(self, body):
        self.tickets.append(self._key_calc.ticket_info(body, modes=self._psk_modes))
        logger.info("got and stored a reconnect ticket")


def build_client_hello(
        sni = None, # server name indication
        ciphers = None, # default, replace with DEFAULT_CIPHER_SUITES or ticket.csuite
        kex_groups = DEFAULT_KEX_GROUPS,
        kex_share_groups = None, # defaults to the first one in kex_groups
        sig_algs = DEFAULT_SIGNATURE_SCHEMES,
        ticket = None, # reconnect ticket to use as PSK for reconnect
        psk_modes = (PskKeyExchangeMode.PSK_DHE_KE,),
        send_time = None, # default to current time
        seed = None, # optional seed for repeatability; NOT secure
        ):
    """Returns (unpacked) ClientHello handshake struct and ClientSecrets tuple."""

    rgen = SystemRandom() if seed is None else Random(seed)

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
