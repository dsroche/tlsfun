"""Logic for TLS 1.3 server-side handshake."""

from secrets import SystemRandom
from random import Random
import threading
from threading import Thread, current_thread
import logging
import socket
from io import StringIO

from spec import kwdict, UnpackError
from tls_common import *
from tls13_spec import (
    ServerState,
    Version,
    Handshake,
    HandshakeType,
    ExtensionType,
    ContentType,
)
from tls_records import (
    Connection,
    HandshakeBuffer,
)
from tls_keycalc import (
    KeyCalc,
    HandshakeTranscript,
    ServerTicketer,
)
from tls_crypto import (
    gen_cert,
    get_hash_alg,
    get_cipher_alg,
    get_sig_alg,
    get_kex_alg,
)

class Server(Connection):
    """Handles a single TLS 1.3 connection from the server side."""

    def __init__(self, cert_secrets, ticketer, rseed=None):
        super().__init__(None, _ServerHandshake(cert_secrets, ticketer, rseed))


class _ServerHandshake:
    def __init__(self, cert_secrets, ticketer, rseed):
        self._state = ServerState.START
        self._cert_secrets = cert_secrets
        self._ticketer = ticketer
        self._ticket_count = 0
        self._rgen = SystemRandom() if rseed is None else Random(seed)
        self._hs_trans = HandshakeTranscript()
        self._key_calc = KeyCalc(self._hs_trans)
        self._sh_exts = []
        self._ee_exts = []
        self._exts_received = set()
        self._kex_modes = set()

    @property
    def started(self):
        return self._state != ServerState.START

    @property
    def connected(self):
        return self._state == ServerState.CONNECTED

    @property
    def can_send(self):
        return ServerState.WAIT_EOED <= self._state <= ServerState.CONNECTED

    @property
    def can_recv(self):
        return self._state == ServerState.CONNECTED

    def begin(self, rreader, rwriter):
        assert self._state == ServerState.START
        self._rreader = rreader
        self._rreader.hs_buffer = HandshakeBuffer(self)
        self._rwriter = rwriter

    def _send_hs_msg(self, typ, vers=Version.TLS_1_2, raw=None):
        assert raw is not None
        logger.info(f"sending hs message {typ} to client")
        self._rwriter.send(
            typ     = ContentType.HANDSHAKE,
            vers    = vers,
            payload = raw,
        )
        self._hs_trans.add(
            typ         = typ,
            from_client = False,
            data        = raw,
        )

    def process_hs_payload(self, raw):
        try:
            typ, body = Handshake.unpack(raw)
        except UnpackError as e:
            raise TlsError("Malformed handshake message") from e
        self._hs_trans.add(typ=typ, from_client=True, data=raw)
        logger.info(f"Received handshake message {typ} with length {len(raw)}")

        match (self._state, typ):
            case (ServerState.START, HandshakeType.CLIENT_HELLO):
                self._process_client_hello(body)
            case (ServerState.WAIT_FINISHED, HandshakeType.FINISHED):
                self._process_finished(body)
            case _:
                raise TlsError(f"Unexpected {typ} in state {self._state}")

    def _process_client_hello(self, body):
        assert self._state == ServerState.START
        self._state = ServerState.RECVD_CH

        ## negotiate parameters

        for csuite in body.ciphers:
            try:
                self._hash_alg = get_hash_alg(csuite)
                self._cipher = get_cipher_alg(csuite)
            except ValueError:
                continue
            logger.info(f'negotiated cipher suite {csuite}')
            self._key_calc.cipher_suite = csuite
            break
        else:
            raise TlsError(f"no supported cipher suites in {body.ciphers}")

        for ext in body.extensions:
            self._process_client_ext(ext)

        if ExtensionType.SUPPORTED_VERSIONS not in self._exts_received:
            raise TlsError("client does not support TLS 1.3")
        if ExtensionType.KEY_SHARE not in self._exts_received:
            # TODO allow for PSK-only mode
            raise TlsError("client did not provide a key exchange share")
        # TODO allow psks
        self._key_calc.psk = None

        self._state = ServerState.NEGOTIATED

        ## construct and send server hello

        sh_raw = Handshake.pack(
            typ = HandshakeType.SERVER_HELLO,
            body = kwdict(
                server_random = self._rgen.randbytes(32),
                session_id    = body.session_id,
                cipher_suite  = self._key_calc.cipher_suite,
                extensions    = self._sh_exts,
            ),
        )

        self._send_hs_msg(typ=HandshakeType.SERVER_HELLO, raw=sh_raw)
        logger.info(f'sent SH')

        ## send ccs and update handshake sending key

        self._rwriter.send(typ=ContentType.CHANGE_CIPHER_SPEC, payload=b'\x01')
        logger.info(f'sent change cipher spec to client')

        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self._key_calc.server_handshake_traffic_secret)
        logger.info(f'switched to handshake encryption for sending')

        ## construct and send encrypted extensions

        ee_raw = Handshake.pack(
            typ  = HandshakeType.ENCRYPTED_EXTENSIONS,
            body = [],
        )
        self._send_hs_msg(typ=HandshakeType.ENCRYPTED_EXTENSIONS, raw=ee_raw)
        logger.info(f'sent EE')

        ## send Cert and CV

        cert_raw = Handshake.pack(
            typ  = HandshakeType.CERTIFICATE,
            body = kwdict(
                certificate_request_context = b'',
                certificate_list = [kwdict(
                    cert_data  = self._cert_secrets.cert_der,
                    extensions = b'',
                )],
            ),
        )
        self._send_hs_msg(typ=HandshakeType.CERTIFICATE, raw=cert_raw)
        logger.info(f'sent Cert')

        cvsig = get_sig_alg(self._cert_secrets.sig_alg).sign(
            self._cert_secrets.private_key, self._key_calc.server_cv_message)
        cv_raw = Handshake.pack(
            typ  = HandshakeType.CERTIFICATE_VERIFY,
            body = kwdict(
                algorithm = self._cert_secrets.sig_alg,
                signature = cvsig,
            ),
        )
        self._send_hs_msg(typ=HandshakeType.CERTIFICATE_VERIFY, raw=cv_raw)
        logger.info(f'sent CV')

        ## send finished

        sf_raw = Handshake.pack(
            typ  = HandshakeType.FINISHED,
            body = self._key_calc.server_finished_verify,
        )
        self._send_hs_msg(typ=HandshakeType.FINISHED, raw=sf_raw)
        logger.info(f'sent SF')

        ## update sending key and state

        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self._key_calc.server_application_traffic_secret)
        logger.info(f'switched to application key for sending')

        # TODO handle 0-RTT early data here

        self._rreader.rekey(self._cipher, self._hash_alg,
                            self._key_calc.client_handshake_traffic_secret)
        logger.info(f'switched to handshake key for receiving')

        self._state = ServerState.WAIT_FLIGHT2

        # TODO handle client auth here

        self._state = ServerState.WAIT_FINISHED


    def _process_client_ext(self, ext):
        assert self._state == ServerState.RECVD_CH
        self._exts_received.add(ext.typ)
        match ext.typ:
            case ExtensionType.SUPPORTED_VERSIONS:
                if Version.TLS_1_3 not in ext.data:
                    raise TlsError("client does not support TLS 1.3")
                logger.info('negotiated TLS 1.3')
                self._sh_exts.append(kwdict(
                    typ = ExtensionType.SUPPORTED_VERSIONS,
                    data = Version.TLS_1_3,
                ))
            case ExtensionType.SERVER_NAME:
                logger.info(f"Client sent SNI with hostnames '{[ent.host_name for ent in ext.data]}'")
            case ExtensionType.SIGNATURE_ALGORITHMS:
                if self._cert_secrets.sig_alg not in ext.data:
                    raise TlsError(f"client doesn't support sig {self._cert_secrets.sig_alg}")
                logger.info(f'negotiated sig alg {self._cert_secrets.sig_alg}')
            case ExtensionType.SUPPORTED_GROUPS:
                logger.info(f'server ignoring supported groups extension, will just look in key share')
            case ExtensionType.PSK_KEY_EXCHANGE_MODES:
                for mode in ext.data:
                    logger.info(f'client allows kex mode {mode}')
                    self._kex_modes.add(mode)
            case ExtensionType.KEY_SHARE:
                for (group, pubkey) in ext.data:
                    try:
                        kex_alg = get_kex_alg(group)
                    except ValueError:
                        continue
                    kex_private = kex_alg.gen_private(self._rgen)
                    self._sh_exts.append(kwdict(
                        typ  = ExtensionType.KEY_SHARE,
                        data = kwdict(
                            group  = group,
                            pubkey = kex_alg.get_public(kex_private),
                        ),
                    ))
                    logger.info(f'negotiated kex alg {group}')
                    self._key_calc.kex_secret = kex_alg.exchange(kex_private, pubkey)
                    break
                else:
                    raise TlsError(f"no supported group found in key share ext")
            case ExtensionType.PRE_SHARED_KEY:
                for (index, psk_identity) in ext.data.identitites:
                    logger.info(f'trying client-provided ticket {pformat(psk_identity.identity)}')
                    psk = use_ticket(psk_identity, self._key_calc.cipher_suite)
                    if psk is not None:
                        logger.info(f'derived valid PSK {pformat(psk)}')
                        self._key_calc.psk = psk
            case _:
                logger.info(f'IGNORING extension with type {ext.typ}')


    def _process_finished(self, body):
        if body != self._key_calc.client_finished_verify:
            raise TlsError("client finished has incorrect verify string")
        logger.info('received correct CF; rekeying to complete handshake')
        self._rreader.rekey(self._cipher, self._hash_alg,
                            self._key_calc.client_application_traffic_secret)
        self._state = ServerState.CONNECTED

        if self._ticketer is not None:
            logger.info('sending two reconnect tickets')
            self.send_ticket()
            self.send_ticket()


    def send_ticket(self, lifetime=60*60, current_time=None):
        """Generates and sends a fresh Ticket struct to the client.

        lifetime is the expiration lifetime, in seconds (default 1 hour).
        """
        self._ticket_count += 1
        ticket_nonce = self._ticket_count.to_bytes()

        ticket = self._ticketer.gen_ticket(
            secret = self._key_calc.ticket_secret(ticket_nonce),
            nonce = ticket_nonce,
            lifetime = lifetime,
            csuite = self._key_calc.cipher_suite,
            current_time = current_time,
        )

        self._send_hs_msg(
            typ = HandshakeType.NEW_SESSION_TICKET,
            raw = Handshake.pack(typ=HandshakeType.NEW_SESSION_TICKET, body=ticket),
        )


def serve_once(hostname='localhost', port=5000, cert_secrets=None, rseed=None):
    """Starts a server that accepts exactly one connection.

    Returns the connected Server object.
    """
    if cert_secrets is None:
        logger.info('generating new self-signed server cert')
        cert_secrets = gen_cert(hostname)

    with socket.create_server((hostname, port)) as ssock:
        logger.info(f'listening for connection to {hostname} on port {port}')
        sock, addr = ssock.accept()
        logger.info(f'got a connection from {addr}')
        server = Server(cert_secrets, None, rseed)
        server.connect_socket(sock)
        return server


class _ThreadLogFilter(logging.Filter):
    # inspired by https://stackoverflow.com/a/55035193/1008966
    def __init__(self, tname, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tname = tname

    def filter(self, record):
        return record.threadName == self._tname


server_thread_info = threading.local()


class _ServerThread:
    def __init__(self, handler, *args, **kwargs):
        self._server = Server(*args, **kwargs)
        self._handler = handler

    def __call__(self, sock, addr):
        tname = current_thread().name
        server_thread_info.log_buffer = StringIO()
        log_handle = logging.StreamHandler(server_thread_info.log_buffer)
        log_handle.setLevel(logging.INFO)
        log_handle.setFormatter(logging.Formatter())
        log_handle.addFilter(_ThreadLogFilter(tname))
        logger.addHandler(log_handle)
        logger.info(f'started connection from client at {addr}')
        try:
            self._server.connect_socket(sock)
            self._handler(self._server)
        finally:
            logger.removeHandler(log_handle)


def start_server(handler, hostname='localhost', port=5000, cert_secrets=None, rseed=None):
    """Starts a server that calls a handler to handle each connection.

    Handler should be runnable and accept one argument of type Server.
    The Server object will be connected before the handler is started.
    Each connection will run in a separate thread.
    """
    if cert_secrets is None:
        logger.info('generating new self-signed server cert')
        cert_secrets = gen_cert(hostname)

    ticketer = ServerTicketer()

    count = 1
    with socket.create_server((hostname, port)) as ssock:
        while True:
            logger.info(f'listening for connection to {hostname} on port {port}')
            sock, addr = ssock.accept()
            st = _ServerThread(handler, cert_secrets, ticketer, rseed)
            tname = f's{count}'
            sthread = Thread(name=tname, target=st, args=(sock,addr,))
            logger.info(f'launching new thread to handle client connection')
            sthread.start()
            count += 1
            if rseed is not None:
                rseed += 1
