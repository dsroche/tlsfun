"""Logic for TLS 1.3 server-side handshake."""

from typing import override, Any
from collections.abc import Callable
from secrets import SystemRandom
from random import Random
from dataclasses import dataclass, field
from functools import cached_property
import threading
from threading import Thread, current_thread
import logging
import socket
from io import StringIO

from util import pformat
from spec import UnpackError
from tls_common import *
from tls13_spec import (
    ServerStates,
    Version,
    ContentType,
    PskKeyExchangeMode,
    ServerSecrets,
    CertSecrets,
    EchSecrets,
    Record,
    CipherSuite,

    Handshake,
    HandshakeVariant,
    ClientHelloHandshake,
    ServerHelloHandshake,
    EncryptedExtensionsHandshake,
    CertificateHandshake,
    CertificateVerifyHandshake,
    FinishedHandshake,
    NewSessionTicketHandshake,

    ExtensionTypes,
    ServerExtensionVariant,
    KeyShareServerExtension,
    SupportedVersionsServerExtension,
    PreSharedKeyServerExtension,
    EncryptedClientHelloServerExtension,

    ClientExtensionVariant,
    SupportedVersionsClientExtension,
    ServerNameClientExtension,
    SignatureAlgorithmsClientExtension,
    SupportedGroupsClientExtension,
    PskKeyExchangeModesClientExtension,
    KeyShareClientExtension,
    PreSharedKeyClientExtension,
    EncryptedClientHelloClientExtension,

    OuterECHClientHello,
    InnerECHClientHello,
)
from tls_records import (
    Connection,
    HandshakeBuffer,
    AbstractHandshake,
    RecordTranscript,
    RecordReader,
    RecordWriter,
    PayloadProcessor,
    DEFAULT_LEGACY_VERSION,
    DEFAULT_LEGACY_COMPRESSION,
    CCS_MESSAGE,
)
from tls_keycalc import (
    KeyCalc,
    HandshakeTranscript,
    ServerTicketer,
    calc_binder_key,
)
from tls_crypto import (
    gen_cert,
    get_hash_alg,
    get_cipher_alg,
    get_sig_alg,
    get_kex_alg,
    gen_server_secrets,
)

@dataclass
class _ServerHandshake(AbstractHandshake, PayloadProcessor):
    server_secrets: ServerSecrets
    ticketer: ServerTicketer
    rseed: int|None = None

    state: ServerStates = ServerStates.START
    ticket_count: int = 0
    hs_trans: HandshakeTranscript = field(default_factory=HandshakeTranscript)
    sh_exts: list[ServerExtensionVariant] = field(default_factory=list)
    ee_exts: list[ServerExtensionVariant] = field(default_factory=list)
    exts_received: set[ExtensionTypes] = field(default_factory=set)
    kex_modes: set[PskKeyExchangeMode] = field(default_factory=set)
    _chello: ClientHelloHandshake|None = None
    _kex_info: tuple[KeyShareServerExtension,bytes]|None = None
    saved_ech: OuterECHClientHello|None = None

    @property
    def cert_secrets(self) -> CertSecrets:
        return self.server_secrets.cert

    @cached_property
    def ech_secrets_list(self) -> tuple[EchSecrets,...]:
        return tuple(self.server_secrets.eches)

    @cached_property
    def rgen(self) -> Random:
        if self.rseed is None:
            return SystemRandom()
        else:
            return Random(self.rseed)

    @cached_property
    def key_calc(self) -> KeyCalc:
        return KeyCalc(self.hs_trans)

    @property
    def chello(self) -> ClientHelloHandshake:
        assert self._chello is not None, "chello not set"
        return self._chello

    @property
    def csuite(self) -> CipherSuite:
        return self.key_calc.cipher_suite

    @property
    def kex_info(self) -> tuple[KeyShareServerExtension,bytes]:
        assert self._kex_info is not None, "kex_info not set"
        return self._kex_info

    @override
    @property
    def started(self) -> bool:
        return self.state != ServerStates.START

    @override
    @property
    def connected(self) -> bool:
        return self.state == ServerStates.CONNECTED

    @override
    @property
    def can_send(self) -> bool:
        return ServerStates.WAIT_EOED <= self.state <= ServerStates.CONNECTED

    @override
    @property
    def can_recv(self) -> bool:
        return self.state == ServerStates.CONNECTED

    @override
    def begin(self, rreader: RecordReader, rwriter: RecordWriter) -> None:
        assert self.state == ServerStates.START
        self.rreader = rreader
        self.rreader.hs_buffer = HandshakeBuffer(owner=self)
        self.rwriter = rwriter

    def _send_hs_msg(self, msg: HandshakeVariant, vers:Version = DEFAULT_LEGACY_VERSION) -> None:
        logger.info(f"sending hs message {msg.typ} to client")
        raw = msg.pack()
        self.rwriter.send(Record.create(
            typ     = ContentType.HANDSHAKE,
            version = vers,
            payload = raw,
        ))
        self.hs_trans.add(msg, from_client=False)

    @override
    def process_hs_payload(self, raw: bytes) -> None:
        try:
            msg = Handshake.unpack(raw)
        except UnpackError as e:
            raise TlsError("Malformed handshake message") from e
        self.hs_trans.add(msg.variant, from_client=True)
        logger.info(f"Received handshake message {msg.typ} with length {len(raw)}")

        match (self.state, msg.variant):
            case (ServerStates.START, ClientHelloHandshake() as chello):
                self._process_client_hello(chello)
            case (ServerStates.WAIT_FINISHED, FinishedHandshake() as fin):
                self._process_finished(fin)
            case _:
                raise TlsError(f"Unexpected {msg.typ} in state {self.state}")

    def _process_client_hello(self, chello: ClientHelloHandshake) -> None:
        assert self.state == ServerStates.START

        # TODO check for acceptance of ECH

        self.state = ServerStates.RECVD_CH
        assert self._chello is None
        assert self._chello is None
        self._chello = chello

        ## negotiate parameters

        for csuite in chello.data.ciphers:
            try:
                _hash_alg = get_hash_alg(csuite)
                _cipher = get_cipher_alg(csuite)
            except ValueError:
                continue
            logger.info(f'negotiated cipher suite {csuite}')
            self.key_calc.cipher_suite = csuite
            break
        else:
            raise TlsError(f"no supported cipher suites in {chello.data.ciphers}")

        for ext in chello.data.extensions:
            self._process_client_ext(ext.variant)

        if ExtensionTypes.SUPPORTED_VERSIONS not in self.exts_received:
            raise TlsError("client does not support TLS 1.3")

        # PSK exchange mode logic
        use_psk = ExtensionTypes.PRE_SHARED_KEY in self.exts_received
        use_dh = ExtensionTypes.KEY_SHARE in self.exts_received

        if use_psk:
            if use_dh and PskKeyExchangeMode.PSK_DHE_KE in self.kex_modes:
                logger.info('using PSK plus DH mode')
            elif PskKeyExchangeMode.PSK_KE in self.kex_modes:
                logger.info('using PSK only mode')
                use_dh = False
            else:
                raise TlsError('could not negotiate compatible psk key exchange mode')
        elif use_dh:
            logger.info('using DH only mode')
            self.key_calc.set_psk(None)
        else:
            raise TlsError('no PSK or DH extension received!')

        if use_dh:
            kex_ext, kex_secret = self.kex_info
            self.sh_exts.append(kex_ext)
            self.key_calc.set_kex_secret(kex_secret)
        else:
            self.key_calc.set_kex_secret(None)

        self.state = ServerStates.NEGOTIATED

        ## construct and send server hello

        sh = ServerHelloHandshake.create(
            legacy_version     = DEFAULT_LEGACY_VERSION,
            server_random      = self.rgen.randbytes(32),
            session_id         = self.chello.data.session_id,
            cipher_suite       = self.csuite,
            legacy_compression = DEFAULT_LEGACY_COMPRESSION[0],
            extensions         = self.sh_exts,
        )

        self._send_hs_msg(sh)
        logger.info(f'sent SH')

        ## send ccs and update handshake sending key

        self.rwriter.send(CCS_MESSAGE)
        logger.info(f'sent change cipher spec to client')

        self.rwriter.rekey(self.csuite,
                           self.key_calc.server_handshake_traffic_secret)
        logger.info(f'switched to handshake encryption for sending')

        ## construct and send encrypted extensions

        self._send_hs_msg(EncryptedExtensionsHandshake.create(self.ee_exts))
        logger.info(f'sent EE')

        ## send Cert and CV if not using PSKs

        if not use_psk:
            self._send_hs_msg(CertificateHandshake.create(
                certificate_request_context = b'',
                certificate_list = [(self.cert_secrets.cert_der, b'')],
            ))
            logger.info(f'sent Cert')

            cvsig = get_sig_alg(self.cert_secrets.sig_alg).sign(
                self.cert_secrets.private_key, self.key_calc.server_cv_message)
            self._send_hs_msg(CertificateVerifyHandshake.create(
                algorithm = self.cert_secrets.sig_alg,
                signature = cvsig,
            ))
            logger.info(f'sent CV')

        ## send finished

        self._send_hs_msg(FinishedHandshake.create(self.key_calc.server_finished_verify))
        logger.info(f'sent SF')

        ## update sending key and state

        self.rwriter.rekey(self.csuite,
                           self.key_calc.server_application_traffic_secret)
        logger.info(f'switched to application key for sending')

        # TODO handle 0-RTT early data here

        self.rreader.rekey(self.csuite,
                           self.key_calc.client_handshake_traffic_secret)
        logger.info(f'switched to handshake key for receiving')

        self.state = ServerStates.WAIT_FLIGHT2

        # TODO handle client auth here

        self.state = ServerStates.WAIT_FINISHED


    def _process_client_ext(self, ext: ClientExtensionVariant) -> None:
        assert self.state == ServerStates.RECVD_CH
        self.exts_received.add(ext.typ)
        match ext:
            case SupportedVersionsClientExtension():
                if Version.TLS_1_3 not in ext.data:
                    raise TlsError("client does not support TLS 1.3")
                logger.info('negotiated TLS 1.3')
                self.sh_exts.append(SupportedVersionsServerExtension.create(
                    [Version.TLS_1_3],
                ))
            case ServerNameClientExtension():
                logger.info(f"Client sent SNI with hostnames '{[ent.host_name for ent in ext.data]}'")
            case SignatureAlgorithmsClientExtension():
                if self.cert_secrets.sig_alg not in ext.data:
                    raise TlsError(f"client doesn't support sig {self.cert_secrets.sig_alg}")
                logger.info(f'negotiated sig alg {self.cert_secrets.sig_alg}')
            case SupportedGroupsClientExtension():
                logger.info(f'server ignoring supported groups extension, will just look in key share')
            case PskKeyExchangeModesClientExtension():
                for mode in ext.data:
                    logger.info(f'client allows kex mode {mode}')
                    self.kex_modes.add(mode)
            case KeyShareClientExtension():
                for entry in ext.data:
                    try:
                        kex_alg = get_kex_alg(entry.group)
                    except ValueError:
                        continue
                    kex_private = kex_alg.gen_private(self.rgen)
                    logger.info(f'negotiated kex alg {entry.group}')
                    assert self._kex_info is None
                    self._kex_info = (
                        KeyShareServerExtension.create(
                            group  = entry.group,
                            pubkey = kex_alg.get_public(kex_private),
                        ),
                        kex_alg.exchange(kex_private, entry.pubkey),
                    )
                    break
                else:
                    raise TlsError(f"no supported group found in key share ext")
            case PreSharedKeyClientExtension():
                for (index, psk_identity) in enumerate(ext.data.identities):
                    logger.info(f'trying client-provided ticket {pformat(psk_identity.identity)}')
                    psk = self.ticketer.use_ticket(psk_identity, self.key_calc.cipher_suite)
                    if psk is not None:
                        logger.info(f'derived valid PSK {pformat(psk)}')
                        binder_key = calc_binder_key(self.chello, index, psk, self.key_calc.cipher_suite)
                        if binder_key != ext.data.binders.data[index]:
                            raise TlsError(f"binder key mismatch for selected index {index}")

                        self.key_calc.set_psk(psk)
                        self.sh_exts.append(PreSharedKeyServerExtension.create(
                            index,
                        ))
                        break
                else:
                    raise TlsError("none of the provided tickets could be used")
            case EncryptedClientHelloClientExtension():
                match ext.data.variant:
                    case OuterECHClientHello(data) as ech:
                        logger.info(f'got ECH from client (that will be rejected) with config id {ech.data.config_id}')
                        assert self.saved_ech is None
                        self.saved_ech = ech
                        self.ee_exts.append(EncryptedClientHelloServerExtension.create(
                            [es.config for es in self.ech_secrets_list],
                        ))
                    case InnerECHClientHello():
                        raise TlsTODO("don't know how to handle inner ECH yet")
            case _:
                logger.warning(f'IGNORING extension with type {ext.typ}')


    def _process_finished(self, cf: FinishedHandshake) -> None:
        if cf.data != self.key_calc.client_finished_verify:
            raise TlsError("client finished has incorrect verify string")
        logger.info('received correct CF; rekeying to complete handshake')
        self.rreader.rekey(self.csuite,
                           self.key_calc.client_application_traffic_secret)
        self.state = ServerStates.CONNECTED

        if self.ticketer is not None:
            logger.info('sending two reconnect tickets')
            self.send_ticket()
            self.send_ticket()

    def send_ticket(self, lifetime:int=60*60, current_time:float|None=None) -> None:
        """Generates and sends a fresh Ticket struct to the client.

        lifetime is the expiration lifetime, in seconds (default 1 hour).
        """
        self.ticket_count += 1
        ticket_nonce = self.ticket_count.to_bytes()

        ticket = self.ticketer.gen_ticket(
            secret = self.key_calc.ticket_secret(ticket_nonce),
            nonce = ticket_nonce,
            lifetime = lifetime,
            csuite = self.key_calc.cipher_suite,
            current_time = current_time,
        )

        self._send_hs_msg(NewSessionTicketHandshake.create(*ticket.uncreate()))


class Server(Connection):
    """Handles a single TLS 1.3 connection from the server side."""

    def __init__(self, server_secrets: ServerSecrets, ticketer: ServerTicketer, rseed:int|None=None) -> None:
        super().__init__(RecordTranscript(is_client=False), _ServerHandshake(server_secrets, ticketer, rseed))


class _ThreadLogFilter(logging.Filter):
    # inspired by https://stackoverflow.com/a/55035193/1008966
    def __init__(self, tname: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tname = tname

    def filter(self, record: logging.LogRecord) -> bool:
        return record.threadName == self._tname

server_thread_info = threading.local()

class _ServerThread:
    def __init__(self, handler: Callable[[Server], None], *args: Any, **kwargs: Any) -> None:
        self._server = Server(*args, **kwargs)
        self._handler = handler

    def __call__(self, sock: socket.socket, addr: tuple[str,int]) -> None:
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


def start_server(handler: Callable[[Server],None], hostname:str='localhost', port:int=5000, server_secrets:ServerSecrets|None=None, rseed:int|None=None) -> None:
    """Starts a server that calls a handler to handle each connection.

    Handler should be runnable and accept one argument of type Server.
    The Server object will be connected before the handler is started.
    Each connection will run in a separate thread.
    """
    if server_secrets is None:
        logger.info('generating new self-signed server cert and ECH config')
        server_secrets = gen_server_secrets(hostname)

    ticketer = ServerTicketer()

    count = 1
    with socket.create_server((hostname, port)) as ssock:
        while True:
            logger.info(f'listening for connection to {hostname} on port {port}')
            sock, addr = ssock.accept()
            st = _ServerThread(handler, server_secrets, ticketer, rseed)
            tname = f's{count}'
            sthread = Thread(name=tname, target=st, args=(sock,addr,))
            logger.info(f'launching new thread to handle client connection')
            sthread.start()
            count += 1
            if rseed is not None:
                rseed += 1
