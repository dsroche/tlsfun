"""Logic for TLS 1.3 server-side handshake."""

from tls_common import *
from tls13_spec import (
    ServerState,
)
from tls_records import (
    Connection,
)
from tls_keycalc import (
    KeyCalc,
)

class Server(Connection):
    def __init__(self):
        super().__init__(self, None, _ServerHandshake())

class _ServerHandshake:
    def __init__(self):
        self._state = ServerState.START
        self._hs_trans = HandshakeTranscript()
        self._key_calc = KeyCalc(self._hs_trans)

    @property
    def started(self):
        return self._state != ServerState.START

    @property
    def connected(self):
        return self._state == ServerState.CONNECTED

    @property
    def can_send(self):
        return ServerState.NEGOTIATED <= self._state <= ServerState.CONNECTED

    @property
    def can_recv(self):
        return self._state == ServerState.CONNECTED

    def begin(self, rreader, rwriter):
        assert self._state == ServerState.START
        self._rreader = rreader
        self._rreader.hs_buffer = HandshakeBuffer(self)
        self._rwriter = rwriter

    def _send_hs_msg(self, typ, vers=Version.TLS_1_2, raw):
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

        for csuite in body.ciphers:
            try:
                self._hash_alg = get_hash_alg(csuite)
                self._cipher = get_cipher_alg(csuite)
            except ValueError:
                continue
            self._cipher_suite = csuite
            break
        else:
            raise TlsError(f"unsupported cipher suites: {body.ciphers}")

        #TODO HERE





    def _process_finished(self, body):
        # FIXME TODO
        raise TlsTODO("not here yet")
