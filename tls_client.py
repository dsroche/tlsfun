"""High-level logic for TLS 1.3 client-side handshake."""

import time
from collections import namedtuple
from collections.abc import Iterable
from typing import Self, Any, override
from dataclasses import dataclass, field
from secrets import SystemRandom
from random import Random

from util import same_args
from spec import UnpackError
from tls_common import *
from tls13_spec import (
    Handshake,
    ClientStates,
    HandshakeType,
    Record,
    ContentType,
    PskKeyExchangeMode,
    ExtensionTypes,
    Version,
    ClientExtension,
    ECHClientHelloType,
    HpkeKdfId,
    HpkeAeadId,
    CipherSuite,
    NamedGroup,
    SignatureScheme,
    ClientHelloHandshake,
    ClientSecrets,
    ClientExtensionVariant,
    ServerNameClientExtension,
    GenericClientExtension,
    SupportedGroupsClientExtension,
    SignatureAlgorithmsClientExtension,
    SupportedVersionsClientExtension,
    PskKeyExchangeModesClientExtension,
    KeyShareClientExtension,
    OuterECHClientHello,
    EncryptedClientHelloClientExtension,
    ECHConfigVariant,
    PreSharedKeyClientExtension,
    HandshakeVariant,
    ServerHelloHandshake,
    EncryptedExtensionsHandshake,
    CertificateHandshake,
    CertificateVerifyHandshake,
    FinishedHandshake,
    NewSessionTicketHandshake,
    KeyShareServerExtension,
    SupportedVersionsServerExtension,
    PreSharedKeyServerExtension,
    ServerNameServerExtension,
    SupportedGroupsServerExtension,
    EncryptedClientHelloServerExtension,
)
from tls_crypto import (
    get_kex_alg,
    get_sig_alg,
    get_hash_alg,
    get_cipher_alg,
    extract_x509_pubkey,
    KexAlg,
    DEFAULT_KEX_GROUPS,
    DEFAULT_KEX_MODES,
    DEFAULT_SIGNATURE_SCHEMES,
    DEFAULT_CIPHER_SUITES,
    DEFAULT_HPKE_CSUITES,
)
from tls_records import (
    RecordTranscript,
    DataBuffer,
    RecordReader,
    RecordWriter,
    HandshakeBuffer,
    Connection,
    HOST_NAME_TYPE,
    DEFAULT_LEGACY_VERSION,
    DEFAULT_LEGACY_COMPRESSION,
    CCS_PAYLOAD,
    AbstractHandshake,
    PayloadProcessor,
)
from tls_keycalc import KeyCalc, HandshakeTranscript, TicketInfo


def build_client_hello(
        sni: str|None = None, # server name indication
        ciphers: Iterable[CipherSuite]|None = None, # default, replace with DEFAULT_CIPHER_SUITES or ticket.csuite
        kex_groups: Iterable[NamedGroup] = DEFAULT_KEX_GROUPS,
        kex_share_groups: Iterable[NamedGroup]|None = None, # defaults to the first one in kex_groups
        sig_algs: Iterable[SignatureScheme] = DEFAULT_SIGNATURE_SCHEMES,
        ticket: TicketInfo|None = None, # reconnect ticket to use as PSK for reconnect
        psk_modes: Iterable[PskKeyExchangeMode] = DEFAULT_KEX_MODES,
        send_time: float|None = None, # default to current time
        rseed: int|bytes|None = None, # optional seed for repeatability; NOT secure
        grease_ech: bool = True, # send a GREASE ECH extension (to gather server parameters)
) -> tuple[ClientHelloHandshake, ClientSecrets]:
    """Returns (unpacked) ClientHello handshake struct and ClientSecrets tuple."""

    rgen = SystemRandom() if rseed is None else Random(rseed)

    if ciphers is None:
        if ticket is None:
            ciphers = DEFAULT_CIPHER_SUITES
        else:
            ciphers = (ticket.csuite,)
    else:
        ciphers = tuple(ciphers)

    if ticket is not None and ticket.csuite not in ciphers:
        raise ValueError("incompatible cipher suites for this ticket")

    kex_groups = tuple(kex_groups)

    # generate key exchange secrets and shares
    kex_sks: list[bytes] = []
    shares: list[tuple[NamedGroup, bytes]] = []
    if kex_share_groups is None:
        kex_share_groups = kex_groups[:1]
    for group in kex_share_groups:
        kex = get_kex_alg(group)
        secret = kex.gen_private(rgen)
        share = kex.get_public(secret)
        kex_sks.append(secret)
        shares.append((group, share))

    if not shares and ticket is None:
        raise ValueError("need either DHE or PSK (or both), but got neither")

    # fill in client hello extension entries
    extensions: list[ClientExtensionVariant] = []
    if sni is not None:
        extensions.append(ServerNameClientExtension.create(
            [(HOST_NAME_TYPE, sni)]
        ))

    # indicates all point formats are accepted (legacy)
    extensions.append(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_EC_POINT_FORMATS,
        data = bytes.fromhex('03000102'),
    ))

    # which groups supported for key exchange
    extensions.append(SupportedGroupsClientExtension.create(kex_groups))

    # more backwards compatibility empty info,
    # probably not necessary but who knows
    extensions.append(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_SESSION_TICKET,
        data = b'',
    ))
    extensions.append(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_ENCRYPT_THEN_MAC,
        data = b'',
    ))
    extensions.append(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_EXTENDED_MASTER_SECRET,
        data = b'',
    ))

    # which signature algorithms allowed for CertificateVerify message
    extensions.append(SignatureAlgorithmsClientExtension.create(sig_algs))

    # indicate only TLS 1.3 is supported
    extensions.append(SupportedVersionsClientExtension.create([Version.TLS_1_3]))

    # indicate whether DHE must still be done on resumption with a ticket
    extensions.append(PskKeyExchangeModesClientExtension.create(psk_modes))

    if shares:
        # send the DHE public key
        extensions.append(KeyShareClientExtension.create(shares))

    # add GREASE ECH if requested
    if grease_ech:
        extensions.append(EncryptedClientHelloClientExtension.create(
            variant = OuterECHClientHello.create(
                cipher_suite = DEFAULT_HPKE_CSUITES[0],
                config_id = rgen.randrange(2**8),
                enc = rgen.randbytes(32),
                payload = rgen.randbytes(239),
            ),
        ))

    # calculate client hello handshake message
    ch = ClientHelloHandshake.create(
        legacy_version     = DEFAULT_LEGACY_VERSION,
        client_random      = rgen.randbytes(32),
        session_id         = rgen.randbytes(32),
        ciphers            = (c.value for c in ciphers),
        legacy_compression = DEFAULT_LEGACY_COMPRESSION,
        extensions         = extensions,
    )

    # add PRE_SHARED_KEY extension if using a ticket
    psk = b''
    if ticket is not None:
        ch = ticket.add_psk_ext(ch, send_time)
        psk = ticket.secret

    return ch, ClientSecrets.create(kex_sks=kex_sks, psk=psk)


@dataclass
class ClientHandshake(AbstractHandshake, PayloadProcessor):
    chello         : ClientHelloHandshake
    state          : ClientStates                 = ClientStates.START
    psk            : bytes|None                   = None
    sni            : str|None                     = None
    kexes          : dict[NamedGroup, bytes]      = field(default_factory=dict)
    psk_modes      : Iterable[PskKeyExchangeMode] = PskKeyExchangeMode.all()
    hs_trans       : HandshakeTranscript          = field(default_factory=HandshakeTranscript)
    key_calc       : KeyCalc                      = field(init=False)
    tickets        : list[TicketInfo]             = field(default_factory=list)
    ech_configs    : list[ECHConfigVariant]       = field(default_factory=list)

    def __post_init__(self) -> None:
        self.key_calc = KeyCalc(self.hs_trans)

    @classmethod
    def create(cls, ch: ClientHelloHandshake, secrets: ClientSecrets) -> Self:
        psk: bytes|None = None if not secrets.psk else secrets.psk
        need_kex_mode = need_psk = (psk is not None)

        # extract some data from the client hello
        sni: str|None = None
        kexes: dict[NamedGroup, bytes] = {}

        psk_modes = PskKeyExchangeMode.all()

        for ext in ch.data.extensions.uncreate():
            match ext:
                case ServerNameClientExtension():
                    try:
                        sni = ext.data[0].host_name
                    except IndexError:
                        pass
                case KeyShareClientExtension():
                    for (group, _), private in zip(ext.uncreate(), secrets.kex_sks):
                        kexes[NamedGroup.create(group)] = private
                case PskKeyExchangeModesClientExtension():
                    psk_modes = tuple(ext.data)
                    need_kex_mode = False
                case PreSharedKeyClientExtension():
                    assert need_psk
                    need_psk = False
                case GenericClientExtension():
                    match ext.typ:
                        case ExtensionTypes.EARLY_DATA:
                            raise TlsTODO("no support for 0RTT early data yet")

        assert not need_kex_mode and not need_psk, "needed psk and psk exchange mode extensions in client hello but didn't get them"

        return cls(
            chello = ch,
            psk = psk,
            sni = sni,
            kexes = kexes,
            psk_modes = psk_modes,
        )

    @override
    @property
    def started(self) -> bool:
        return self.state != ClientStates.START

    @override
    @property
    def connected(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    @property
    def can_send(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    @property
    def can_recv(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    def begin(self, rreader: RecordReader, rwriter: RecordWriter) -> None:
        assert self.state == ClientStates.START
        self._rreader = rreader
        self._rreader.hs_buffer = HandshakeBuffer(owner=self)
        self._rwriter = rwriter
        self.send_hello()

    def _send_hs_msg(self, msg: HandshakeVariant, vers:Version = DEFAULT_LEGACY_VERSION) -> None:
        logger.info(f"sending hs message {msg.typ} to server")
        raw = msg.pack()
        self._rwriter.send(Record.create(
            typ     = ContentType.HANDSHAKE,
            version = vers,
            payload = raw,
        ))
        self.hs_trans.add(hs=msg, from_client=True)

    def send_hello(self) -> None:
        assert self.state == ClientStates.START
        self._send_hs_msg(self.chello, Version.TLS_1_0)
        self.state = ClientStates.WAIT_SH

    @override
    def process_hs_payload(self, raw: bytes) -> None:
        try:
            msg = Handshake.unpack(raw)
        except UnpackError as e:
            raise TlsError("Malformed handshake message") from e
        self.hs_trans.add(hs=msg.variant, from_client=False)
        logger.info(f"Received handshake message {msg.typ} with length {len(raw)}")

        match (self.state, msg.variant):
            case (ClientStates.WAIT_SH, ServerHelloHandshake() as shello):
                self._process_server_hello(shello)
            case (ClientStates.WAIT_EE, EncryptedExtensionsHandshake() as ee):
                self._process_ee(ee)
            case ((ClientStates.WAIT_CERT_CR | ClientStates.WAIT_CERT), CertificateHandshake() as cert):
                self._process_cert(cert)
            case (ClientStates.WAIT_CV, CertificateVerifyHandshake() as cv):
                self._process_cv(cv)
            case (ClientStates.WAIT_FINISHED, FinishedHandshake() as fin):
                self._process_finished(fin)
            case (ClientStates.CONNECTED, NewSessionTicketHandshake() as nst):
                self._process_ticket(nst)
            case _:
                raise TlsError(f"Unexpected {msg.typ} in state {self.state}")

    def _process_server_hello(self, sh: ServerHelloHandshake) -> None:
        if sh.data.server_random.hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
            # it's the sha256 hash of 'HelloRetryRequest'
            raise TlsTODO("HelloRetryRequest not yet implemented")

        self._cipher_suite = sh.data.cipher_suite

        kex_secret = None
        got_psk = False

        for ext in sh.data.extensions.uncreate():
            match ext:
                case KeyShareServerExtension():
                    group = ext.data.group
                    private = self.kexes[group]
                    try:
                        kex = get_kex_alg(group)
                    except ValueError:
                        raise TlsError(f"no implementation for kex group {group}")
                    kex_secret = kex.exchange(private, ext.data.pubkey)
                case SupportedVersionsServerExtension():
                    assert any(v == Version.TLS_1_3 for v in ext.data)
                case PreSharedKeyServerExtension():
                    if ext.data != 0:
                        raise TlsError(f'unexpected index in PRE_SHARED_KEY: {ext.data}')
                    got_psk = True
                case _:
                    logger.warning("Ignoring server extension", ext.typ)

        match ((kex_secret is not None), (self.psk is not None), got_psk):
            case (True, True, True):
                if not any(m == PskKeyExchangeMode.PSK_DHE_KE for m in self.psk_modes):
                    raise TlsError("server wants PSK_DHE_KE but client didn't ask for it")
            case (False, True, True):
                if not any(m == PskKeyExchangeMode.PSK_KE for m in self.psk_modes):
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
        self.key_calc.cipher_suite = self._cipher_suite

        # set up handshake keys
        self.key_calc.set_psk(self.psk)
        self.key_calc.set_kex_secret(kex_secret)
        self._rreader.rekey(self._cipher, self._hash_alg, self.key_calc.server_handshake_traffic_secret)

        logger.info(f"Finished processing server hello")
        self.state = ClientStates.WAIT_EE

    def _process_ee(self, ee: EncryptedExtensionsHandshake) -> None:
        for ext in ee.data.data:
            match ext.variant:
                case ServerNameServerExtension() as sne:
                    if sne.data:
                        raise TlsError(f"SERVER_NAME extension data should be empty, but got {ext.data}")
                case SupportedGroupsServerExtension():
                    # only informational; ignore
                    pass
                case EncryptedClientHelloServerExtension() as eche:
                    logger.info(f'received {len(eche.data.data)} ECH configs in server EE')
                    self.ech_configs.extend(x.variant for x in eche.data.data)
                case _:
                    logger.warning(f"Ignoring server extension extension of type {ext.typ}")

        logger.info(f"Finished processing server encrypted extensions")
        if self.psk is None:
            self.state = ClientStates.WAIT_CERT_CR
        else:
            self.state = ClientStates.WAIT_FINISHED

    def _process_cert(self, cert: CertificateHandshake) -> None:
        if cert.data.certificate_request_context:
            raise TlsError(f"certificate_request_context field should be empty")
        self._cert_chain = []
        for cert_struct in cert.data.certificate_list:
            if cert_struct.extensions:
                raise TlsError(f"certificate extensions should be empty")
            self._cert_chain.append(cert_struct.cert_data)
        logger.info(f"Received a length-{len(self._cert_chain)} certificate chain"
            f" with lengths {[len(x) for x in self._cert_chain]}")
        self._cert_pubkey = extract_x509_pubkey(self._cert_chain[0])

        self.state = ClientStates.WAIT_CV

    def _process_cv(self, cv: CertificateVerifyHandshake) -> None:
        logger.info(f"Received a length-{len(cv.data.signature)} sig of type {cv.data.algorithm}")
        self._sig_alg = cv.data.algorithm
        try:
            sigscheme = get_sig_alg(self._sig_alg)
        except ValueError as e:
            raise TlsError(f"signature algorithm {self._sig_alg} not supported") from e
        check = sigscheme.verify(
            pubkey    = self._cert_pubkey,
            signature = cv.data.signature,
            data      = self.key_calc.server_cv_message,
        )
        if check:
            logger.info("certificate verify signature check passed")
        else:
            raise TlsError("signature check failed in CERTIFICATE_VERIFY")

        self.state = ClientStates.WAIT_FINISHED

    def _process_finished(self, sf: FinishedHandshake) -> None:
        if sf.data != self.key_calc.server_finished_verify:
            raise TlsError("verify data in server finished message doesn't match")
        logger.info(f"Received correct SERVER FINISHED.")

        logger.info(f"Sending change cipher spec to server")
        self._rwriter.send(Record.create(
            typ     = ContentType.CHANGE_CIPHER_SPEC,
            version = DEFAULT_LEGACY_VERSION,
            payload = CCS_PAYLOAD,
        ))

        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self.key_calc.client_handshake_traffic_secret)

        client_finished = FinishedHandshake.create(self.key_calc.client_finished_verify)
        self._send_hs_msg(client_finished)
        logger.info(f"Sent CLIENT FINISHED. Handshake complete!")

        self._rreader.rekey(self._cipher, self._hash_alg,
                            self.key_calc.server_application_traffic_secret)
        self._rwriter.rekey(self._cipher, self._hash_alg,
                            self.key_calc.client_application_traffic_secret)

        self.state = ClientStates.CONNECTED

    def _process_ticket(self, nst: NewSessionTicketHandshake) -> None:
        self.tickets.append(self.key_calc.ticket_info(nst.data, modes=self.psk_modes))
        logger.info("got and stored a reconnect ticket")

@dataclass
class Client(Connection):
    handshake: ClientHandshake

    @classmethod
    def create(cls, ch: ClientHelloHandshake, secrets: ClientSecrets) -> Self:
        return cls(
            transcript = RecordTranscript(is_client=True),
            handshake = ClientHandshake.create(ch, secrets),
        )

    @property
    def tickets(self) -> tuple[TicketInfo,...]:
        return tuple(self.handshake.tickets)

    @property
    def ech_configs(self) -> tuple[ECHConfigVariant,...]:
        return tuple(self.handshake.ech_configs)


@same_args(build_client_hello)
def build_client(*args: Any, **kwargs: Any) -> Client:
    ch, secrets = build_client_hello(*args, **kwargs)
    return Client.create(ch, secrets)
