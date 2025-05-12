"""Network protocol specifications for TLS1.3.

Using the `specs` framework, contains code for translating objects communicated
over the network in TLS1.3 into Python objects such as dicts and lists.

Also contains enums (with special subclassing of `spec`) for the various families
of constants defined for normal TLS 1.3 things.
"""

from enum import Enum, IntEnum, EnumType

from tls_common import *
from spec import *

class _FixedEnum(FixedSize, EnumType):
    def __new__(metacls, name, bases, namespace, **kwargs):
        return super().__new__(metacls, name, bases, namespace)

    def __init__(self, name, bases, namespace, bytelen):
        FixedSize.__init__(self, bytelen)
        EnumType.__init__(self, name, bases, namespace)
        self.encode = lambda obj: obj.value.to_bytes(self._packed_size)
        self.as_const = lambda obj: self.const(obj)
        self.__str__ = lambda obj: f"{obj.name}({hex(obj.value)})"

    def prepack(self, obj):
        return self(obj)

    def _pack(self, obj):
        return obj.value.to_bytes(self._packed_size)

    def _unpack(self, raw):
        assert len(raw) == self._packed_size
        value = int.from_bytes(raw)
        try:
            return self(value)
        except ValueError as e:
            raise ParseError(f'could not convert {value} to {self}') from e


class ClientState(IntEnum, metaclass=_FixedEnum, bytelen=1):
    # rfc8446#appendix-A.1
    START         = 0
    WAIT_SH       = 1
    WAIT_EE       = 2
    WAIT_CERT_CR  = 3
    WAIT_CERT     = 4
    WAIT_CV       = 5
    WAIT_FINISHED = 6
    CONNECTED     = 7
    CLOSED        = 8
    ERROR         = 9


class ServerState(IntEnum, metaclass=_FixedEnum, bytelen=1):
    # rfc8446#appendix-A.2
    START         = 0
    RECVD_CH      = 1
    NEGOTIATED    = 2
    WAIT_EOED     = 3
    WAIT_FLIGHT2  = 4
    WAIT_CERT     = 5
    WAIT_CV       = 6
    WAIT_FINISHED = 7
    CONNECTED     = 8


class ContentType(IntEnum, metaclass=_FixedEnum, bytelen=1):
    INVALID            = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT              = 21
    HANDSHAKE          = 22
    APPLICATION_DATA   = 23
    HEARTBEAT          = 24


class HandshakeType(IntEnum, metaclass=_FixedEnum, bytelen=1):
    CLIENT_HELLO         = 1
    SERVER_HELLO         = 2
    NEW_SESSION_TICKET   = 4
    END_OF_EARLY_DATA    = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE          = 11
    CERTIFICATE_REQUEST  = 13
    CERTIFICATE_VERIFY   = 15
    FINISHED             = 20
    KEY_UPDATE           = 24
    MESSAGE_HASH         = 254


class ExtensionType(IntEnum, metaclass=_FixedEnum, bytelen=2):
    SERVER_NAME                            = 0
    MAX_FRAGMENT_LENGTH                    = 1
    STATUS_REQUEST                         = 5
    SUPPORTED_GROUPS                       = 10
    LEGACY_EC_POINT_FORMATS                = 11
    SIGNATURE_ALGORITHMS                   = 13
    USE_SRTP                               = 14
    HEARTBEAT                              = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    SIGNED_CERTIFICATE_TIMESTAMP           = 18
    CLIENT_CERTIFICATE_TYPE                = 19
    SERVER_CERTIFICATE_TYPE                = 20
    PADDING                                = 21
    LEGACY_ENCRYPT_THEN_MAC                = 22
    LEGACY_EXTENDED_MASTER_SECRET          = 23
    LEGACY_SESSION_TICKET                  = 35
    PRE_SHARED_KEY                         = 41
    EARLY_DATA                             = 42
    SUPPORTED_VERSIONS                     = 43
    COOKIE                                 = 44
    PSK_KEY_EXCHANGE_MODES                 = 45
    CERTIFICATE_AUTHORITIES                = 47
    OID_FILTERS                            = 48
    POST_HANDSHAKE_AUTH                    = 49
    SIGNATURE_ALGORITHMS_CERT              = 50
    KEY_SHARE                              = 51
    TICKET_REQUEST                         = 58
    UNSUPPORTED                            = 2570

    @classmethod
    def _missing_(cls, value):
        logger.info(f'Saw unsupported extension with value {value} = 0x{hex(value)}')
        return cls.UNSUPPORTED


class SignatureScheme(IntEnum, metaclass=_FixedEnum, bytelen=2):
    RSA_PKCS1_SHA256       = 0x0401
    RSA_PKCS1_SHA384       = 0x0501
    RSA_PKCS1_SHA512       = 0x0601
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    RSA_PSS_RSAE_SHA256    = 0x0804
    RSA_PSS_RSAE_SHA384    = 0x0805
    RSA_PSS_RSAE_SHA512    = 0x0806
    ED25519                = 0x0807
    ED448                  = 0x0808
    RSA_PSS_PSS_SHA256     = 0x0809
    RSA_PSS_PSS_SHA384     = 0x080a
    RSA_PSS_PSS_SHA512     = 0x080b
    RSA_PKCS1_SHA1         = 0x0201
    ECDSA_SHA1             = 0x0203


class NamedGroup(IntEnum, metaclass=_FixedEnum, bytelen=2):
    SECP256R1   = 0x0017
    SECP384R1   = 0x0018
    SECP521R1   = 0x0019
    X25519      = 0x001d
    X448        = 0x001e
    FFDHE2048   = 0x0100
    FFDHE3072   = 0x0101
    FFDHE4096   = 0x0102
    FFDHE6144   = 0x0103
    FFDHE8192   = 0x0104
    UNSUPPORTED = 0xFFFF

    @classmethod
    def _missing_(cls, value):
        logger.info(f'Saw unsupported named group with value {value} = 0x{hex(value)}')
        return cls.UNSUPPORTED


class CipherSuite(IntEnum, metaclass=_FixedEnum, bytelen=2):
    TLS_AES_128_GCM_SHA256                   = 0x1301
    TLS_AES_256_GCM_SHA384                   = 0x1302
    TLS_CHACHA20_POLY1305_SHA256             = 0x1303
    TLS_AES_128_CCM_SHA256                   = 0x1304
    TLS_AES_128_CCM_8_SHA256                 = 0x1305
    LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
    UNSUPPORTED                              = 0x4a4a

    @classmethod
    def _missing_(cls, value):
        return cls.UNSUPPORTED


class PskKeyExchangeMode(IntEnum, metaclass=_FixedEnum, bytelen=1):
    PSK_KE     = 0
    PSK_DHE_KE = 1


class CertificateType(IntEnum, metaclass=_FixedEnum, bytelen=1):
    X509         = 0
    RawPublicKey = 2


class Version(IntEnum, metaclass=_FixedEnum, bytelen=2):
    TLS_1_0 = 0x0301
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304


class AlertLevel(IntEnum, metaclass=_FixedEnum, bytelen=1):
    WARNING = 1
    FATAL   = 2


class AlertDescription(IntEnum, metaclass=_FixedEnum, bytelen=1):
    CLOSE_NOTIFY                        = 0
    UNEXPECTED_MESSAGE                  = 10
    BAD_RECORD_MAC                      = 20
    RECORD_OVERFLOW                     = 22
    HANDSHAKE_FAILURE                   = 40
    BAD_CERTIFICATE                     = 42
    UNSUPPORTED_CERTIFICATE             = 43
    CERTIFICATE_REVOKED                 = 44
    CERTIFICATE_EXPIRED                 = 45
    CERTIFICATE_UNKNOWN                 = 46
    ILLEGAL_PARAMETER                   = 47
    UNKNOWN_CA                          = 48
    ACCESS_DENIED                       = 49
    DECODE_ERROR                        = 50
    DECRYPT_ERROR                       = 51
    PROTOCOL_VERSION                    = 70
    INSUFFICIENT_SECURITY               = 71
    INTERNAL_ERROR                      = 80
    INAPPROPRIATE_FALLBACK              = 86
    USER_CANCELED                       = 90
    MISSING_EXTENSION                   = 109
    UNSUPPORTED_EXTENSION               = 110
    UNRECOGNIZED_NAME                   = 112
    BAD_CERTIFICATE_STATUS_RESPONSE     = 113
    UNKNOWN_PSK_IDENTITY                = 115
    CERTIFICATE_REQUIRED                = 116
    NO_APPLICATION_PROTOCOL             = 120


HkdfLabel = Struct(
    length  = Integer(2),
    label   = Bounded(1, Raw),
    context = Bounded(1, Raw),
)

KeyShareEntry = Struct(
    group  = NamedGroup,
    pubkey = Bounded(2, Raw),
)

common_extensions = {
    ExtensionType.SERVER_NAME
        : Sequence(Bounded(2, Struct(
            name_type = Integer(1).const(0),
            host_name = Bounded(2, String),
        ))),
    ExtensionType.SUPPORTED_GROUPS
        : Bounded(2, Sequence(NamedGroup)),
    ExtensionType.SIGNATURE_ALGORITHMS
        : Bounded(2, Sequence(SignatureScheme)),
    ExtensionType.SUPPORTED_VERSIONS
        : Bounded(1, Version.TLS_1_3.as_const()),
}

PskIdentity = Struct(
    identity              = Bounded(2, Raw),
    obfuscated_ticket_age = Integer(4),
)

PskBinders = Bounded(2, Sequence(Bounded(1, Raw)))

ClientExtension = Select(
    typ = ExtensionType,
    data = SelectBounded(2, common_extensions | {
        ExtensionType.SUPPORTED_VERSIONS
            : Bounded(1, Sequence(Version)),
        ExtensionType.PSK_KEY_EXCHANGE_MODES
            : Bounded(1, Sequence(PskKeyExchangeMode)),
        ExtensionType.KEY_SHARE
            : Bounded(2, Sequence(KeyShareEntry)),
        ExtensionType.TICKET_REQUEST
            : Struct(
                new_session_count = Integer(1),
                resumption_count  = Integer(1),
            ),
        ExtensionType.PRE_SHARED_KEY
            : Struct(
                identities = Bounded(2, Sequence(PskIdentity)),
                binders    = PskBinders,
            ),
    })
)

ServerExtension = Select(
    typ = ExtensionType,
    data = SelectBounded(2, common_extensions | {
        ExtensionType.SUPPORTED_VERSIONS
            : Version.TLS_1_3.as_const(),
        ExtensionType.KEY_SHARE
            : KeyShareEntry,
        ExtensionType.TICKET_REQUEST
            : Struct(expected_count = Integer(1)),
        ExtensionType.PRE_SHARED_KEY
            : Integer(2),
    })
)

ServerExtensionList = Bounded(2, Sequence(ServerExtension))

Ticket = Struct(
    ticket_lifetime = Integer(4),
    ticket_age_add  = Integer(4),
    ticket_nonce    = Bounded(1, Raw),
    ticket          = Bounded(2, Raw),
    extensions      = ServerExtensionList,
)

Handshake = Select(
    typ = HandshakeType,
    body = SelectBounded(3, {
        HandshakeType.CLIENT_HELLO
            : Struct(
                legacy_version     = Version.TLS_1_2.as_const(),
                client_random      = Fix(32, Raw),
                session_id         = Bounded(1, Raw),
                ciphers            = Bounded(2, Sequence(CipherSuite)),
                legacy_compression = Bounded(1, Sequence(Integer(1))).const([0]),
                extensions         = Bounded(2, Sequence(ClientExtension)),
            ),
        HandshakeType.SERVER_HELLO
            : Struct(
                legacy_version     = Version.TLS_1_2.as_const(),
                server_random      = Fix(32, Raw),
                session_id         = Bounded(1, Raw),
                cipher_suite       = CipherSuite,
                legacy_compression = Integer(1).const(0),
                extensions         = ServerExtensionList,
            ),
        HandshakeType.ENCRYPTED_EXTENSIONS
            : ServerExtensionList,
        HandshakeType.CERTIFICATE
            : Struct(
                certificate_request_context = Bounded(1, Raw),
                certificate_list = Bounded(3, Sequence(Struct(
                    cert_data  = Bounded(3, Raw),
                    extensions = Bounded(2, Raw),
                ))),
            ),
        HandshakeType.CERTIFICATE_VERIFY
            : Struct(
                algorithm = SignatureScheme,
                signature = Bounded(2, Raw),
            ),
        HandshakeType.FINISHED
            : Raw,
        HandshakeType.NEW_SESSION_TICKET
            : Ticket,
    })
)


class _InnerPlaintext(Struct):
    def __init__(self):
        super().__init__(
            typ     = ContentType,
            data    = Raw,
            padding = Fill(),
        )

    def _pack_to(self, dest, tup):
        for i in [1,0,2]:
            self._types[i].pack_to(dest, tup[i])

    def _unpack(self, raw):
        tlen = ContentType._packed_size
        stripped = raw.rstrip(b'\x00')
        if len(stripped) < tlen:
            raise ParseError("ContentType missing")
        parts = [stripped[-tlen:], stripped[:-tlen], raw[len(stripped):]]
        return self.Tuple(*(typ._unpack(part) for typ,part in zip(self._types, parts)))


InnerPlaintext = _InnerPlaintext()


Alert = Struct(
    level       = AlertLevel,
    description = AlertDescription,
)


RecordHeader = Struct(
    typ  = ContentType,
    vers = Version,
    size = Integer(2),
)

def _record_body_spec(prefix):
    match prefix:
        case (ContentType.CHANGE_CIPHER_SPEC, Version.TLS_1_2):
            # will be ignored
            spec = Raw.const(b'\x01')
        case (ContentType.HANDSHAKE, _):
            # can't parse as Handshake because HS msgs can be split between records
            spec = Raw
        case (ContentType.APPLICATION_DATA, Version.TLS_1_2):
            # ciphertext
            spec = Raw
        case (ContentType.ALERT, _):
            spec = Alert
        case _:
            raise ParseError(f"unsupported record prefix {prefix}")
    return Bounded(2, spec)

Record = Select(
    prefix = Struct(
        typ = ContentType,
        vers = Version,
    ),
    payload = _record_body_spec
)
