from tls_common import *
# XXX AUTO-GENERATED - DO NOT EDIT! XXX
from typing import Self, override, BinaryIO, ClassVar, Any
from collections.abc import Iterable
import enum
import dataclasses
from dataclasses import dataclass
import spec
from spec import *

class Uint8(spec._Integral):
    _BYTE_LENGTH = 1

class ClientStates(enum.IntEnum):
    START = 0
    WAIT_SH = 1
    WAIT_EE = 2
    WAIT_CERT_CR = 3
    WAIT_CERT = 4
    WAIT_CV = 5
    WAIT_FINISHED = 6
    CONNECTED = 7
    CLOSED = 8
    ERROR = 9

    def parent(self) -> 'ClientState':
        return ClientState(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ClientState(spec._NamedConstBase[ClientStates]):
    _T = ClientStates
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    START: 'ClientState'
    WAIT_SH: 'ClientState'
    WAIT_EE: 'ClientState'
    WAIT_CERT_CR: 'ClientState'
    WAIT_CERT: 'ClientState'
    WAIT_CV: 'ClientState'
    WAIT_FINISHED: 'ClientState'
    CONNECTED: 'ClientState'
    CLOSED: 'ClientState'
    ERROR: 'ClientState'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class ServerStates(enum.IntEnum):
    START = 0
    RECVD_CH = 1
    NEGOTIATED = 2
    WAIT_EOED = 3
    WAIT_FLIGHT2 = 4
    WAIT_CERT = 5
    WAIT_CV = 6
    WAIT_FINISHED = 7
    CONNECTED = 8

    def parent(self) -> 'ServerState':
        return ServerState(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ServerState(spec._NamedConstBase[ServerStates]):
    _T = ServerStates
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    START: 'ServerState'
    RECVD_CH: 'ServerState'
    NEGOTIATED: 'ServerState'
    WAIT_EOED: 'ServerState'
    WAIT_FLIGHT2: 'ServerState'
    WAIT_CERT: 'ServerState'
    WAIT_CV: 'ServerState'
    WAIT_FINISHED: 'ServerState'
    CONNECTED: 'ServerState'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class ContentTypes(enum.IntEnum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24

    def parent(self) -> 'ContentType':
        return ContentType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ContentType(spec._NamedConstBase[ContentTypes]):
    _T = ContentTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    INVALID: 'ContentType'
    CHANGE_CIPHER_SPEC: 'ContentType'
    ALERT: 'ContentType'
    HANDSHAKE: 'ContentType'
    APPLICATION_DATA: 'ContentType'
    HEARTBEAT: 'ContentType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class HandshakeTypes(enum.IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254

    def parent(self) -> 'HandshakeType':
        return HandshakeType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class HandshakeType(spec._NamedConstBase[HandshakeTypes]):
    _T = HandshakeTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    CLIENT_HELLO: 'HandshakeType'
    SERVER_HELLO: 'HandshakeType'
    NEW_SESSION_TICKET: 'HandshakeType'
    END_OF_EARLY_DATA: 'HandshakeType'
    ENCRYPTED_EXTENSIONS: 'HandshakeType'
    CERTIFICATE: 'HandshakeType'
    CERTIFICATE_REQUEST: 'HandshakeType'
    CERTIFICATE_VERIFY: 'HandshakeType'
    FINISHED: 'HandshakeType'
    KEY_UPDATE: 'HandshakeType'
    MESSAGE_HASH: 'HandshakeType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class Uint16(spec._Integral):
    _BYTE_LENGTH = 2

class ExtensionTypes(enum.IntEnum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    LEGACY_EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    LEGACY_ENCRYPT_THEN_MAC = 22
    LEGACY_EXTENDED_MASTER_SECRET = 23
    LEGACY_SESSION_TICKET = 35
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51
    TICKET_REQUEST = 58
    ENCRYPTED_CLIENT_HELLO = 65037
    GREASE = 2570
    UNRECOGNIZED = 65000

    def parent(self) -> 'ExtensionType':
        return ExtensionType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ExtensionType(spec._NamedConstBase[ExtensionTypes]):
    _T = ExtensionTypes
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _alternate_values = {6682:ExtensionTypes.GREASE, 10794:ExtensionTypes.GREASE, 14906:ExtensionTypes.GREASE, 19018:ExtensionTypes.GREASE, 23130:ExtensionTypes.GREASE, 27242:ExtensionTypes.GREASE, 31354:ExtensionTypes.GREASE, 35466:ExtensionTypes.GREASE, 39578:ExtensionTypes.GREASE, 43690:ExtensionTypes.GREASE, 47802:ExtensionTypes.GREASE, 51914:ExtensionTypes.GREASE, 56026:ExtensionTypes.GREASE, 60138:ExtensionTypes.GREASE, 64250:ExtensionTypes.GREASE}
    _default_typ = ExtensionTypes.UNRECOGNIZED
    SERVER_NAME: 'ExtensionType'
    MAX_FRAGMENT_LENGTH: 'ExtensionType'
    STATUS_REQUEST: 'ExtensionType'
    SUPPORTED_GROUPS: 'ExtensionType'
    LEGACY_EC_POINT_FORMATS: 'ExtensionType'
    SIGNATURE_ALGORITHMS: 'ExtensionType'
    USE_SRTP: 'ExtensionType'
    HEARTBEAT: 'ExtensionType'
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION: 'ExtensionType'
    SIGNED_CERTIFICATE_TIMESTAMP: 'ExtensionType'
    CLIENT_CERTIFICATE_TYPE: 'ExtensionType'
    SERVER_CERTIFICATE_TYPE: 'ExtensionType'
    PADDING: 'ExtensionType'
    LEGACY_ENCRYPT_THEN_MAC: 'ExtensionType'
    LEGACY_EXTENDED_MASTER_SECRET: 'ExtensionType'
    LEGACY_SESSION_TICKET: 'ExtensionType'
    PRE_SHARED_KEY: 'ExtensionType'
    EARLY_DATA: 'ExtensionType'
    SUPPORTED_VERSIONS: 'ExtensionType'
    COOKIE: 'ExtensionType'
    PSK_KEY_EXCHANGE_MODES: 'ExtensionType'
    CERTIFICATE_AUTHORITIES: 'ExtensionType'
    OID_FILTERS: 'ExtensionType'
    POST_HANDSHAKE_AUTH: 'ExtensionType'
    SIGNATURE_ALGORITHMS_CERT: 'ExtensionType'
    KEY_SHARE: 'ExtensionType'
    TICKET_REQUEST: 'ExtensionType'
    ENCRYPTED_CLIENT_HELLO: 'ExtensionType'
    GREASE: 'ExtensionType'
    UNRECOGNIZED: 'ExtensionType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class SignatureSchemes(enum.IntEnum):
    RSA_PKCS1_SHA256 = 1025
    RSA_PKCS1_SHA384 = 1281
    RSA_PKCS1_SHA512 = 1537
    ECDSA_SECP256R1_SHA256 = 1027
    ECDSA_SECP384R1_SHA384 = 1283
    ECDSA_SECP521R1_SHA512 = 1539
    RSA_PSS_RSAE_SHA256 = 2052
    RSA_PSS_RSAE_SHA384 = 2053
    RSA_PSS_RSAE_SHA512 = 2054
    ED25519 = 2055
    ED448 = 2056
    RSA_PSS_PSS_SHA256 = 2057
    RSA_PSS_PSS_SHA384 = 2058
    RSA_PSS_PSS_SHA512 = 2059
    RSA_PKCS1_SHA1 = 513
    ECDSA_SHA1 = 515
    GREASE = 2570

    def parent(self) -> 'SignatureScheme':
        return SignatureScheme(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class SignatureScheme(spec._NamedConstBase[SignatureSchemes]):
    _T = SignatureSchemes
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _alternate_values = {6682:SignatureSchemes.GREASE, 10794:SignatureSchemes.GREASE, 14906:SignatureSchemes.GREASE, 19018:SignatureSchemes.GREASE, 23130:SignatureSchemes.GREASE, 27242:SignatureSchemes.GREASE, 31354:SignatureSchemes.GREASE, 35466:SignatureSchemes.GREASE, 39578:SignatureSchemes.GREASE, 43690:SignatureSchemes.GREASE, 47802:SignatureSchemes.GREASE, 51914:SignatureSchemes.GREASE, 56026:SignatureSchemes.GREASE, 60138:SignatureSchemes.GREASE, 64250:SignatureSchemes.GREASE}
    RSA_PKCS1_SHA256: 'SignatureScheme'
    RSA_PKCS1_SHA384: 'SignatureScheme'
    RSA_PKCS1_SHA512: 'SignatureScheme'
    ECDSA_SECP256R1_SHA256: 'SignatureScheme'
    ECDSA_SECP384R1_SHA384: 'SignatureScheme'
    ECDSA_SECP521R1_SHA512: 'SignatureScheme'
    RSA_PSS_RSAE_SHA256: 'SignatureScheme'
    RSA_PSS_RSAE_SHA384: 'SignatureScheme'
    RSA_PSS_RSAE_SHA512: 'SignatureScheme'
    ED25519: 'SignatureScheme'
    ED448: 'SignatureScheme'
    RSA_PSS_PSS_SHA256: 'SignatureScheme'
    RSA_PSS_PSS_SHA384: 'SignatureScheme'
    RSA_PSS_PSS_SHA512: 'SignatureScheme'
    RSA_PKCS1_SHA1: 'SignatureScheme'
    ECDSA_SHA1: 'SignatureScheme'
    GREASE: 'SignatureScheme'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class NamedGroups(enum.IntEnum):
    SECP256R1 = 23
    SECP384R1 = 24
    SECP521R1 = 25
    X25519 = 29
    X448 = 30
    FFDHE2048 = 256
    FFDHE3072 = 257
    FFDHE4096 = 258
    FFDHE6144 = 259
    FFDHE8192 = 260
    GREASE = 2570
    UNSUPPORTED = 65535

    def parent(self) -> 'NamedGroup':
        return NamedGroup(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class NamedGroup(spec._NamedConstBase[NamedGroups]):
    _T = NamedGroups
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _alternate_values = {6682:NamedGroups.GREASE, 10794:NamedGroups.GREASE, 14906:NamedGroups.GREASE, 19018:NamedGroups.GREASE, 23130:NamedGroups.GREASE, 27242:NamedGroups.GREASE, 31354:NamedGroups.GREASE, 35466:NamedGroups.GREASE, 39578:NamedGroups.GREASE, 43690:NamedGroups.GREASE, 47802:NamedGroups.GREASE, 51914:NamedGroups.GREASE, 56026:NamedGroups.GREASE, 60138:NamedGroups.GREASE, 64250:NamedGroups.GREASE}
    _default_typ = NamedGroups.UNSUPPORTED
    SECP256R1: 'NamedGroup'
    SECP384R1: 'NamedGroup'
    SECP521R1: 'NamedGroup'
    X25519: 'NamedGroup'
    X448: 'NamedGroup'
    FFDHE2048: 'NamedGroup'
    FFDHE3072: 'NamedGroup'
    FFDHE4096: 'NamedGroup'
    FFDHE6144: 'NamedGroup'
    FFDHE8192: 'NamedGroup'
    GREASE: 'NamedGroup'
    UNSUPPORTED: 'NamedGroup'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class CipherSuites(enum.IntEnum):
    TLS_AES_128_GCM_SHA256 = 4865
    TLS_AES_256_GCM_SHA384 = 4866
    TLS_CHACHA20_POLY1305_SHA256 = 4867
    TLS_AES_128_CCM_SHA256 = 4868
    TLS_AES_128_CCM_8_SHA256 = 4869
    LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 255
    GREASE = 2570
    UNSUPPORTED = 65535

    def parent(self) -> 'CipherSuite':
        return CipherSuite(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class CipherSuite(spec._NamedConstBase[CipherSuites]):
    _T = CipherSuites
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _alternate_values = {6682:CipherSuites.GREASE, 10794:CipherSuites.GREASE, 14906:CipherSuites.GREASE, 19018:CipherSuites.GREASE, 23130:CipherSuites.GREASE, 27242:CipherSuites.GREASE, 31354:CipherSuites.GREASE, 35466:CipherSuites.GREASE, 39578:CipherSuites.GREASE, 43690:CipherSuites.GREASE, 47802:CipherSuites.GREASE, 51914:CipherSuites.GREASE, 56026:CipherSuites.GREASE, 60138:CipherSuites.GREASE, 64250:CipherSuites.GREASE}
    _default_typ = CipherSuites.UNSUPPORTED
    TLS_AES_128_GCM_SHA256: 'CipherSuite'
    TLS_AES_256_GCM_SHA384: 'CipherSuite'
    TLS_CHACHA20_POLY1305_SHA256: 'CipherSuite'
    TLS_AES_128_CCM_SHA256: 'CipherSuite'
    TLS_AES_128_CCM_8_SHA256: 'CipherSuite'
    LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV: 'CipherSuite'
    GREASE: 'CipherSuite'
    UNSUPPORTED: 'CipherSuite'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class PskKeyExchangeModes(enum.IntEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1
    GREASE = 11

    def parent(self) -> 'PskKeyExchangeMode':
        return PskKeyExchangeMode(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class PskKeyExchangeMode(spec._NamedConstBase[PskKeyExchangeModes]):
    _T = PskKeyExchangeModes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    _alternate_values = {42:PskKeyExchangeModes.GREASE, 73:PskKeyExchangeModes.GREASE, 104:PskKeyExchangeModes.GREASE, 135:PskKeyExchangeModes.GREASE, 166:PskKeyExchangeModes.GREASE, 197:PskKeyExchangeModes.GREASE, 228:PskKeyExchangeModes.GREASE}
    PSK_KE: 'PskKeyExchangeMode'
    PSK_DHE_KE: 'PskKeyExchangeMode'
    GREASE: 'PskKeyExchangeMode'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class CertificateTypes(enum.IntEnum):
    X509 = 0
    RawPublicKey = 2

    def parent(self) -> 'CertificateType':
        return CertificateType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class CertificateType(spec._NamedConstBase[CertificateTypes]):
    _T = CertificateTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    X509: 'CertificateType'
    RawPublicKey: 'CertificateType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class Versions(enum.IntEnum):
    TLS_1_0 = 769
    TLS_1_2 = 771
    TLS_1_3 = 772
    GREASE = 2570

    def parent(self) -> 'Version':
        return Version(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class Version(spec._NamedConstBase[Versions]):
    _T = Versions
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _alternate_values = {6682:Versions.GREASE, 10794:Versions.GREASE, 14906:Versions.GREASE, 19018:Versions.GREASE, 23130:Versions.GREASE, 27242:Versions.GREASE, 31354:Versions.GREASE, 35466:Versions.GREASE, 39578:Versions.GREASE, 43690:Versions.GREASE, 47802:Versions.GREASE, 51914:Versions.GREASE, 56026:Versions.GREASE, 60138:Versions.GREASE, 64250:Versions.GREASE}
    TLS_1_0: 'Version'
    TLS_1_2: 'Version'
    TLS_1_3: 'Version'
    GREASE: 'Version'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class AlertLevels(enum.IntEnum):
    WARNING = 1
    FATAL = 2

    def parent(self) -> 'AlertLevel':
        return AlertLevel(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class AlertLevel(spec._NamedConstBase[AlertLevels]):
    _T = AlertLevels
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    WARNING: 'AlertLevel'
    FATAL: 'AlertLevel'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class AlertDescriptions(enum.IntEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    RECORD_OVERFLOW = 22
    HANDSHAKE_FAILURE = 40
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    INAPPROPRIATE_FALLBACK = 86
    USER_CANCELED = 90
    MISSING_EXTENSION = 109
    UNSUPPORTED_EXTENSION = 110
    UNRECOGNIZED_NAME = 112
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    UNKNOWN_PSK_IDENTITY = 115
    CERTIFICATE_REQUIRED = 116
    NO_APPLICATION_PROTOCOL = 120

    def parent(self) -> 'AlertDescription':
        return AlertDescription(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class AlertDescription(spec._NamedConstBase[AlertDescriptions]):
    _T = AlertDescriptions
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    CLOSE_NOTIFY: 'AlertDescription'
    UNEXPECTED_MESSAGE: 'AlertDescription'
    BAD_RECORD_MAC: 'AlertDescription'
    RECORD_OVERFLOW: 'AlertDescription'
    HANDSHAKE_FAILURE: 'AlertDescription'
    BAD_CERTIFICATE: 'AlertDescription'
    UNSUPPORTED_CERTIFICATE: 'AlertDescription'
    CERTIFICATE_REVOKED: 'AlertDescription'
    CERTIFICATE_EXPIRED: 'AlertDescription'
    CERTIFICATE_UNKNOWN: 'AlertDescription'
    ILLEGAL_PARAMETER: 'AlertDescription'
    UNKNOWN_CA: 'AlertDescription'
    ACCESS_DENIED: 'AlertDescription'
    DECODE_ERROR: 'AlertDescription'
    DECRYPT_ERROR: 'AlertDescription'
    PROTOCOL_VERSION: 'AlertDescription'
    INSUFFICIENT_SECURITY: 'AlertDescription'
    INTERNAL_ERROR: 'AlertDescription'
    INAPPROPRIATE_FALLBACK: 'AlertDescription'
    USER_CANCELED: 'AlertDescription'
    MISSING_EXTENSION: 'AlertDescription'
    UNSUPPORTED_EXTENSION: 'AlertDescription'
    UNRECOGNIZED_NAME: 'AlertDescription'
    BAD_CERTIFICATE_STATUS_RESPONSE: 'AlertDescription'
    UNKNOWN_PSK_IDENTITY: 'AlertDescription'
    CERTIFICATE_REQUIRED: 'AlertDescription'
    NO_APPLICATION_PROTOCOL: 'AlertDescription'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class ECHClientHelloTypes(enum.IntEnum):
    OUTER = 0
    INNER = 1

    def parent(self) -> 'ECHClientHelloType':
        return ECHClientHelloType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ECHClientHelloType(spec._NamedConstBase[ECHClientHelloTypes]):
    _T = ECHClientHelloTypes
    _V = Uint8
    _BYTE_LENGTH = Uint8._BYTE_LENGTH
    OUTER: 'ECHClientHelloType'
    INNER: 'ECHClientHelloType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class ECHConfigExtensionTypes(enum.IntEnum):
    UNSUPPORTED = 65535

    def parent(self) -> 'ECHConfigExtensionType':
        return ECHConfigExtensionType(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ECHConfigExtensionType(spec._NamedConstBase[ECHConfigExtensionTypes]):
    _T = ECHConfigExtensionTypes
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    _default_typ = ECHConfigExtensionTypes.UNSUPPORTED
    UNSUPPORTED: 'ECHConfigExtensionType'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class HpkeKemIds(enum.IntEnum):
    DHKEM_P256_HKDF_SHA256 = 16
    DHKEM_P384_HKDF_SHA384 = 17
    DHKEM_P521_HKDF_SHA512 = 18
    DHKEM_X25519_HKDF_SHA256 = 32
    DHKEM_X448_HKDF_SHA512 = 33

    def parent(self) -> 'HpkeKemId':
        return HpkeKemId(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class HpkeKemId(spec._NamedConstBase[HpkeKemIds]):
    _T = HpkeKemIds
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    DHKEM_P256_HKDF_SHA256: 'HpkeKemId'
    DHKEM_P384_HKDF_SHA384: 'HpkeKemId'
    DHKEM_P521_HKDF_SHA512: 'HpkeKemId'
    DHKEM_X25519_HKDF_SHA256: 'HpkeKemId'
    DHKEM_X448_HKDF_SHA512: 'HpkeKemId'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class HpkeKdfIds(enum.IntEnum):
    HKDF_SHA256 = 1
    HKDF_SHA384 = 2
    HKDF_SHA512 = 3

    def parent(self) -> 'HpkeKdfId':
        return HpkeKdfId(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class HpkeKdfId(spec._NamedConstBase[HpkeKdfIds]):
    _T = HpkeKdfIds
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    HKDF_SHA256: 'HpkeKdfId'
    HKDF_SHA384: 'HpkeKdfId'
    HKDF_SHA512: 'HpkeKdfId'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class HpkeAeadIds(enum.IntEnum):
    AES_128_GCM = 1
    AES_256_GCM = 2
    CHACHA20_POLY1305 = 3

    def parent(self) -> 'HpkeAeadId':
        return HpkeAeadId(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class HpkeAeadId(spec._NamedConstBase[HpkeAeadIds]):
    _T = HpkeAeadIds
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    AES_128_GCM: 'HpkeAeadId'
    AES_256_GCM: 'HpkeAeadId'
    CHACHA20_POLY1305: 'HpkeAeadId'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class BoundedRaw(spec.Raw, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B8Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint8, )

@dataclass(frozen=True)
class HkdfLabel(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('length','label','context',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint16,B8Raw,B8Raw,)
    length: Uint16
    label: B8Raw
    context: B8Raw

    def replace(self, length:int|None=None, label:bytes|None=None, context:bytes|None=None) -> Self:
        return type(self)((self.length if length is None else Uint16.create(length)), (self.label if label is None else B8Raw.create(label)), (self.context if context is None else B8Raw.create(context)))

    @classmethod
    def create(cls,length:int,label:bytes,context:bytes) -> Self:
        return cls(length=Uint16.create(length), label=B8Raw.create(label), context=B8Raw.create(context))

    def uncreate(self) -> tuple[int, bytes, bytes]:
        return (self.length.uncreate(), self.label.uncreate(), self.context.uncreate())

class B16Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class KeyShareEntry(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('group','pubkey',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (NamedGroup,B16Raw,)
    group: NamedGroup
    pubkey: B16Raw

    def replace(self, group:int|NamedGroup|None=None, pubkey:bytes|None=None) -> Self:
        return type(self)((self.group if group is None else NamedGroup.create(group)), (self.pubkey if pubkey is None else B16Raw.create(pubkey)))

    @classmethod
    def create(cls,group:int|NamedGroup,pubkey:bytes) -> Self:
        return cls(group=NamedGroup.create(group), pubkey=B16Raw.create(pubkey))

    def uncreate(self) -> tuple[int|NamedGroup, bytes]:
        return (self.group.uncreate(), self.pubkey.uncreate())

class Uint32(spec._Integral):
    _BYTE_LENGTH = 4

@dataclass(frozen=True)
class PskIdentity(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('identity','obfuscated_ticket_age',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16Raw,Uint32,)
    identity: B16Raw
    obfuscated_ticket_age: Uint32

    def replace(self, identity:bytes|None=None, obfuscated_ticket_age:int|None=None) -> Self:
        return type(self)((self.identity if identity is None else B16Raw.create(identity)), (self.obfuscated_ticket_age if obfuscated_ticket_age is None else Uint32.create(obfuscated_ticket_age)))

    @classmethod
    def create(cls,identity:bytes,obfuscated_ticket_age:int) -> Self:
        return cls(identity=B16Raw.create(identity), obfuscated_ticket_age=Uint32.create(obfuscated_ticket_age))

    def uncreate(self) -> tuple[bytes, int]:
        return (self.identity.uncreate(), self.obfuscated_ticket_age.uncreate())

@dataclass(frozen=True)
class HpkeSymmetricCipherSuite(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('kdf_id','aead_id',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (HpkeKdfId,HpkeAeadId,)
    kdf_id: HpkeKdfId
    aead_id: HpkeAeadId

    def replace(self, kdf_id:int|HpkeKdfId|None=None, aead_id:int|HpkeAeadId|None=None) -> Self:
        return type(self)((self.kdf_id if kdf_id is None else HpkeKdfId.create(kdf_id)), (self.aead_id if aead_id is None else HpkeAeadId.create(aead_id)))

    @classmethod
    def create(cls,kdf_id:int|HpkeKdfId,aead_id:int|HpkeAeadId) -> Self:
        return cls(kdf_id=HpkeKdfId.create(kdf_id), aead_id=HpkeAeadId.create(aead_id))

    def uncreate(self) -> tuple[int|HpkeKdfId, int|HpkeAeadId]:
        return (self.kdf_id.uncreate(), self.aead_id.uncreate())

class SeqB8Raw(spec._Sequence[B8Raw]):
    _ITEM_TYPE = B8Raw

    @classmethod
    def create(cls, items: Iterable[bytes]) -> Self:
        return cls(B8Raw.create(item) for item in items)

    def uncreate(self) -> Iterable[bytes]:
        for item in self:
            yield item.uncreate()

class BoundedSeqB8Raw(SeqB8Raw, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqB8Raw(BoundedSeqB8Raw):
    _LENGTH_TYPES = (Uint16, )

class PskBinders(spec._Wrapper[B16SeqB8Raw]):
    _DATA_TYPE = B16SeqB8Raw

    @classmethod
    def create(cls, items:Iterable[bytes]) -> Self:
        return cls(data=B16SeqB8Raw.create(items))

    def uncreate(self) -> Iterable[bytes]:
        return self.data.uncreate()

class GenericClientExtension(spec._Selectee[ExtensionTypes, B16Raw]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16Raw

    @classmethod
    def create(cls, selector: int|ExtensionType, data: bytes) -> Self:
        return cls(selector=ExtensionType.create(selector), data=B16Raw.create(data))

    def uncreate(self) -> tuple[int|ExtensionType, bytes]:
        return (self.selector.uncreate(), self.data.uncreate())

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class BoundedString(spec.String, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16String(BoundedString):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class ServerNameClientExtensionData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('name_type','host_name',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint8,B16String,)
    name_type: Uint8
    host_name: B16String

    def replace(self, name_type:int|None=None, host_name:str|None=None) -> Self:
        return type(self)((self.name_type if name_type is None else Uint8.create(name_type)), (self.host_name if host_name is None else B16String.create(host_name)))

    @classmethod
    def create(cls,name_type:int,host_name:str) -> Self:
        return cls(name_type=Uint8.create(name_type), host_name=B16String.create(host_name))

    def uncreate(self) -> tuple[int, str]:
        return (self.name_type.uncreate(), self.host_name.uncreate())

class BoundedServerNameClientExtensionData(ServerNameClientExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16ServerNameClientExtensionData(BoundedServerNameClientExtensionData):
    _LENGTH_TYPES = (Uint16, )

class SeqB16ServerNameClientExtensionData(spec._Sequence[B16ServerNameClientExtensionData]):
    _ITEM_TYPE = B16ServerNameClientExtensionData

    @classmethod
    def create(cls, items: Iterable[tuple[int,str]]) -> Self:
        return cls(B16ServerNameClientExtensionData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[int,str]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqB16ServerNameClientExtensionData(SeqB16ServerNameClientExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqB16ServerNameClientExtensionData(BoundedSeqB16ServerNameClientExtensionData):
    _LENGTH_TYPES = (Uint16, )

class ServerNameClientExtension(spec._SpecificSelectee[ExtensionTypes, B16SeqB16ServerNameClientExtensionData]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16SeqB16ServerNameClientExtensionData
    _SELECTOR = ExtensionTypes.SERVER_NAME

    @classmethod
    def create(cls, items:Iterable[tuple[int,str]]) -> Self:
        return cls(data=B16SeqB16ServerNameClientExtensionData.create(items))

    def uncreate(self) -> Iterable[tuple[int,str]]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class SeqNamedGroup(spec._Sequence[NamedGroup]):
    _ITEM_TYPE = NamedGroup

    @classmethod
    def create(cls, items: Iterable[int|NamedGroup]) -> Self:
        return cls(NamedGroup.create(item) for item in items)

    def uncreate(self) -> Iterable[int|NamedGroup]:
        for item in self:
            yield item.uncreate()

class BoundedSeqNamedGroup(SeqNamedGroup, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16B16SeqNamedGroup(BoundedSeqNamedGroup):
    _LENGTH_TYPES = (Uint16, Uint16)

class SupportedGroupsClientExtension(spec._SpecificSelectee[ExtensionTypes, B16B16SeqNamedGroup]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B16SeqNamedGroup
    _SELECTOR = ExtensionTypes.SUPPORTED_GROUPS

    @classmethod
    def create(cls, items:Iterable[int|NamedGroup]) -> Self:
        return cls(data=B16B16SeqNamedGroup.create(items))

    def uncreate(self) -> Iterable[int|NamedGroup]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class SeqSignatureScheme(spec._Sequence[SignatureScheme]):
    _ITEM_TYPE = SignatureScheme

    @classmethod
    def create(cls, items: Iterable[int|SignatureScheme]) -> Self:
        return cls(SignatureScheme.create(item) for item in items)

    def uncreate(self) -> Iterable[int|SignatureScheme]:
        for item in self:
            yield item.uncreate()

class BoundedSeqSignatureScheme(SeqSignatureScheme, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16B16SeqSignatureScheme(BoundedSeqSignatureScheme):
    _LENGTH_TYPES = (Uint16, Uint16)

class SignatureAlgorithmsClientExtension(spec._SpecificSelectee[ExtensionTypes, B16B16SeqSignatureScheme]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B16SeqSignatureScheme
    _SELECTOR = ExtensionTypes.SIGNATURE_ALGORITHMS

    @classmethod
    def create(cls, items:Iterable[int|SignatureScheme]) -> Self:
        return cls(data=B16B16SeqSignatureScheme.create(items))

    def uncreate(self) -> Iterable[int|SignatureScheme]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class SeqVersion(spec._Sequence[Version]):
    _ITEM_TYPE = Version

    @classmethod
    def create(cls, items: Iterable[int|Version]) -> Self:
        return cls(Version.create(item) for item in items)

    def uncreate(self) -> Iterable[int|Version]:
        for item in self:
            yield item.uncreate()

class BoundedSeqVersion(SeqVersion, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16B8SeqVersion(BoundedSeqVersion):
    _LENGTH_TYPES = (Uint16, Uint8)

class SupportedVersionsClientExtension(spec._SpecificSelectee[ExtensionTypes, B16B8SeqVersion]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B8SeqVersion
    _SELECTOR = ExtensionTypes.SUPPORTED_VERSIONS

    @classmethod
    def create(cls, items:Iterable[int|Version]) -> Self:
        return cls(data=B16B8SeqVersion.create(items))

    def uncreate(self) -> Iterable[int|Version]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class SeqPskKeyExchangeMode(spec._Sequence[PskKeyExchangeMode]):
    _ITEM_TYPE = PskKeyExchangeMode

    @classmethod
    def create(cls, items: Iterable[int|PskKeyExchangeMode]) -> Self:
        return cls(PskKeyExchangeMode.create(item) for item in items)

    def uncreate(self) -> Iterable[int|PskKeyExchangeMode]:
        for item in self:
            yield item.uncreate()

class BoundedSeqPskKeyExchangeMode(SeqPskKeyExchangeMode, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16B8SeqPskKeyExchangeMode(BoundedSeqPskKeyExchangeMode):
    _LENGTH_TYPES = (Uint16, Uint8)

class PskKeyExchangeModesClientExtension(spec._SpecificSelectee[ExtensionTypes, B16B8SeqPskKeyExchangeMode]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B8SeqPskKeyExchangeMode
    _SELECTOR = ExtensionTypes.PSK_KEY_EXCHANGE_MODES

    @classmethod
    def create(cls, items:Iterable[int|PskKeyExchangeMode]) -> Self:
        return cls(data=B16B8SeqPskKeyExchangeMode.create(items))

    def uncreate(self) -> Iterable[int|PskKeyExchangeMode]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

class SeqKeyShareEntry(spec._Sequence[KeyShareEntry]):
    _ITEM_TYPE = KeyShareEntry

    @classmethod
    def create(cls, items: Iterable[tuple[int|NamedGroup,bytes]]) -> Self:
        return cls(KeyShareEntry.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[int|NamedGroup,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqKeyShareEntry(SeqKeyShareEntry, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16B16SeqKeyShareEntry(BoundedSeqKeyShareEntry):
    _LENGTH_TYPES = (Uint16, Uint16)

class KeyShareClientExtension(spec._SpecificSelectee[ExtensionTypes, B16B16SeqKeyShareEntry]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B16SeqKeyShareEntry
    _SELECTOR = ExtensionTypes.KEY_SHARE

    @classmethod
    def create(cls, items:Iterable[tuple[int|NamedGroup,bytes]]) -> Self:
        return cls(data=B16B16SeqKeyShareEntry.create(items))

    def uncreate(self) -> Iterable[tuple[int|NamedGroup,bytes]]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

@dataclass(frozen=True)
class TicketRequestClientExtensionData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('new_session_count','resumption_count',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint8,Uint8,)
    new_session_count: Uint8
    resumption_count: Uint8

    def replace(self, new_session_count:int|None=None, resumption_count:int|None=None) -> Self:
        return type(self)((self.new_session_count if new_session_count is None else Uint8.create(new_session_count)), (self.resumption_count if resumption_count is None else Uint8.create(resumption_count)))

    @classmethod
    def create(cls,new_session_count:int,resumption_count:int) -> Self:
        return cls(new_session_count=Uint8.create(new_session_count), resumption_count=Uint8.create(resumption_count))

    def uncreate(self) -> tuple[int, int]:
        return (self.new_session_count.uncreate(), self.resumption_count.uncreate())

class BoundedTicketRequestClientExtensionData(TicketRequestClientExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16TicketRequestClientExtensionData(BoundedTicketRequestClientExtensionData):
    _LENGTH_TYPES = (Uint16, )

class TicketRequestClientExtension(spec._SpecificSelectee[ExtensionTypes, B16TicketRequestClientExtensionData]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16TicketRequestClientExtensionData
    _SELECTOR = ExtensionTypes.TICKET_REQUEST

    @classmethod
    def create(cls, new_session_count:int, resumption_count:int) -> Self:
        return cls(data=B16TicketRequestClientExtensionData.create(new_session_count, resumption_count))

    def uncreate(self) -> tuple[int,int]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

    def replace(self, new_session_count: int|None=None, resumption_count: int|None=None) -> Self:
        orig_new_session_count, orig_resumption_count = self.uncreate()
        return self.create((orig_new_session_count if new_session_count is None else new_session_count), (orig_resumption_count if resumption_count is None else resumption_count))

class SeqPskIdentity(spec._Sequence[PskIdentity]):
    _ITEM_TYPE = PskIdentity

    @classmethod
    def create(cls, items: Iterable[tuple[bytes,int]]) -> Self:
        return cls(PskIdentity.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[bytes,int]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqPskIdentity(SeqPskIdentity, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqPskIdentity(BoundedSeqPskIdentity):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class PreSharedKeyClientExtensionData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('identities','binders',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16SeqPskIdentity,PskBinders,)
    identities: B16SeqPskIdentity
    binders: PskBinders

    def replace(self, identities:Iterable[tuple[bytes,int]]|None=None, binders:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.identities if identities is None else B16SeqPskIdentity.create(identities)), (self.binders if binders is None else PskBinders.create(binders)))

    @classmethod
    def create(cls,identities:Iterable[tuple[bytes,int]],binders:Iterable[bytes]) -> Self:
        return cls(identities=B16SeqPskIdentity.create(identities), binders=PskBinders.create(binders))

    def uncreate(self) -> tuple[Iterable[tuple[bytes,int]], Iterable[bytes]]:
        return (self.identities.uncreate(), self.binders.uncreate())

class BoundedPreSharedKeyClientExtensionData(PreSharedKeyClientExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16PreSharedKeyClientExtensionData(BoundedPreSharedKeyClientExtensionData):
    _LENGTH_TYPES = (Uint16, )

class PreSharedKeyClientExtension(spec._SpecificSelectee[ExtensionTypes, B16PreSharedKeyClientExtensionData]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16PreSharedKeyClientExtensionData
    _SELECTOR = ExtensionTypes.PRE_SHARED_KEY

    @classmethod
    def create(cls, identities:Iterable[tuple[bytes,int]], binders:Iterable[bytes]) -> Self:
        return cls(data=B16PreSharedKeyClientExtensionData.create(identities, binders))

    def uncreate(self) -> tuple[Iterable[tuple[bytes,int]],Iterable[bytes]]:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)

    def replace(self, identities: Iterable[tuple[bytes,int]]|None=None, binders: Iterable[bytes]|None=None) -> Self:
        orig_identities, orig_binders = self.uncreate()
        return self.create((orig_identities if identities is None else identities), (orig_binders if binders is None else binders))

@dataclass(frozen=True)
class OuterECHClientHelloData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cipher_suite','config_id','enc','payload',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (HpkeSymmetricCipherSuite,Uint8,B16Raw,B16Raw,)
    cipher_suite: HpkeSymmetricCipherSuite
    config_id: Uint8
    enc: B16Raw
    payload: B16Raw

    def replace(self, cipher_suite:tuple[int|HpkeKdfId,int|HpkeAeadId]|None=None, config_id:int|None=None, enc:bytes|None=None, payload:bytes|None=None) -> Self:
        return type(self)((self.cipher_suite if cipher_suite is None else HpkeSymmetricCipherSuite.create(*cipher_suite)), (self.config_id if config_id is None else Uint8.create(config_id)), (self.enc if enc is None else B16Raw.create(enc)), (self.payload if payload is None else B16Raw.create(payload)))

    @classmethod
    def create(cls,cipher_suite:tuple[int|HpkeKdfId,int|HpkeAeadId],config_id:int,enc:bytes,payload:bytes) -> Self:
        return cls(cipher_suite=HpkeSymmetricCipherSuite.create(*cipher_suite), config_id=Uint8.create(config_id), enc=B16Raw.create(enc), payload=B16Raw.create(payload))

    def uncreate(self) -> tuple[tuple[int|HpkeKdfId,int|HpkeAeadId], int, bytes, bytes]:
        return (self.cipher_suite.uncreate(), self.config_id.uncreate(), self.enc.uncreate(), self.payload.uncreate())

class OuterECHClientHello(spec._SpecificSelectee[ECHClientHelloTypes, OuterECHClientHelloData]):
    _SELECT_TYPE = ECHClientHelloType
    _DATA_TYPE = OuterECHClientHelloData
    _SELECTOR = ECHClientHelloTypes.OUTER

    @classmethod
    def create(cls, cipher_suite:tuple[int|HpkeKdfId,int|HpkeAeadId], config_id:int, enc:bytes, payload:bytes) -> Self:
        return cls(data=OuterECHClientHelloData.create(cipher_suite, config_id, enc, payload))

    def uncreate(self) -> tuple[tuple[int|HpkeKdfId,int|HpkeAeadId],int,bytes,bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ECHClientHello':
        return ECHClientHello(self)

    def replace(self, cipher_suite: tuple[int|HpkeKdfId,int|HpkeAeadId]|None=None, config_id: int|None=None, enc: bytes|None=None, payload: bytes|None=None) -> Self:
        orig_cipher_suite, orig_config_id, orig_enc, orig_payload = self.uncreate()
        return self.create((orig_cipher_suite if cipher_suite is None else cipher_suite), (orig_config_id if config_id is None else config_id), (orig_enc if enc is None else enc), (orig_payload if payload is None else payload))

class InnerECHClientHello(spec._SpecificSelectee[ECHClientHelloTypes, spec.Empty]):
    _SELECT_TYPE = ECHClientHelloType
    _DATA_TYPE = spec.Empty
    _SELECTOR = ECHClientHelloTypes.INNER

    @classmethod
    def create(cls) -> Self:
        return cls(data=spec.Empty.create())

    def uncreate(self) -> tuple[()]:
        return self.data.uncreate()

    def parent(self) -> 'ECHClientHello':
        return ECHClientHello(self)


ECHClientHelloVariant = OuterECHClientHello | InnerECHClientHello

class ECHClientHello(spec._Select[ECHClientHelloTypes]):
    _SELECT_TYPE = ECHClientHelloType
    _GENERIC_TYPE = None
    _SELECTEES = {ECHClientHelloTypes.OUTER:OuterECHClientHello, ECHClientHelloTypes.INNER:InnerECHClientHello}

    def __init__(self, value: ECHClientHelloVariant) -> None:
        super().__init__(value)
        self._value: ECHClientHelloVariant = value

    @property
    def variant(self) -> ECHClientHelloVariant:
        return self._value

    @classmethod
    def create(cls, variant: ECHClientHelloVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> ECHClientHelloVariant:
        return self.variant

class BoundedECHClientHello(ECHClientHello, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16ECHClientHello(BoundedECHClientHello):
    _LENGTH_TYPES = (Uint16, )

class EncryptedClientHelloClientExtension(spec._SpecificSelectee[ExtensionTypes, B16ECHClientHello]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16ECHClientHello
    _SELECTOR = ExtensionTypes.ENCRYPTED_CLIENT_HELLO

    @classmethod
    def create(cls, variant:ECHClientHelloVariant) -> Self:
        return cls(data=B16ECHClientHello.create(variant))

    def uncreate(self) -> ECHClientHelloVariant:
        return self.data.uncreate()

    def parent(self) -> 'ClientExtension':
        return ClientExtension(self)


ClientExtensionVariant = ServerNameClientExtension | SupportedGroupsClientExtension | SignatureAlgorithmsClientExtension | SupportedVersionsClientExtension | PskKeyExchangeModesClientExtension | KeyShareClientExtension | TicketRequestClientExtension | PreSharedKeyClientExtension | EncryptedClientHelloClientExtension | GenericClientExtension

class ClientExtension(spec._Select[ExtensionTypes]):
    _SELECT_TYPE = ExtensionType
    _GENERIC_TYPE = GenericClientExtension
    _SELECTEES = {ExtensionTypes.SERVER_NAME:ServerNameClientExtension, ExtensionTypes.SUPPORTED_GROUPS:SupportedGroupsClientExtension, ExtensionTypes.SIGNATURE_ALGORITHMS:SignatureAlgorithmsClientExtension, ExtensionTypes.SUPPORTED_VERSIONS:SupportedVersionsClientExtension, ExtensionTypes.PSK_KEY_EXCHANGE_MODES:PskKeyExchangeModesClientExtension, ExtensionTypes.KEY_SHARE:KeyShareClientExtension, ExtensionTypes.TICKET_REQUEST:TicketRequestClientExtension, ExtensionTypes.PRE_SHARED_KEY:PreSharedKeyClientExtension, ExtensionTypes.ENCRYPTED_CLIENT_HELLO:EncryptedClientHelloClientExtension}

    def __init__(self, value: ClientExtensionVariant) -> None:
        super().__init__(value)
        self._value: ClientExtensionVariant = value

    @property
    def variant(self) -> ClientExtensionVariant:
        return self._value

    @classmethod
    def create(cls, variant: ClientExtensionVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> ClientExtensionVariant:
        return self.variant

class ECHConfigVersions(enum.IntEnum):
    DRAFT_24 = 65037

    def parent(self) -> 'ECHConfigVersion':
        return ECHConfigVersion(value=self.value)
    def __str__(self) -> str:
        return f'{type(self).__name__}.{self.name}'

class ECHConfigVersion(spec._NamedConstBase[ECHConfigVersions]):
    _T = ECHConfigVersions
    _V = Uint16
    _BYTE_LENGTH = Uint16._BYTE_LENGTH
    DRAFT_24: 'ECHConfigVersion'

    def __init__(self, value: int) -> None:
        self._subclass_init(value)

class SeqHpkeSymmetricCipherSuite(spec._Sequence[HpkeSymmetricCipherSuite]):
    _ITEM_TYPE = HpkeSymmetricCipherSuite

    @classmethod
    def create(cls, items: Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]) -> Self:
        return cls(HpkeSymmetricCipherSuite.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqHpkeSymmetricCipherSuite(SeqHpkeSymmetricCipherSuite, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqHpkeSymmetricCipherSuite(BoundedSeqHpkeSymmetricCipherSuite):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class KeyConfig(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('config_id','kem_id','public_key','cipher_suites',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint8,HpkeKemId,B16Raw,B16SeqHpkeSymmetricCipherSuite,)
    config_id: Uint8
    kem_id: HpkeKemId
    public_key: B16Raw
    cipher_suites: B16SeqHpkeSymmetricCipherSuite

    def replace(self, config_id:int|None=None, kem_id:int|HpkeKemId|None=None, public_key:bytes|None=None, cipher_suites:Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]|None=None) -> Self:
        return type(self)((self.config_id if config_id is None else Uint8.create(config_id)), (self.kem_id if kem_id is None else HpkeKemId.create(kem_id)), (self.public_key if public_key is None else B16Raw.create(public_key)), (self.cipher_suites if cipher_suites is None else B16SeqHpkeSymmetricCipherSuite.create(cipher_suites)))

    @classmethod
    def create(cls,config_id:int,kem_id:int|HpkeKemId,public_key:bytes,cipher_suites:Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]) -> Self:
        return cls(config_id=Uint8.create(config_id), kem_id=HpkeKemId.create(kem_id), public_key=B16Raw.create(public_key), cipher_suites=B16SeqHpkeSymmetricCipherSuite.create(cipher_suites))

    def uncreate(self) -> tuple[int, int|HpkeKemId, bytes, Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]]:
        return (self.config_id.uncreate(), self.kem_id.uncreate(), self.public_key.uncreate(), self.cipher_suites.uncreate())

class B8String(BoundedString):
    _LENGTH_TYPES = (Uint8, )

@dataclass(frozen=True)
class Extension(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('typ','data',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (ECHConfigExtensionType,B16Raw,)
    typ: ECHConfigExtensionType
    data: B16Raw

    def replace(self, typ:int|ECHConfigExtensionType|None=None, data:bytes|None=None) -> Self:
        return type(self)((self.typ if typ is None else ECHConfigExtensionType.create(typ)), (self.data if data is None else B16Raw.create(data)))

    @classmethod
    def create(cls,typ:int|ECHConfigExtensionType,data:bytes) -> Self:
        return cls(typ=ECHConfigExtensionType.create(typ), data=B16Raw.create(data))

    def uncreate(self) -> tuple[int|ECHConfigExtensionType, bytes]:
        return (self.typ.uncreate(), self.data.uncreate())

class SeqExtension(spec._Sequence[Extension]):
    _ITEM_TYPE = Extension

    @classmethod
    def create(cls, items: Iterable[tuple[int|ECHConfigExtensionType,bytes]]) -> Self:
        return cls(Extension.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[int|ECHConfigExtensionType,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqExtension(SeqExtension, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqExtension(BoundedSeqExtension):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class Draft24ECHConfigData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('key_config','maximum_name_length','public_name','extensions',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (KeyConfig,Uint8,B8String,B16SeqExtension,)
    key_config: KeyConfig
    maximum_name_length: Uint8
    public_name: B8String
    extensions: B16SeqExtension

    def replace(self, key_config:tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]]|None=None, maximum_name_length:int|None=None, public_name:str|None=None, extensions:Iterable[tuple[int|ECHConfigExtensionType,bytes]]|None=None) -> Self:
        return type(self)((self.key_config if key_config is None else KeyConfig.create(*key_config)), (self.maximum_name_length if maximum_name_length is None else Uint8.create(maximum_name_length)), (self.public_name if public_name is None else B8String.create(public_name)), (self.extensions if extensions is None else B16SeqExtension.create(extensions)))

    @classmethod
    def create(cls,key_config:tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]],maximum_name_length:int,public_name:str,extensions:Iterable[tuple[int|ECHConfigExtensionType,bytes]]) -> Self:
        return cls(key_config=KeyConfig.create(*key_config), maximum_name_length=Uint8.create(maximum_name_length), public_name=B8String.create(public_name), extensions=B16SeqExtension.create(extensions))

    def uncreate(self) -> tuple[tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]], int, str, Iterable[tuple[int|ECHConfigExtensionType,bytes]]]:
        return (self.key_config.uncreate(), self.maximum_name_length.uncreate(), self.public_name.uncreate(), self.extensions.uncreate())

class BoundedDraft24ECHConfigData(Draft24ECHConfigData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16Draft24ECHConfigData(BoundedDraft24ECHConfigData):
    _LENGTH_TYPES = (Uint16, )

class Draft24ECHConfig(spec._SpecificSelectee[ECHConfigVersions, B16Draft24ECHConfigData]):
    _SELECT_TYPE = ECHConfigVersion
    _DATA_TYPE = B16Draft24ECHConfigData
    _SELECTOR = ECHConfigVersions.DRAFT_24

    @classmethod
    def create(cls, key_config:tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]], maximum_name_length:int, public_name:str, extensions:Iterable[tuple[int|ECHConfigExtensionType,bytes]]) -> Self:
        return cls(data=B16Draft24ECHConfigData.create(key_config, maximum_name_length, public_name, extensions))

    def uncreate(self) -> tuple[tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]],int,str,Iterable[tuple[int|ECHConfigExtensionType,bytes]]]:
        return self.data.uncreate()

    def parent(self) -> 'ECHConfig':
        return ECHConfig(self)

    def replace(self, key_config: tuple[int,int|HpkeKemId,bytes,Iterable[tuple[int|HpkeKdfId,int|HpkeAeadId]]]|None=None, maximum_name_length: int|None=None, public_name: str|None=None, extensions: Iterable[tuple[int|ECHConfigExtensionType,bytes]]|None=None) -> Self:
        orig_key_config, orig_maximum_name_length, orig_public_name, orig_extensions = self.uncreate()
        return self.create((orig_key_config if key_config is None else key_config), (orig_maximum_name_length if maximum_name_length is None else maximum_name_length), (orig_public_name if public_name is None else public_name), (orig_extensions if extensions is None else extensions))


ECHConfigVariant = Draft24ECHConfig

class ECHConfig(spec._Select[ECHConfigVersions]):
    _SELECT_TYPE = ECHConfigVersion
    _GENERIC_TYPE = None
    _SELECTEES = {ECHConfigVersions.DRAFT_24:Draft24ECHConfig}

    def __init__(self, value: ECHConfigVariant) -> None:
        super().__init__(value)
        self._value: ECHConfigVariant = value

    @property
    def variant(self) -> ECHConfigVariant:
        return self._value

    @classmethod
    def create(cls, variant: ECHConfigVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> ECHConfigVariant:
        return self.variant

class SeqECHConfigVariant(spec._Sequence[ECHConfigVariant]):
    _ITEM_TYPE = ECHConfigVariant

    @classmethod
    def create(cls, items: Iterable[ECHConfigVariant]) -> Self:
        return cls(item for item in items)

    def uncreate(self) -> Iterable[ECHConfigVariant]:
        for item in self:
            yield item

class BoundedSeqECHConfigVariant(SeqECHConfigVariant, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqECHConfigVariant(BoundedSeqECHConfigVariant):
    _LENGTH_TYPES = (Uint16, )

class ECHConfigList(spec._Wrapper[B16SeqECHConfigVariant]):
    _DATA_TYPE = B16SeqECHConfigVariant

    @classmethod
    def create(cls, items:Iterable[ECHConfigVariant]) -> Self:
        return cls(data=B16SeqECHConfigVariant.create(items))

    def uncreate(self) -> Iterable[ECHConfigVariant]:
        return self.data.uncreate()

class GenericServerExtension(spec._Selectee[ExtensionTypes, B16Raw]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16Raw

    @classmethod
    def create(cls, selector: int|ExtensionType, data: bytes) -> Self:
        return cls(selector=ExtensionType.create(selector), data=B16Raw.create(data))

    def uncreate(self) -> tuple[int|ExtensionType, bytes]:
        return (self.selector.uncreate(), self.data.uncreate())

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

@dataclass(frozen=True)
class ServerNameServerExtensionData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('name_type','host_name',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint8,B16String,)
    name_type: Uint8
    host_name: B16String

    def replace(self, name_type:int|None=None, host_name:str|None=None) -> Self:
        return type(self)((self.name_type if name_type is None else Uint8.create(name_type)), (self.host_name if host_name is None else B16String.create(host_name)))

    @classmethod
    def create(cls,name_type:int,host_name:str) -> Self:
        return cls(name_type=Uint8.create(name_type), host_name=B16String.create(host_name))

    def uncreate(self) -> tuple[int, str]:
        return (self.name_type.uncreate(), self.host_name.uncreate())

class BoundedServerNameServerExtensionData(ServerNameServerExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16ServerNameServerExtensionData(BoundedServerNameServerExtensionData):
    _LENGTH_TYPES = (Uint16, )

class SeqB16ServerNameServerExtensionData(spec._Sequence[B16ServerNameServerExtensionData]):
    _ITEM_TYPE = B16ServerNameServerExtensionData

    @classmethod
    def create(cls, items: Iterable[tuple[int,str]]) -> Self:
        return cls(B16ServerNameServerExtensionData.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[int,str]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqB16ServerNameServerExtensionData(SeqB16ServerNameServerExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqB16ServerNameServerExtensionData(BoundedSeqB16ServerNameServerExtensionData):
    _LENGTH_TYPES = (Uint16, )

class ServerNameServerExtension(spec._SpecificSelectee[ExtensionTypes, B16SeqB16ServerNameServerExtensionData]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16SeqB16ServerNameServerExtensionData
    _SELECTOR = ExtensionTypes.SERVER_NAME

    @classmethod
    def create(cls, items:Iterable[tuple[int,str]]) -> Self:
        return cls(data=B16SeqB16ServerNameServerExtensionData.create(items))

    def uncreate(self) -> Iterable[tuple[int,str]]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class SupportedGroupsServerExtension(spec._SpecificSelectee[ExtensionTypes, B16B16SeqNamedGroup]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B16SeqNamedGroup
    _SELECTOR = ExtensionTypes.SUPPORTED_GROUPS

    @classmethod
    def create(cls, items:Iterable[int|NamedGroup]) -> Self:
        return cls(data=B16B16SeqNamedGroup.create(items))

    def uncreate(self) -> Iterable[int|NamedGroup]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class SignatureAlgorithmsServerExtension(spec._SpecificSelectee[ExtensionTypes, B16B16SeqSignatureScheme]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16B16SeqSignatureScheme
    _SELECTOR = ExtensionTypes.SIGNATURE_ALGORITHMS

    @classmethod
    def create(cls, items:Iterable[int|SignatureScheme]) -> Self:
        return cls(data=B16B16SeqSignatureScheme.create(items))

    def uncreate(self) -> Iterable[int|SignatureScheme]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class B16SeqVersion(BoundedSeqVersion):
    _LENGTH_TYPES = (Uint16, )

class SupportedVersionsServerExtension(spec._SpecificSelectee[ExtensionTypes, B16SeqVersion]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16SeqVersion
    _SELECTOR = ExtensionTypes.SUPPORTED_VERSIONS

    @classmethod
    def create(cls, items:Iterable[int|Version]) -> Self:
        return cls(data=B16SeqVersion.create(items))

    def uncreate(self) -> Iterable[int|Version]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class BoundedKeyShareEntry(KeyShareEntry, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16KeyShareEntry(BoundedKeyShareEntry):
    _LENGTH_TYPES = (Uint16, )

class KeyShareServerExtension(spec._SpecificSelectee[ExtensionTypes, B16KeyShareEntry]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16KeyShareEntry
    _SELECTOR = ExtensionTypes.KEY_SHARE

    @classmethod
    def create(cls, group:int|NamedGroup, pubkey:bytes) -> Self:
        return cls(data=B16KeyShareEntry.create(group, pubkey))

    def uncreate(self) -> tuple[int|NamedGroup,bytes]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

    def replace(self, group: int|NamedGroup|None=None, pubkey: bytes|None=None) -> Self:
        orig_group, orig_pubkey = self.uncreate()
        return self.create((orig_group if group is None else group), (orig_pubkey if pubkey is None else pubkey))

@dataclass(frozen=True)
class TicketRequestServerExtensionData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('expected_count',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint8,)
    expected_count: Uint8

    def replace(self, expected_count:int|None=None) -> Self:
        return type(self)((self.expected_count if expected_count is None else Uint8.create(expected_count)))

    @classmethod
    def create(cls,expected_count:int) -> Self:
        return cls(expected_count=Uint8.create(expected_count))

    def uncreate(self) -> int:
        return (self.expected_count.uncreate())

class BoundedTicketRequestServerExtensionData(TicketRequestServerExtensionData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16TicketRequestServerExtensionData(BoundedTicketRequestServerExtensionData):
    _LENGTH_TYPES = (Uint16, )

class TicketRequestServerExtension(spec._SpecificSelectee[ExtensionTypes, B16TicketRequestServerExtensionData]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16TicketRequestServerExtensionData
    _SELECTOR = ExtensionTypes.TICKET_REQUEST

    @classmethod
    def create(cls, expected_count:int) -> Self:
        return cls(data=B16TicketRequestServerExtensionData.create(expected_count))

    def uncreate(self) -> int:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class BoundedUint16(Uint16, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16Uint16(BoundedUint16):
    _LENGTH_TYPES = (Uint16, )

class PreSharedKeyServerExtension(spec._SpecificSelectee[ExtensionTypes, B16Uint16]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16Uint16
    _SELECTOR = ExtensionTypes.PRE_SHARED_KEY

    @classmethod
    def create(cls, value:int) -> Self:
        return cls(data=B16Uint16.create(value))

    def uncreate(self) -> int:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)

class BoundedECHConfigList(ECHConfigList, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16ECHConfigList(BoundedECHConfigList):
    _LENGTH_TYPES = (Uint16, )

class EncryptedClientHelloServerExtension(spec._SpecificSelectee[ExtensionTypes, B16ECHConfigList]):
    _SELECT_TYPE = ExtensionType
    _DATA_TYPE = B16ECHConfigList
    _SELECTOR = ExtensionTypes.ENCRYPTED_CLIENT_HELLO

    @classmethod
    def create(cls, items:Iterable[ECHConfigVariant]) -> Self:
        return cls(data=B16ECHConfigList.create(items))

    def uncreate(self) -> Iterable[ECHConfigVariant]:
        return self.data.uncreate()

    def parent(self) -> 'ServerExtension':
        return ServerExtension(self)


ServerExtensionVariant = ServerNameServerExtension | SupportedGroupsServerExtension | SignatureAlgorithmsServerExtension | SupportedVersionsServerExtension | KeyShareServerExtension | TicketRequestServerExtension | PreSharedKeyServerExtension | EncryptedClientHelloServerExtension | GenericServerExtension

class ServerExtension(spec._Select[ExtensionTypes]):
    _SELECT_TYPE = ExtensionType
    _GENERIC_TYPE = GenericServerExtension
    _SELECTEES = {ExtensionTypes.SERVER_NAME:ServerNameServerExtension, ExtensionTypes.SUPPORTED_GROUPS:SupportedGroupsServerExtension, ExtensionTypes.SIGNATURE_ALGORITHMS:SignatureAlgorithmsServerExtension, ExtensionTypes.SUPPORTED_VERSIONS:SupportedVersionsServerExtension, ExtensionTypes.KEY_SHARE:KeyShareServerExtension, ExtensionTypes.TICKET_REQUEST:TicketRequestServerExtension, ExtensionTypes.PRE_SHARED_KEY:PreSharedKeyServerExtension, ExtensionTypes.ENCRYPTED_CLIENT_HELLO:EncryptedClientHelloServerExtension}

    def __init__(self, value: ServerExtensionVariant) -> None:
        super().__init__(value)
        self._value: ServerExtensionVariant = value

    @property
    def variant(self) -> ServerExtensionVariant:
        return self._value

    @classmethod
    def create(cls, variant: ServerExtensionVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> ServerExtensionVariant:
        return self.variant

class SeqServerExtension(spec._Sequence[ServerExtension]):
    _ITEM_TYPE = ServerExtension

    @classmethod
    def create(cls, items: Iterable[ServerExtensionVariant]) -> Self:
        return cls(ServerExtension.create(item) for item in items)

    def uncreate(self) -> Iterable[ServerExtensionVariant]:
        for item in self:
            yield item.uncreate()

class BoundedSeqServerExtension(SeqServerExtension, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqServerExtension(BoundedSeqServerExtension):
    _LENGTH_TYPES = (Uint16, )

class ServerExtensionList(spec._Wrapper[B16SeqServerExtension]):
    _DATA_TYPE = B16SeqServerExtension

    @classmethod
    def create(cls, items:Iterable[ServerExtensionVariant]) -> Self:
        return cls(data=B16SeqServerExtension.create(items))

    def uncreate(self) -> Iterable[ServerExtensionVariant]:
        return self.data.uncreate()

@dataclass(frozen=True)
class Ticket(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('ticket_lifetime','ticket_age_add','ticket_nonce','ticket','extensions',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Uint32,Uint32,B8Raw,B16Raw,ServerExtensionList,)
    ticket_lifetime: Uint32
    ticket_age_add: Uint32
    ticket_nonce: B8Raw
    ticket: B16Raw
    extensions: ServerExtensionList

    def replace(self, ticket_lifetime:int|None=None, ticket_age_add:int|None=None, ticket_nonce:bytes|None=None, ticket:bytes|None=None, extensions:Iterable[ServerExtensionVariant]|None=None) -> Self:
        return type(self)((self.ticket_lifetime if ticket_lifetime is None else Uint32.create(ticket_lifetime)), (self.ticket_age_add if ticket_age_add is None else Uint32.create(ticket_age_add)), (self.ticket_nonce if ticket_nonce is None else B8Raw.create(ticket_nonce)), (self.ticket if ticket is None else B16Raw.create(ticket)), (self.extensions if extensions is None else ServerExtensionList.create(extensions)))

    @classmethod
    def create(cls,ticket_lifetime:int,ticket_age_add:int,ticket_nonce:bytes,ticket:bytes,extensions:Iterable[ServerExtensionVariant]) -> Self:
        return cls(ticket_lifetime=Uint32.create(ticket_lifetime), ticket_age_add=Uint32.create(ticket_age_add), ticket_nonce=B8Raw.create(ticket_nonce), ticket=B16Raw.create(ticket), extensions=ServerExtensionList.create(extensions))

    def uncreate(self) -> tuple[int, int, bytes, bytes, Iterable[ServerExtensionVariant]]:
        return (self.ticket_lifetime.uncreate(), self.ticket_age_add.uncreate(), self.ticket_nonce.uncreate(), self.ticket.uncreate(), self.extensions.uncreate())

class F32Raw(spec._FixRaw):
    _BYTE_LENGTH = 32

class SeqCipherSuite(spec._Sequence[CipherSuite]):
    _ITEM_TYPE = CipherSuite

    @classmethod
    def create(cls, items: Iterable[int|CipherSuite]) -> Self:
        return cls(CipherSuite.create(item) for item in items)

    def uncreate(self) -> Iterable[int|CipherSuite]:
        for item in self:
            yield item.uncreate()

class BoundedSeqCipherSuite(SeqCipherSuite, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqCipherSuite(BoundedSeqCipherSuite):
    _LENGTH_TYPES = (Uint16, )

class SeqUint8(spec._Sequence[Uint8]):
    _ITEM_TYPE = Uint8

    @classmethod
    def create(cls, items: Iterable[int]) -> Self:
        return cls(Uint8.create(item) for item in items)

    def uncreate(self) -> Iterable[int]:
        for item in self:
            yield item.uncreate()

class BoundedSeqUint8(SeqUint8, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B8SeqUint8(BoundedSeqUint8):
    _LENGTH_TYPES = (Uint8, )

class SeqClientExtension(spec._Sequence[ClientExtension]):
    _ITEM_TYPE = ClientExtension

    @classmethod
    def create(cls, items: Iterable[ClientExtensionVariant]) -> Self:
        return cls(ClientExtension.create(item) for item in items)

    def uncreate(self) -> Iterable[ClientExtensionVariant]:
        for item in self:
            yield item.uncreate()

class BoundedSeqClientExtension(SeqClientExtension, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqClientExtension(BoundedSeqClientExtension):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class ClientHelloHandshakeData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('legacy_version','client_random','session_id','ciphers','legacy_compression','extensions',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Version,F32Raw,B8Raw,B16SeqCipherSuite,B8SeqUint8,B16SeqClientExtension,)
    legacy_version: Version
    client_random: F32Raw
    session_id: B8Raw
    ciphers: B16SeqCipherSuite
    legacy_compression: B8SeqUint8
    extensions: B16SeqClientExtension

    def replace(self, legacy_version:int|Version|None=None, client_random:bytes|None=None, session_id:bytes|None=None, ciphers:Iterable[int|CipherSuite]|None=None, legacy_compression:Iterable[int]|None=None, extensions:Iterable[ClientExtensionVariant]|None=None) -> Self:
        return type(self)((self.legacy_version if legacy_version is None else Version.create(legacy_version)), (self.client_random if client_random is None else F32Raw.create(client_random)), (self.session_id if session_id is None else B8Raw.create(session_id)), (self.ciphers if ciphers is None else B16SeqCipherSuite.create(ciphers)), (self.legacy_compression if legacy_compression is None else B8SeqUint8.create(legacy_compression)), (self.extensions if extensions is None else B16SeqClientExtension.create(extensions)))

    @classmethod
    def create(cls,legacy_version:int|Version,client_random:bytes,session_id:bytes,ciphers:Iterable[int|CipherSuite],legacy_compression:Iterable[int],extensions:Iterable[ClientExtensionVariant]) -> Self:
        return cls(legacy_version=Version.create(legacy_version), client_random=F32Raw.create(client_random), session_id=B8Raw.create(session_id), ciphers=B16SeqCipherSuite.create(ciphers), legacy_compression=B8SeqUint8.create(legacy_compression), extensions=B16SeqClientExtension.create(extensions))

    def uncreate(self) -> tuple[int|Version, bytes, bytes, Iterable[int|CipherSuite], Iterable[int], Iterable[ClientExtensionVariant]]:
        return (self.legacy_version.uncreate(), self.client_random.uncreate(), self.session_id.uncreate(), self.ciphers.uncreate(), self.legacy_compression.uncreate(), self.extensions.uncreate())

class BoundedClientHelloHandshakeData(ClientHelloHandshakeData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class Uint24(spec._Integral):
    _BYTE_LENGTH = 3

class B24ClientHelloHandshakeData(BoundedClientHelloHandshakeData):
    _LENGTH_TYPES = (Uint24, )

class ClientHelloHandshake(spec._SpecificSelectee[HandshakeTypes, B24ClientHelloHandshakeData]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24ClientHelloHandshakeData
    _SELECTOR = HandshakeTypes.CLIENT_HELLO

    @classmethod
    def create(cls, legacy_version:int|Version, client_random:bytes, session_id:bytes, ciphers:Iterable[int|CipherSuite], legacy_compression:Iterable[int], extensions:Iterable[ClientExtensionVariant]) -> Self:
        return cls(data=B24ClientHelloHandshakeData.create(legacy_version, client_random, session_id, ciphers, legacy_compression, extensions))

    def uncreate(self) -> tuple[int|Version,bytes,bytes,Iterable[int|CipherSuite],Iterable[int],Iterable[ClientExtensionVariant]]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

    def replace(self, legacy_version: int|Version|None=None, client_random: bytes|None=None, session_id: bytes|None=None, ciphers: Iterable[int|CipherSuite]|None=None, legacy_compression: Iterable[int]|None=None, extensions: Iterable[ClientExtensionVariant]|None=None) -> Self:
        orig_legacy_version, orig_client_random, orig_session_id, orig_ciphers, orig_legacy_compression, orig_extensions = self.uncreate()
        return self.create((orig_legacy_version if legacy_version is None else legacy_version), (orig_client_random if client_random is None else client_random), (orig_session_id if session_id is None else session_id), (orig_ciphers if ciphers is None else ciphers), (orig_legacy_compression if legacy_compression is None else legacy_compression), (orig_extensions if extensions is None else extensions))

@dataclass(frozen=True)
class ServerHelloHandshakeData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('legacy_version','server_random','session_id','cipher_suite','legacy_compression','extensions',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (Version,F32Raw,B8Raw,CipherSuite,Uint8,ServerExtensionList,)
    legacy_version: Version
    server_random: F32Raw
    session_id: B8Raw
    cipher_suite: CipherSuite
    legacy_compression: Uint8
    extensions: ServerExtensionList

    def replace(self, legacy_version:int|Version|None=None, server_random:bytes|None=None, session_id:bytes|None=None, cipher_suite:int|CipherSuite|None=None, legacy_compression:int|None=None, extensions:Iterable[ServerExtensionVariant]|None=None) -> Self:
        return type(self)((self.legacy_version if legacy_version is None else Version.create(legacy_version)), (self.server_random if server_random is None else F32Raw.create(server_random)), (self.session_id if session_id is None else B8Raw.create(session_id)), (self.cipher_suite if cipher_suite is None else CipherSuite.create(cipher_suite)), (self.legacy_compression if legacy_compression is None else Uint8.create(legacy_compression)), (self.extensions if extensions is None else ServerExtensionList.create(extensions)))

    @classmethod
    def create(cls,legacy_version:int|Version,server_random:bytes,session_id:bytes,cipher_suite:int|CipherSuite,legacy_compression:int,extensions:Iterable[ServerExtensionVariant]) -> Self:
        return cls(legacy_version=Version.create(legacy_version), server_random=F32Raw.create(server_random), session_id=B8Raw.create(session_id), cipher_suite=CipherSuite.create(cipher_suite), legacy_compression=Uint8.create(legacy_compression), extensions=ServerExtensionList.create(extensions))

    def uncreate(self) -> tuple[int|Version, bytes, bytes, int|CipherSuite, int, Iterable[ServerExtensionVariant]]:
        return (self.legacy_version.uncreate(), self.server_random.uncreate(), self.session_id.uncreate(), self.cipher_suite.uncreate(), self.legacy_compression.uncreate(), self.extensions.uncreate())

class BoundedServerHelloHandshakeData(ServerHelloHandshakeData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24ServerHelloHandshakeData(BoundedServerHelloHandshakeData):
    _LENGTH_TYPES = (Uint24, )

class ServerHelloHandshake(spec._SpecificSelectee[HandshakeTypes, B24ServerHelloHandshakeData]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24ServerHelloHandshakeData
    _SELECTOR = HandshakeTypes.SERVER_HELLO

    @classmethod
    def create(cls, legacy_version:int|Version, server_random:bytes, session_id:bytes, cipher_suite:int|CipherSuite, legacy_compression:int, extensions:Iterable[ServerExtensionVariant]) -> Self:
        return cls(data=B24ServerHelloHandshakeData.create(legacy_version, server_random, session_id, cipher_suite, legacy_compression, extensions))

    def uncreate(self) -> tuple[int|Version,bytes,bytes,int|CipherSuite,int,Iterable[ServerExtensionVariant]]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

    def replace(self, legacy_version: int|Version|None=None, server_random: bytes|None=None, session_id: bytes|None=None, cipher_suite: int|CipherSuite|None=None, legacy_compression: int|None=None, extensions: Iterable[ServerExtensionVariant]|None=None) -> Self:
        orig_legacy_version, orig_server_random, orig_session_id, orig_cipher_suite, orig_legacy_compression, orig_extensions = self.uncreate()
        return self.create((orig_legacy_version if legacy_version is None else legacy_version), (orig_server_random if server_random is None else server_random), (orig_session_id if session_id is None else session_id), (orig_cipher_suite if cipher_suite is None else cipher_suite), (orig_legacy_compression if legacy_compression is None else legacy_compression), (orig_extensions if extensions is None else extensions))

class BoundedServerExtensionList(ServerExtensionList, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24ServerExtensionList(BoundedServerExtensionList):
    _LENGTH_TYPES = (Uint24, )

class EncryptedExtensionsHandshake(spec._SpecificSelectee[HandshakeTypes, B24ServerExtensionList]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24ServerExtensionList
    _SELECTOR = HandshakeTypes.ENCRYPTED_EXTENSIONS

    @classmethod
    def create(cls, items:Iterable[ServerExtensionVariant]) -> Self:
        return cls(data=B24ServerExtensionList.create(items))

    def uncreate(self) -> Iterable[ServerExtensionVariant]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

class B24Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint24, )

@dataclass(frozen=True)
class CertificateList(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cert_data','extensions',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B24Raw,B16Raw,)
    cert_data: B24Raw
    extensions: B16Raw

    def replace(self, cert_data:bytes|None=None, extensions:bytes|None=None) -> Self:
        return type(self)((self.cert_data if cert_data is None else B24Raw.create(cert_data)), (self.extensions if extensions is None else B16Raw.create(extensions)))

    @classmethod
    def create(cls,cert_data:bytes,extensions:bytes) -> Self:
        return cls(cert_data=B24Raw.create(cert_data), extensions=B16Raw.create(extensions))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.cert_data.uncreate(), self.extensions.uncreate())

class SeqCertificateList(spec._Sequence[CertificateList]):
    _ITEM_TYPE = CertificateList

    @classmethod
    def create(cls, items: Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(CertificateList.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[bytes,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqCertificateList(SeqCertificateList, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24SeqCertificateList(BoundedSeqCertificateList):
    _LENGTH_TYPES = (Uint24, )

@dataclass(frozen=True)
class CertificateHandshakeData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('certificate_request_context','certificate_list',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8Raw,B24SeqCertificateList,)
    certificate_request_context: B8Raw
    certificate_list: B24SeqCertificateList

    def replace(self, certificate_request_context:bytes|None=None, certificate_list:Iterable[tuple[bytes,bytes]]|None=None) -> Self:
        return type(self)((self.certificate_request_context if certificate_request_context is None else B8Raw.create(certificate_request_context)), (self.certificate_list if certificate_list is None else B24SeqCertificateList.create(certificate_list)))

    @classmethod
    def create(cls,certificate_request_context:bytes,certificate_list:Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(certificate_request_context=B8Raw.create(certificate_request_context), certificate_list=B24SeqCertificateList.create(certificate_list))

    def uncreate(self) -> tuple[bytes, Iterable[tuple[bytes,bytes]]]:
        return (self.certificate_request_context.uncreate(), self.certificate_list.uncreate())

class BoundedCertificateHandshakeData(CertificateHandshakeData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24CertificateHandshakeData(BoundedCertificateHandshakeData):
    _LENGTH_TYPES = (Uint24, )

class CertificateHandshake(spec._SpecificSelectee[HandshakeTypes, B24CertificateHandshakeData]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24CertificateHandshakeData
    _SELECTOR = HandshakeTypes.CERTIFICATE

    @classmethod
    def create(cls, certificate_request_context:bytes, certificate_list:Iterable[tuple[bytes,bytes]]) -> Self:
        return cls(data=B24CertificateHandshakeData.create(certificate_request_context, certificate_list))

    def uncreate(self) -> tuple[bytes,Iterable[tuple[bytes,bytes]]]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

    def replace(self, certificate_request_context: bytes|None=None, certificate_list: Iterable[tuple[bytes,bytes]]|None=None) -> Self:
        orig_certificate_request_context, orig_certificate_list = self.uncreate()
        return self.create((orig_certificate_request_context if certificate_request_context is None else certificate_request_context), (orig_certificate_list if certificate_list is None else certificate_list))

@dataclass(frozen=True)
class CertificateVerifyHandshakeData(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('algorithm','signature',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SignatureScheme,B16Raw,)
    algorithm: SignatureScheme
    signature: B16Raw

    def replace(self, algorithm:int|SignatureScheme|None=None, signature:bytes|None=None) -> Self:
        return type(self)((self.algorithm if algorithm is None else SignatureScheme.create(algorithm)), (self.signature if signature is None else B16Raw.create(signature)))

    @classmethod
    def create(cls,algorithm:int|SignatureScheme,signature:bytes) -> Self:
        return cls(algorithm=SignatureScheme.create(algorithm), signature=B16Raw.create(signature))

    def uncreate(self) -> tuple[int|SignatureScheme, bytes]:
        return (self.algorithm.uncreate(), self.signature.uncreate())

class BoundedCertificateVerifyHandshakeData(CertificateVerifyHandshakeData, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24CertificateVerifyHandshakeData(BoundedCertificateVerifyHandshakeData):
    _LENGTH_TYPES = (Uint24, )

class CertificateVerifyHandshake(spec._SpecificSelectee[HandshakeTypes, B24CertificateVerifyHandshakeData]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24CertificateVerifyHandshakeData
    _SELECTOR = HandshakeTypes.CERTIFICATE_VERIFY

    @classmethod
    def create(cls, algorithm:int|SignatureScheme, signature:bytes) -> Self:
        return cls(data=B24CertificateVerifyHandshakeData.create(algorithm, signature))

    def uncreate(self) -> tuple[int|SignatureScheme,bytes]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

    def replace(self, algorithm: int|SignatureScheme|None=None, signature: bytes|None=None) -> Self:
        orig_algorithm, orig_signature = self.uncreate()
        return self.create((orig_algorithm if algorithm is None else algorithm), (orig_signature if signature is None else signature))

class FinishedHandshake(spec._SpecificSelectee[HandshakeTypes, B24Raw]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24Raw
    _SELECTOR = HandshakeTypes.FINISHED

    @classmethod
    def create(cls, value:bytes) -> Self:
        return cls(data=B24Raw.create(value))

    def uncreate(self) -> bytes:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

class BoundedTicket(Ticket, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B24Ticket(BoundedTicket):
    _LENGTH_TYPES = (Uint24, )

class NewSessionTicketHandshake(spec._SpecificSelectee[HandshakeTypes, B24Ticket]):
    _SELECT_TYPE = HandshakeType
    _DATA_TYPE = B24Ticket
    _SELECTOR = HandshakeTypes.NEW_SESSION_TICKET

    @classmethod
    def create(cls, ticket_lifetime:int, ticket_age_add:int, ticket_nonce:bytes, ticket:bytes, extensions:Iterable[ServerExtensionVariant]) -> Self:
        return cls(data=B24Ticket.create(ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions))

    def uncreate(self) -> tuple[int,int,bytes,bytes,Iterable[ServerExtensionVariant]]:
        return self.data.uncreate()

    def parent(self) -> 'Handshake':
        return Handshake(self)

    def replace(self, ticket_lifetime: int|None=None, ticket_age_add: int|None=None, ticket_nonce: bytes|None=None, ticket: bytes|None=None, extensions: Iterable[ServerExtensionVariant]|None=None) -> Self:
        orig_ticket_lifetime, orig_ticket_age_add, orig_ticket_nonce, orig_ticket, orig_extensions = self.uncreate()
        return self.create((orig_ticket_lifetime if ticket_lifetime is None else ticket_lifetime), (orig_ticket_age_add if ticket_age_add is None else ticket_age_add), (orig_ticket_nonce if ticket_nonce is None else ticket_nonce), (orig_ticket if ticket is None else ticket), (orig_extensions if extensions is None else extensions))


HandshakeVariant = ClientHelloHandshake | ServerHelloHandshake | EncryptedExtensionsHandshake | CertificateHandshake | CertificateVerifyHandshake | FinishedHandshake | NewSessionTicketHandshake

class Handshake(spec._Select[HandshakeTypes]):
    _SELECT_TYPE = HandshakeType
    _GENERIC_TYPE = None
    _SELECTEES = {HandshakeTypes.CLIENT_HELLO:ClientHelloHandshake, HandshakeTypes.SERVER_HELLO:ServerHelloHandshake, HandshakeTypes.ENCRYPTED_EXTENSIONS:EncryptedExtensionsHandshake, HandshakeTypes.CERTIFICATE:CertificateHandshake, HandshakeTypes.CERTIFICATE_VERIFY:CertificateVerifyHandshake, HandshakeTypes.FINISHED:FinishedHandshake, HandshakeTypes.NEW_SESSION_TICKET:NewSessionTicketHandshake}

    def __init__(self, value: HandshakeVariant) -> None:
        super().__init__(value)
        self._value: HandshakeVariant = value

    @property
    def variant(self) -> HandshakeVariant:
        return self._value

    @classmethod
    def create(cls, variant: HandshakeVariant) -> Self:
        return cls(variant)

    def uncreate(self) -> HandshakeVariant:
        return self.variant

@dataclass(frozen=True)
class Alert(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('level','description',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (AlertLevel,AlertDescription,)
    level: AlertLevel
    description: AlertDescription

    def replace(self, level:int|AlertLevel|None=None, description:int|AlertDescription|None=None) -> Self:
        return type(self)((self.level if level is None else AlertLevel.create(level)), (self.description if description is None else AlertDescription.create(description)))

    @classmethod
    def create(cls,level:int|AlertLevel,description:int|AlertDescription) -> Self:
        return cls(level=AlertLevel.create(level), description=AlertDescription.create(description))

    def uncreate(self) -> tuple[int|AlertLevel, int|AlertDescription]:
        return (self.level.uncreate(), self.description.uncreate())

@dataclass(frozen=True)
class RecordHeader(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('typ','version','size',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (ContentType,Version,Uint16,)
    typ: ContentType
    version: Version
    size: Uint16

    def replace(self, typ:int|ContentType|None=None, version:int|Version|None=None, size:int|None=None) -> Self:
        return type(self)((self.typ if typ is None else ContentType.create(typ)), (self.version if version is None else Version.create(version)), (self.size if size is None else Uint16.create(size)))

    @classmethod
    def create(cls,typ:int|ContentType,version:int|Version,size:int) -> Self:
        return cls(typ=ContentType.create(typ), version=Version.create(version), size=Uint16.create(size))

    def uncreate(self) -> tuple[int|ContentType, int|Version, int]:
        return (self.typ.uncreate(), self.version.uncreate(), self.size.uncreate())

@dataclass(frozen=True)
class Record(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('typ','version','payload',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (ContentType,Version,B16Raw,)
    typ: ContentType
    version: Version
    payload: B16Raw

    def replace(self, typ:int|ContentType|None=None, version:int|Version|None=None, payload:bytes|None=None) -> Self:
        return type(self)((self.typ if typ is None else ContentType.create(typ)), (self.version if version is None else Version.create(version)), (self.payload if payload is None else B16Raw.create(payload)))

    @classmethod
    def create(cls,typ:int|ContentType,version:int|Version,payload:bytes) -> Self:
        return cls(typ=ContentType.create(typ), version=Version.create(version), payload=B16Raw.create(payload))

    def uncreate(self) -> tuple[int|ContentType, int|Version, bytes]:
        return (self.typ.uncreate(), self.version.uncreate(), self.payload.uncreate())

class B32Raw(BoundedRaw):
    _LENGTH_TYPES = (Uint32, )

@dataclass(frozen=True)
class CertSecrets(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('sig_alg','private_key','cert_der',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (SignatureScheme,B32Raw,B32Raw,)
    sig_alg: SignatureScheme
    private_key: B32Raw
    cert_der: B32Raw

    def replace(self, sig_alg:int|SignatureScheme|None=None, private_key:bytes|None=None, cert_der:bytes|None=None) -> Self:
        return type(self)((self.sig_alg if sig_alg is None else SignatureScheme.create(sig_alg)), (self.private_key if private_key is None else B32Raw.create(private_key)), (self.cert_der if cert_der is None else B32Raw.create(cert_der)))

    @classmethod
    def create(cls,sig_alg:int|SignatureScheme,private_key:bytes,cert_der:bytes) -> Self:
        return cls(sig_alg=SignatureScheme.create(sig_alg), private_key=B32Raw.create(private_key), cert_der=B32Raw.create(cert_der))

    def uncreate(self) -> tuple[int|SignatureScheme, bytes, bytes]:
        return (self.sig_alg.uncreate(), self.private_key.uncreate(), self.cert_der.uncreate())

@dataclass(frozen=True)
class EchSecrets(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('config','private_key',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (ECHConfigVariant,B32Raw,)
    config: ECHConfigVariant
    private_key: B32Raw

    def replace(self, config:ECHConfigVariant|None=None, private_key:bytes|None=None) -> Self:
        return type(self)((self.config if config is None else config), (self.private_key if private_key is None else B32Raw.create(private_key)))

    @classmethod
    def create(cls,config:ECHConfigVariant,private_key:bytes) -> Self:
        return cls(config=config, private_key=B32Raw.create(private_key))

    def uncreate(self) -> tuple[ECHConfigVariant, bytes]:
        return (self.config, self.private_key.uncreate())

class SeqEchSecrets(spec._Sequence[EchSecrets]):
    _ITEM_TYPE = EchSecrets

    @classmethod
    def create(cls, items: Iterable[tuple[ECHConfigVariant,bytes]]) -> Self:
        return cls(EchSecrets.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[ECHConfigVariant,bytes]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqEchSecrets(SeqEchSecrets, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B32SeqEchSecrets(BoundedSeqEchSecrets):
    _LENGTH_TYPES = (Uint32, )

@dataclass(frozen=True)
class ServerSecrets(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cert','eches',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (CertSecrets,B32SeqEchSecrets,)
    cert: CertSecrets
    eches: B32SeqEchSecrets

    def replace(self, cert:tuple[int|SignatureScheme,bytes,bytes]|None=None, eches:Iterable[tuple[ECHConfigVariant,bytes]]|None=None) -> Self:
        return type(self)((self.cert if cert is None else CertSecrets.create(*cert)), (self.eches if eches is None else B32SeqEchSecrets.create(eches)))

    @classmethod
    def create(cls,cert:tuple[int|SignatureScheme,bytes,bytes],eches:Iterable[tuple[ECHConfigVariant,bytes]]) -> Self:
        return cls(cert=CertSecrets.create(*cert), eches=B32SeqEchSecrets.create(eches))

    def uncreate(self) -> tuple[tuple[int|SignatureScheme,bytes,bytes], Iterable[tuple[ECHConfigVariant,bytes]]]:
        return (self.cert.uncreate(), self.eches.uncreate())

@dataclass(frozen=True)
class PyhpkeKeypair(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('private','public',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B32Raw,B32Raw,)
    private: B32Raw
    public: B32Raw

    def replace(self, private:bytes|None=None, public:bytes|None=None) -> Self:
        return type(self)((self.private if private is None else B32Raw.create(private)), (self.public if public is None else B32Raw.create(public)))

    @classmethod
    def create(cls,private:bytes,public:bytes) -> Self:
        return cls(private=B32Raw.create(private), public=B32Raw.create(public))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.private.uncreate(), self.public.uncreate())

class B8SeqPskKeyExchangeMode(BoundedSeqPskKeyExchangeMode):
    _LENGTH_TYPES = (Uint8, )

class Uint64(spec._Integral):
    _BYTE_LENGTH = 8

@dataclass(frozen=True)
class TicketInfoStruct(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('ticket_id','secret','csuite','modes','mask','lifetime','creation',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16Raw,B8Raw,CipherSuite,B8SeqPskKeyExchangeMode,Uint32,Uint32,Uint64,)
    ticket_id: B16Raw
    secret: B8Raw
    csuite: CipherSuite
    modes: B8SeqPskKeyExchangeMode
    mask: Uint32
    lifetime: Uint32
    creation: Uint64

    def replace(self, ticket_id:bytes|None=None, secret:bytes|None=None, csuite:int|CipherSuite|None=None, modes:Iterable[int|PskKeyExchangeMode]|None=None, mask:int|None=None, lifetime:int|None=None, creation:int|None=None) -> Self:
        return type(self)((self.ticket_id if ticket_id is None else B16Raw.create(ticket_id)), (self.secret if secret is None else B8Raw.create(secret)), (self.csuite if csuite is None else CipherSuite.create(csuite)), (self.modes if modes is None else B8SeqPskKeyExchangeMode.create(modes)), (self.mask if mask is None else Uint32.create(mask)), (self.lifetime if lifetime is None else Uint32.create(lifetime)), (self.creation if creation is None else Uint64.create(creation)))

    @classmethod
    def create(cls,ticket_id:bytes,secret:bytes,csuite:int|CipherSuite,modes:Iterable[int|PskKeyExchangeMode],mask:int,lifetime:int,creation:int) -> Self:
        return cls(ticket_id=B16Raw.create(ticket_id), secret=B8Raw.create(secret), csuite=CipherSuite.create(csuite), modes=B8SeqPskKeyExchangeMode.create(modes), mask=Uint32.create(mask), lifetime=Uint32.create(lifetime), creation=Uint64.create(creation))

    def uncreate(self) -> tuple[bytes, bytes, int|CipherSuite, Iterable[int|PskKeyExchangeMode], int, int, int]:
        return (self.ticket_id.uncreate(), self.secret.uncreate(), self.csuite.uncreate(), self.modes.uncreate(), self.mask.uncreate(), self.lifetime.uncreate(), self.creation.uncreate())

@dataclass(frozen=True)
class ServerTicketPlaintext(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('cipher_suite','expiration','psk',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (CipherSuite,Uint64,B16Raw,)
    cipher_suite: CipherSuite
    expiration: Uint64
    psk: B16Raw

    def replace(self, cipher_suite:int|CipherSuite|None=None, expiration:int|None=None, psk:bytes|None=None) -> Self:
        return type(self)((self.cipher_suite if cipher_suite is None else CipherSuite.create(cipher_suite)), (self.expiration if expiration is None else Uint64.create(expiration)), (self.psk if psk is None else B16Raw.create(psk)))

    @classmethod
    def create(cls,cipher_suite:int|CipherSuite,expiration:int,psk:bytes) -> Self:
        return cls(cipher_suite=CipherSuite.create(cipher_suite), expiration=Uint64.create(expiration), psk=B16Raw.create(psk))

    def uncreate(self) -> tuple[int|CipherSuite, int, bytes]:
        return (self.cipher_suite.uncreate(), self.expiration.uncreate(), self.psk.uncreate())

@dataclass(frozen=True)
class ServerTicketCiphertext(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('inner_ciphertext','iv',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16Raw,B8Raw,)
    inner_ciphertext: B16Raw
    iv: B8Raw

    def replace(self, inner_ciphertext:bytes|None=None, iv:bytes|None=None) -> Self:
        return type(self)((self.inner_ciphertext if inner_ciphertext is None else B16Raw.create(inner_ciphertext)), (self.iv if iv is None else B8Raw.create(iv)))

    @classmethod
    def create(cls,inner_ciphertext:bytes,iv:bytes) -> Self:
        return cls(inner_ciphertext=B16Raw.create(inner_ciphertext), iv=B8Raw.create(iv))

    def uncreate(self) -> tuple[bytes, bytes]:
        return (self.inner_ciphertext.uncreate(), self.iv.uncreate())

@dataclass(frozen=True)
class InnerPlaintextBase(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('payload','typ','padding',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (spec.Raw,ContentType,spec.Fill,)
    payload: spec.Raw
    typ: ContentType
    padding: spec.Fill

    def replace(self, payload:bytes|None=None, typ:int|ContentType|None=None, padding:int|None=None) -> Self:
        return type(self)((self.payload if payload is None else spec.Raw.create(payload)), (self.typ if typ is None else ContentType.create(typ)), (self.padding if padding is None else spec.Fill.create(padding)))

    @classmethod
    def create(cls,payload:bytes,typ:int|ContentType,padding:int) -> Self:
        return cls(payload=spec.Raw.create(payload), typ=ContentType.create(typ), padding=spec.Fill.create(padding))

    def uncreate(self) -> tuple[bytes, int|ContentType, int]:
        return (self.payload.uncreate(), self.typ.uncreate(), self.padding.uncreate())

@dataclass(frozen=True)
class RecordEntry(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('raw','record','from_client',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B16Raw,Record,spec.Bool,)
    raw: B16Raw
    record: Record
    from_client: spec.Bool

    def replace(self, raw:bytes|None=None, record:tuple[int|ContentType,int|Version,bytes]|None=None, from_client:bool|None=None) -> Self:
        return type(self)((self.raw if raw is None else B16Raw.create(raw)), (self.record if record is None else Record.create(*record)), (self.from_client if from_client is None else spec.Bool.create(from_client)))

    @classmethod
    def create(cls,raw:bytes,record:tuple[int|ContentType,int|Version,bytes],from_client:bool) -> Self:
        return cls(raw=B16Raw.create(raw), record=Record.create(*record), from_client=spec.Bool.create(from_client))

    def uncreate(self) -> tuple[bytes, tuple[int|ContentType,int|Version,bytes], bool]:
        return (self.raw.uncreate(), self.record.uncreate(), self.from_client.uncreate())

class SeqB16Raw(spec._Sequence[B16Raw]):
    _ITEM_TYPE = B16Raw

    @classmethod
    def create(cls, items: Iterable[bytes]) -> Self:
        return cls(B16Raw.create(item) for item in items)

    def uncreate(self) -> Iterable[bytes]:
        for item in self:
            yield item.uncreate()

class BoundedSeqB16Raw(SeqB16Raw, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B16SeqB16Raw(BoundedSeqB16Raw):
    _LENGTH_TYPES = (Uint16, )

@dataclass(frozen=True)
class ClientSecrets(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('psk','kex_sks',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8Raw,B16SeqB16Raw,)
    psk: B8Raw
    kex_sks: B16SeqB16Raw

    def replace(self, psk:bytes|None=None, kex_sks:Iterable[bytes]|None=None) -> Self:
        return type(self)((self.psk if psk is None else B8Raw.create(psk)), (self.kex_sks if kex_sks is None else B16SeqB16Raw.create(kex_sks)))

    @classmethod
    def create(cls,psk:bytes,kex_sks:Iterable[bytes]) -> Self:
        return cls(psk=B8Raw.create(psk), kex_sks=B16SeqB16Raw.create(kex_sks))

    def uncreate(self) -> tuple[bytes, Iterable[bytes]]:
        return (self.psk.uncreate(), self.kex_sks.uncreate())

class SeqRecordEntry(spec._Sequence[RecordEntry]):
    _ITEM_TYPE = RecordEntry

    @classmethod
    def create(cls, items: Iterable[tuple[bytes,tuple[int|ContentType,int|Version,bytes],bool]]) -> Self:
        return cls(RecordEntry.create(*item) for item in items)

    def uncreate(self) -> Iterable[tuple[bytes,tuple[int|ContentType,int|Version,bytes],bool]]:
        for item in self:
            yield item.uncreate()

class BoundedSeqRecordEntry(SeqRecordEntry, Spec):
    _LENGTH_TYPES: tuple[type[spec._Integral],...]

    @override
    def packed_size(self) -> int:
        return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

    @override
    def pack(self) -> bytes:
        raw = super().pack()
        length = len(raw)
        parts = [raw]
        for LT in reversed(self._LENGTH_TYPES):
            parts.append(LT(length).pack())
            length += LT._BYTE_LENGTH
        parts.reverse()
        return b''.join(parts)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return Spec.pack_to(self, dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        offset = 0
        for LT in cls._LENGTH_TYPES:
            lenlen = LT._BYTE_LENGTH
            if len(raw) < offset + lenlen:
                raise ValueError
            length = LT.unpack(raw[offset:offset+lenlen])
            if len(raw) != offset + lenlen + length:
                raise ValueError
            offset += lenlen
        try:
            return super().unpack(raw[offset:])
        except UnpackError as e:
            raise e.above(raw, {'bounded_size': length, 'data': e.partial}) from e

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        lit = iter(cls._LENGTH_TYPES)
        length = next(lit).unpack_from(src)
        for LT in lit:
            len2 = LT.unpack_from(src)
            if length != LT._BYTE_LENGTH + len2:
                raise UnpackError(src.got, f"bounded length should have been {length - LT._BYTE_LENGTH} but got {len2}")
            length = len2
        supraw = src.read(length)
        try:
            return super().unpack(supraw)
        except UnpackError as e:
            raise e.above(src.got, {'bounded_size': length, 'data': e.partial}) from e

class B32SeqRecordEntry(BoundedSeqRecordEntry):
    _LENGTH_TYPES = (Uint32, )

@dataclass(frozen=True)
class Transcript(spec._StructBase):
    _member_names: ClassVar[tuple[str,...]] = ('psk','kex_secret','records',)
    _member_types: ClassVar[tuple[type[Spec],...]] = (B8Raw,B8Raw,B32SeqRecordEntry,)
    psk: B8Raw
    kex_secret: B8Raw
    records: B32SeqRecordEntry

    def replace(self, psk:bytes|None=None, kex_secret:bytes|None=None, records:Iterable[tuple[bytes,tuple[int|ContentType,int|Version,bytes],bool]]|None=None) -> Self:
        return type(self)((self.psk if psk is None else B8Raw.create(psk)), (self.kex_secret if kex_secret is None else B8Raw.create(kex_secret)), (self.records if records is None else B32SeqRecordEntry.create(records)))

    @classmethod
    def create(cls,psk:bytes,kex_secret:bytes,records:Iterable[tuple[bytes,tuple[int|ContentType,int|Version,bytes],bool]]) -> Self:
        return cls(psk=B8Raw.create(psk), kex_secret=B8Raw.create(kex_secret), records=B32SeqRecordEntry.create(records))

    def uncreate(self) -> tuple[bytes, bytes, Iterable[tuple[bytes,tuple[int|ContentType,int|Version,bytes],bool]]]:
        return (self.psk.uncreate(), self.kex_secret.uncreate(), self.records.uncreate())

_enum_types: list[type[spec._NamedConstBase[Any]]] = [ClientState, ServerState, ContentType, HandshakeType, ExtensionType, SignatureScheme, NamedGroup, CipherSuite, PskKeyExchangeMode, CertificateType, Version, AlertLevel, AlertDescription, ECHClientHelloType, ECHConfigExtensionType, HpkeKemId, HpkeKdfId, HpkeAeadId, ECHConfigVersion]
def _set_enum_constants() -> None:
    for etype in _enum_types:
        for enum_val in etype._T:
            setattr(etype, enum_val.name, etype.create(enum_val.value))
_set_enum_constants()
