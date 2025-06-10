#!/usr/bin/env python3

from util import kwdict
from spec import (
    Raw,
    String,
    Empty,
    Fill,
    Bool,
)
from spec_gen import (
    GenSpec,
    NamedConst,
    NamedConst,
    Struct,
    Uint,
    Sequence,
    Bounded,
    Select,
    Wrap,
    FixRaw,
    generate_specs,
)

specs: dict[str, GenSpec] = kwdict(
    ClientState = NamedConst(8)(
        # rfc8446#appendix-A.1
        START         = 0,
        WAIT_SH       = 1,
        WAIT_EE       = 2,
        WAIT_CERT_CR  = 3,
        WAIT_CERT     = 4,
        WAIT_CV       = 5,
        WAIT_FINISHED = 6,
        CONNECTED     = 7,
        CLOSED        = 8,
        ERROR         = 9,
    ),
    ServerState = NamedConst(8)(
        # rfc8446#appendix-A.2
        START         = 0,
        RECVD_CH      = 1,
        NEGOTIATED    = 2,
        WAIT_EOED     = 3,
        WAIT_FLIGHT2  = 4,
        WAIT_CERT     = 5,
        WAIT_CV       = 6,
        WAIT_FINISHED = 7,
        CONNECTED     = 8,
    ),
    ContentType = NamedConst(8)(
        INVALID            = 0,
        CHANGE_CIPHER_SPEC = 20,
        ALERT              = 21,
        HANDSHAKE          = 22,
        APPLICATION_DATA   = 23,
        HEARTBEAT          = 24,
    ),
    HandshakeType = NamedConst(8)(
        CLIENT_HELLO         = 1,
        SERVER_HELLO         = 2,
        NEW_SESSION_TICKET   = 4,
        END_OF_EARLY_DATA    = 5,
        ENCRYPTED_EXTENSIONS = 8,
        CERTIFICATE          = 11,
        CERTIFICATE_REQUEST  = 13,
        CERTIFICATE_VERIFY   = 15,
        FINISHED             = 20,
        KEY_UPDATE           = 24,
        MESSAGE_HASH         = 254,
    ),
    ExtensionType = NamedConst(16, 'UNSUPPORTED')(
        SERVER_NAME                            = 0,
        MAX_FRAGMENT_LENGTH                    = 1,
        STATUS_REQUEST                         = 5,
        SUPPORTED_GROUPS                       = 10,
        LEGACY_EC_POINT_FORMATS                = 11,
        SIGNATURE_ALGORITHMS                   = 13,
        USE_SRTP                               = 14,
        HEARTBEAT                              = 15,
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
        SIGNED_CERTIFICATE_TIMESTAMP           = 18,
        CLIENT_CERTIFICATE_TYPE                = 19,
        SERVER_CERTIFICATE_TYPE                = 20,
        PADDING                                = 21,
        LEGACY_ENCRYPT_THEN_MAC                = 22,
        LEGACY_EXTENDED_MASTER_SECRET          = 23,
        LEGACY_SESSION_TICKET                  = 35,
        PRE_SHARED_KEY                         = 41,
        EARLY_DATA                             = 42,
        SUPPORTED_VERSIONS                     = 43,
        COOKIE                                 = 44,
        PSK_KEY_EXCHANGE_MODES                 = 45,
        CERTIFICATE_AUTHORITIES                = 47,
        OID_FILTERS                            = 48,
        POST_HANDSHAKE_AUTH                    = 49,
        SIGNATURE_ALGORITHMS_CERT              = 50,
        KEY_SHARE                              = 51,
        TICKET_REQUEST                         = 58,
        UNSUPPORTED                            = 2570,
        ENCRYPTED_CLIENT_HELLO                 = 65037,
    ),
    SignatureScheme = NamedConst(16)(
        RSA_PKCS1_SHA256       = 0x0401,
        RSA_PKCS1_SHA384       = 0x0501,
        RSA_PKCS1_SHA512       = 0x0601,
        ECDSA_SECP256R1_SHA256 = 0x0403,
        ECDSA_SECP384R1_SHA384 = 0x0503,
        ECDSA_SECP521R1_SHA512 = 0x0603,
        RSA_PSS_RSAE_SHA256    = 0x0804,
        RSA_PSS_RSAE_SHA384    = 0x0805,
        RSA_PSS_RSAE_SHA512    = 0x0806,
        ED25519                = 0x0807,
        ED448                  = 0x0808,
        RSA_PSS_PSS_SHA256     = 0x0809,
        RSA_PSS_PSS_SHA384     = 0x080a,
        RSA_PSS_PSS_SHA512     = 0x080b,
        RSA_PKCS1_SHA1         = 0x0201,
        ECDSA_SHA1             = 0x0203,
    ),
    NamedGroup = NamedConst(16, 'UNSUPPORTED')(
        SECP256R1   = 0x0017,
        SECP384R1   = 0x0018,
        SECP521R1   = 0x0019,
        X25519      = 0x001d,
        X448        = 0x001e,
        FFDHE2048   = 0x0100,
        FFDHE3072   = 0x0101,
        FFDHE4096   = 0x0102,
        FFDHE6144   = 0x0103,
        FFDHE8192   = 0x0104,
        UNSUPPORTED = 0xFFFF,
    ),
    CipherSuite = NamedConst(16, 'UNSUPPORTED')(
        TLS_AES_128_GCM_SHA256                   = 0x1301,
        TLS_AES_256_GCM_SHA384                   = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256             = 0x1303,
        TLS_AES_128_CCM_SHA256                   = 0x1304,
        TLS_AES_128_CCM_8_SHA256                 = 0x1305,
        LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
        UNSUPPORTED                              = 0x4a4a,
    ),
    PskKeyExchangeMode = NamedConst(8)(
        PSK_KE     = 0,
        PSK_DHE_KE = 1,
    ),
    CertificateType = NamedConst(8)(
        X509         = 0,
        RawPublicKey = 2,
    ),
    Version = NamedConst(16)(
        TLS_1_0 = 0x0301,
        TLS_1_2 = 0x0303,
        TLS_1_3 = 0x0304,
    ),
    AlertLevel = NamedConst(8)(
        WARNING = 1,
        FATAL   = 2,
    ),
    AlertDescription = NamedConst(8)(
        CLOSE_NOTIFY                        = 0,
        UNEXPECTED_MESSAGE                  = 10,
        BAD_RECORD_MAC                      = 20,
        RECORD_OVERFLOW                     = 22,
        HANDSHAKE_FAILURE                   = 40,
        BAD_CERTIFICATE                     = 42,
        UNSUPPORTED_CERTIFICATE             = 43,
        CERTIFICATE_REVOKED                 = 44,
        CERTIFICATE_EXPIRED                 = 45,
        CERTIFICATE_UNKNOWN                 = 46,
        ILLEGAL_PARAMETER                   = 47,
        UNKNOWN_CA                          = 48,
        ACCESS_DENIED                       = 49,
        DECODE_ERROR                        = 50,
        DECRYPT_ERROR                       = 51,
        PROTOCOL_VERSION                    = 70,
        INSUFFICIENT_SECURITY               = 71,
        INTERNAL_ERROR                      = 80,
        INAPPROPRIATE_FALLBACK              = 86,
        USER_CANCELED                       = 90,
        MISSING_EXTENSION                   = 109,
        UNSUPPORTED_EXTENSION               = 110,
        UNRECOGNIZED_NAME                   = 112,
        BAD_CERTIFICATE_STATUS_RESPONSE     = 113,
        UNKNOWN_PSK_IDENTITY                = 115,
        CERTIFICATE_REQUIRED                = 116,
        NO_APPLICATION_PROTOCOL             = 120,
    ),
    ECHClientHelloType = NamedConst(8)(
        OUTER = 0,
        INNER = 1,
    ),
    ECHConfigExtensionType = NamedConst(16, 'UNSUPPORTED')(
        UNSUPPORTED = 0xffff,
    ),
    HpkeKemId = NamedConst(16)(
        DHKEM_P256_HKDF_SHA256  = 0x0010,
        DHKEM_P384_HKDF_SHA384  = 0x0011,
        DHKEM_P521_HKDF_SHA512  = 0x0012,
        DHKEM_X25519_HKDF_SHA256 = 0x0020,
        DHKEM_X448_HKDF_SHA512   = 0x0021,
    ),
    HpkeKdfId = NamedConst(16)(
        HKDF_SHA256 = 0x0001,
        HKDF_SHA384 = 0x0002,
        HKDF_SHA512 = 0x0003,
    ),
    HpkeAeadId = NamedConst(16)(
        AES_128_GCM       = 0x0001,
        AES_256_GCM       = 0x0002,
        CHACHA20_POLY1305 = 0x0003,
    ),

    HkdfLabel = Struct(
        length  = Uint(16),
        label   = Bounded(8, Raw),
        context = Bounded(8, Raw),
    ),
    KeyShareEntry = Struct(
        group  = 'NamedGroup',
        pubkey = Bounded(16, Raw),
    ),
    PskIdentity = Struct(
        identity              = Bounded(16, Raw),
        obfuscated_ticket_age = Uint(32),
    ),
    HpkeSymmetricCipherSuite = Struct(
        kdf_id  = 'HpkeKdfId',
        aead_id = 'HpkeAeadId',
    ),
    PskBinders = Wrap(Bounded(16, Sequence(Bounded(8, Raw)))),

    ClientExtension = Select('ExtensionType', 16, Raw)(
        SERVER_NAME =
            Sequence(Bounded(16, Struct(
                name_type = Uint(8), # TODO FIXME .const(0),
                host_name = Bounded(16, String),
            ))),
        SUPPORTED_GROUPS =
            Bounded(16, Sequence('NamedGroup')),
        SIGNATURE_ALGORITHMS =
            Bounded(16, Sequence('SignatureScheme')),
        SUPPORTED_VERSIONS =
            Bounded(8, Sequence('Version')),
        PSK_KEY_EXCHANGE_MODES =
            Bounded(8, Sequence('PskKeyExchangeMode')),
        KEY_SHARE =
            Bounded(16, Sequence('KeyShareEntry')),
        TICKET_REQUEST =
            Struct(
                new_session_count = Uint(8),
                resumption_count  = Uint(8),
            ),
        PRE_SHARED_KEY =
            Struct(
                identities = Bounded(16, Sequence('PskIdentity')),
                binders    = 'PskBinders',
            ),
        ENCRYPTED_CLIENT_HELLO =
            Select('ECHClientHelloType')(
                OUTER =
                    Struct(
                        cipher_suite = 'HpkeSymmetricCipherSuite',
                        config_id    = Uint(8),
                        enc          = Bounded(16, Raw),
                        payload      = Bounded(16, Raw),
                    ),
                INNER = Empty,
            ),
    ),

    ECHConfigVersion = NamedConst(16)(
        DRAFT_24 = 0xfe0d,
    ),

    ECHConfig = Select('ECHConfigVersion', 16)(
        DRAFT_24 = Struct(
            key_config = Struct (
                config_id     = Uint(8),
                kem_id        = 'HpkeKemId',
                public_key    = Bounded(16, Raw),
                cipher_suites = Bounded(16, Sequence('HpkeSymmetricCipherSuite')),
            ),
            maximum_name_length = Uint(8),
            public_name         = Bounded(8, String),
            extensions          = Bounded(16, Sequence(Struct(
                typ  = 'ECHConfigExtensionType',
                data = Bounded(16, Raw),
            ))),
        ),
    ),

    ECHConfigList = Wrap(Bounded(16, Sequence('ECHConfigVariant'))),

    ServerExtension = Select('ExtensionType', 16, Raw)(
        SERVER_NAME =
            Sequence(Bounded(16, Struct(
                name_type = Uint(8),
                host_name = Bounded(16, String),
            ))),
        SUPPORTED_GROUPS =
            Bounded(16, Sequence('NamedGroup')),
        SIGNATURE_ALGORITHMS =
            Bounded(16, Sequence('SignatureScheme')),
        SUPPORTED_VERSIONS =
            Sequence('Version'),
        KEY_SHARE = 'KeyShareEntry',
        TICKET_REQUEST = Struct(expected_count = Uint(8)),
        PRE_SHARED_KEY = Uint(16),
        ENCRYPTED_CLIENT_HELLO = 'ECHConfigList',
    ),

    ServerExtensionList = Wrap(Bounded(16, Sequence('ServerExtension'))),

    Ticket = Struct(
        ticket_lifetime = Uint(32),
        ticket_age_add  = Uint(32),
        ticket_nonce    = Bounded(8, Raw),
        ticket          = Bounded(16, Raw),
        extensions      = 'ServerExtensionList',
    ),

    Handshake = Select('HandshakeType', 24)(
        CLIENT_HELLO = Struct(
            legacy_version     = 'Version', # FIXME Version.TLS_1_2.as_const(),
            client_random      = FixRaw(32),
            session_id         = Bounded(8, Raw),
            ciphers            = Bounded(16, Sequence('CipherSuite')),
            legacy_compression = Bounded(8, Sequence(Uint(8))), # FIXME .const([0]),
            extensions         = Bounded(16, Sequence('ClientExtension')),
        ),
        SERVER_HELLO = Struct(
            legacy_version     = 'Version', # FIXME .TLS_1_2.as_const(),
            server_random      = FixRaw(32),
            session_id         = Bounded(8, Raw),
            cipher_suite       = 'CipherSuite',
            legacy_compression = Uint(8), # FIXME .const(0),
            extensions         = 'ServerExtensionList',
        ),
        ENCRYPTED_EXTENSIONS = 'ServerExtensionList',
        CERTIFICATE = Struct(
            certificate_request_context = Bounded(8, Raw),
            certificate_list = Bounded(24, Sequence(Struct(
                cert_data  = Bounded(24, Raw),
                extensions = Bounded(16, Raw),
            ))),
        ),
        CERTIFICATE_VERIFY = Struct(
            algorithm = 'SignatureScheme',
            signature = Bounded(16, Raw),
        ),
        FINISHED = Raw,
        NEW_SESSION_TICKET = 'Ticket',
    ),

    Alert = Struct(
        level       = 'AlertLevel',
        description = 'AlertDescription',
    ),

    RecordHeader = Struct(
        typ  = 'ContentType',
        version = 'Version',
        size = Uint(16),
    ),

    Record = Struct(
        typ = 'ContentType',
        version = 'Version',
        payload = Bounded(16, Raw),
    ),

    CertSecrets = Struct(
        sig_alg = 'SignatureScheme',
        private_key = Bounded(32, Raw),
        cert_der = Bounded(32, Raw),
    ),

    EchSecrets = Struct(
        config = 'ECHConfigVariant',
        private_key = Bounded(32, Raw),
    ),

    ServerSecrets = Struct(
        cert = 'CertSecrets',
        eches = Bounded(32, Sequence('EchSecrets')),
    ),

    PyhpkeKeypair = Struct(
        private = Bounded(32, Raw),
        public = Bounded(32, Raw),
    ),

    TicketInfoStruct = Struct(
        ticket_id = Bounded(16, Raw),
        secret = Bounded(8, Raw),
        csuite = 'CipherSuite',
        modes = Bounded(8, Sequence('PskKeyExchangeMode')),
        mask = Uint(32),
        lifetime = Uint(32),
        creation = Uint(64),
    ),

    ServerTicketPlaintext = Struct(
        cipher_suite = 'CipherSuite',
        expiration = Uint(64),
        psk = Bounded(16, Raw),
    ),

    ServerTicketCiphertext = Struct(
        inner_ciphertext = Bounded(16, Raw),
        iv = Bounded(8, Raw),
    ),

    InnerPlaintextBase = Struct(
        payload = Raw,
        typ = 'ContentType',
        padding = Fill,
    ),

    RecordEntry = Struct(
        raw = Bounded(16, Raw),
        record = 'Record',
        from_client = Bool,
    ),

    ClientSecrets = Struct(
        psk = Bounded(8, Raw),
        kex_sks = Bounded(16, Sequence(Bounded(16, Raw))),
    ),

    Transcript = Struct(
        psk = Bounded(8, Raw),
        kex_secret = Bounded(8, Raw),
        records = Bounded(32, Sequence('RecordEntry')),
    ),

    #### XXX remove below TODO

    Happy = Wrap(Uint(32)),

    Day = NamedConst(8)(
        Monday = 1,
        Tuesday = 2,
    ),
    Month = NamedConst(16)(
        February = 2,
        May = 5,
    ),
    Uint8 = Uint(8),
    Uint24 = Uint(24),
    Raw8 = Bounded(8, Raw),
    Raw16 = Bounded(16, Raw),
    String8 = Bounded(8, String),
    String16 = Bounded(16, String),
    Shorts = Sequence(Uint(16)),
    ShortShorts = Bounded(8, Sequence(Uint(16))),
    B16S8 = Bounded(16, Sequence(Uint(8))),
    Person = Struct(
        name = 'String16',
        phone = Uint(16),
    ),
    Animal = Struct(
        name = Bounded(8, String),
        legs = Uint(8),
        nums = Bounded(8, Sequence(Uint(16))),
    ),
    InstrumentType = NamedConst(8)(
        Brass = 1,
        Woodwind = 2,
        Strings = 3,
    ),
    Instrument = Select('InstrumentType')(
        Brass = Struct(
            valves = 'Uint8',
            weight = Uint(16),
        ),
        Woodwind = Bounded(8, String),
    ),
)

def write_to(fname: str) -> None:
    with open(fname, 'w') as fout:
        fout.write("from tls_common import *")
        generate_specs(fout, **specs)
    print('specs written to', fname)

if __name__ == '__main__':
    write_to('tls13_spec.py')
