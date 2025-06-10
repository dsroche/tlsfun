"""Cryptographic algorithms and primitives used for TLS.

Includes ciphers, hashes, KDF, key exchange, and signatures,
as well as X509 certificate generation.

Most of these are actually implemented by the python cryptography library;
this module just provides the "glue code" to give a consistent interface
for how they are used in TLS.
"""
from typing import override, Protocol
from abc import ABC, abstractmethod, abstractproperty
from collections.abc import Iterable, Callable
from functools import cached_property
from dataclasses import dataclass, field
from datetime import timedelta, datetime
from collections import namedtuple
from random import Random
from secrets import SystemRandom

from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, SECP384R1, SECP521R1, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding as cryptopad
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import pyhpke

from util import kwdict
from tls_common import *
from tls13_spec import (
    CertSecrets,
    EchSecrets,
    ServerSecrets,
    NamedGroup,
    SignatureScheme,
    CipherSuite,
    HkdfLabel,
    HpkeKemId,
    HpkeKdfId,
    HpkeAeadId,
    PyhpkeKeypair,
    KeyConfig,
    Draft24ECHConfig,
    PskKeyExchangeMode,
)

_PycaXPublicKey = X25519PublicKey | X448PublicKey
_PycaXPrivateKey = X25519PrivateKey | X448PrivateKey
_PycaEdPublicKey = Ed25519PublicKey | Ed448PublicKey
_PycaSigPublicKey = _PycaEdPublicKey | EllipticCurvePublicKey | RSAPublicKey
_PycaEdPrivateKey = Ed25519PrivateKey | Ed448PrivateKey
_PycaSigPrivateKey = _PycaEdPrivateKey | EllipticCurvePrivateKey | RSAPrivateKey

class KexAlg(ABC):
    @abstractmethod
    def gen_private(self, rgen: Random) -> bytes: ...
    @abstractmethod
    def get_public(self, private: bytes) -> bytes: ...
    @abstractmethod
    def exchange(self, private: bytes, public: bytes) -> bytes: ...

@dataclass(frozen=True)
class _XKex(KexAlg):
    """Key exchange support in X* groups using python cryptography module."""
    _Private: type[_PycaXPrivateKey]
    _Public: type[_PycaXPublicKey]
    _genlen: int

    def _get_private(self, data: bytes) -> _PycaXPrivateKey:
        return self._Private.from_private_bytes(data)

    def _get_public(self, data: bytes) -> _PycaXPublicKey:
        return self._Public.from_public_bytes(data)

    @override
    def gen_private(self, rgen: Random) -> bytes:
        return self._get_private(rgen.randbytes(self._genlen)).private_bytes_raw()

    @override
    def get_public(self, private: bytes) -> bytes:
        return self._get_private(private).public_key().public_bytes_raw()

    @override
    def exchange(self, private: bytes, public: bytes) -> bytes:
        prikey = self._get_private(private)
        pubkey = self._get_public(public)
        match (prikey, pubkey):
            case (X25519PrivateKey(), X25519PublicKey()):
                return prikey.exchange(pubkey)
            case (X448PrivateKey(), X448PublicKey()):
                return prikey.exchange(pubkey)
        raise ValueError("incompatible key types for exchange {prikey} and {pubkey}")


def get_kex_alg(group: NamedGroup) -> KexAlg:
    """Given a NamedGroup, returns an object to do key exchange.
    The returned object kex will have:
        kex.gen_private(rgen) -> private
        kex.get_public(private) -> public
        kex.exchange(private, public) -> shared_secret
    """
    match group:
        case NamedGroup.X25519:
            return _XKex(X25519PrivateKey, X25519PublicKey, 32)
        case NamedGroup.X448:
            return _XKex(X448PrivateKey, X448PublicKey, 56)
        case _:
            raise ValueError(f"no implementation for key exchange in {group}")


DEFAULT_KEX_GROUPS: tuple[NamedGroup,...] = (
    NamedGroup.X25519,
    NamedGroup.SECP256R1,
    NamedGroup.X448,
    NamedGroup.SECP521R1,
    NamedGroup.SECP384R1,
    NamedGroup.FFDHE2048,
    NamedGroup.FFDHE3072,
    NamedGroup.FFDHE4096,
    NamedGroup.FFDHE6144,
    NamedGroup.FFDHE8192,
)

class SigAlg(ABC):
    @abstractmethod
    def gen_private(self, rgen: Random) -> bytes: ...
    @abstractmethod
    def get_public(self, privkey: bytes) -> bytes: ...
    @abstractmethod
    def sign(self, privkey: bytes, data: bytes) -> bytes: ...
    @abstractmethod
    def verify(self, pubkey: bytes, signature: bytes, data: bytes) -> bool: ...

class _PycaSig(SigAlg):
    @abstractmethod
    def _gen_private_pyca(self, rgen: Random) -> _PycaSigPrivateKey: ...

    @override
    def gen_private(self, rgen: Random) -> bytes:
        return pyca_to_bytes(self._gen_private_pyca(rgen))

    @override
    def get_public(self, privkey: bytes) -> bytes:
        return pyca_to_bytes(
            pyca_from_bytes_private(privkey).public_key())

    @abstractmethod
    def _sign_pyca(self, privkey: _PycaSigPrivateKey, data: bytes) -> bytes: ...

    @override
    def sign(self, privkey: bytes, data: bytes) -> bytes:
        return self._sign_pyca(pyca_from_bytes_private(privkey), data)

    @abstractmethod
    def _verify_pyca(self, pubkey: _PycaSigPublicKey, signature: bytes, data: bytes) -> None: ...

    @override
    def verify(self, pubkey: bytes, signature: bytes, data: bytes) -> bool:
        pk = pyca_from_bytes_public(pubkey)
        try:
            self._verify_pyca(pk, signature, data)
        except InvalidSignature:
            return False
        return True

@dataclass(frozen=True)
class _PycaECDSA(_PycaSig):
    curve: ec.EllipticCurve
    hash_alg: HashAlgorithm
    gen_bits: int
    sig_alg: ec.EllipticCurveSignatureAlgorithm = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'sig_alg', ECDSA(self.hash_alg, deterministic_signing=True))

    @override
    def _gen_private_pyca(self, rgen: Random) -> EllipticCurvePrivateKey:
        for _ in range(128):
            try:
                return ec.derive_private_key(rgen.randrange(2**self.gen_bits), self.curve)
            except ValueError:
                continue # try again
        raise ValueError("failed EC private key generation 128 times")

    @override
    def _sign_pyca(self, privkey: _PycaSigPrivateKey, data: bytes) -> bytes:
        if isinstance(privkey, EllipticCurvePrivateKey):
            return privkey.sign(data, self.sig_alg)
        raise ValueError(f"invalid private key for PycaECDSA: {privkey}")

    @override
    def _verify_pyca(self, pubkey: _PycaSigPublicKey, signature: bytes, data: bytes) -> None:
        if isinstance(pubkey, EllipticCurvePublicKey):
            return pubkey.verify(signature, data, self.sig_alg)
        raise ValueError(f"invalid public key for PycaECDSA: {pubkey}")

@dataclass(frozen=True)
class _PycaEdDSA(_PycaSig):
    _KeyClass: type[_PycaEdPrivateKey]
    _keylen: int

    @override
    def _gen_private_pyca(self, rgen: Random) -> _PycaSigPrivateKey:
        # XXX rgen not actually used
        return self._KeyClass.generate()

    @override
    def _sign_pyca(self, privkey: _PycaSigPrivateKey, data: bytes) -> bytes:
        if isinstance(privkey, _PycaEdPrivateKey):
            return privkey.sign(data)
        raise ValueError(f"invalid private key for PycaEdDSA: {privkey}")

    @override
    def _verify_pyca(self, pubkey: _PycaSigPublicKey, signature: bytes, data: bytes) -> None:
        if isinstance(pubkey, _PycaEdPublicKey):
            return pubkey.verify(signature, data)
        raise ValueError(f"invalid public key for PycaEdDSA: {pubkey}")

def _pss_padder(hash_alg: HashAlgorithm) -> cryptopad.AsymmetricPadding:
    return cryptopad.PSS(
        mgf         = cryptopad.MGF1(hash_alg),
        salt_length = cryptopad.PSS.DIGEST_LENGTH,
    )

def _pkcs_padder(hash_alg: HashAlgorithm) -> cryptopad.AsymmetricPadding:
    return cryptopad.PKCS1v15()

@dataclass(frozen=True)
class _PycaRSA(_PycaSig):
    padder: Callable[[HashAlgorithm], cryptopad.AsymmetricPadding]
    hash_alg: HashAlgorithm

    @property
    def padding(self) -> cryptopad.AsymmetricPadding:
        return self.padder(self.hash_alg)

    @override
    def _gen_private_pyca(self, rgen: Random) -> rsa.RSAPrivateKey:
        # XXX doesn't actually use rgen!!
        return rsa.generate_private_key(
            public_exponent = 65537,
            key_size        = 4096,
        )

    @override
    def _sign_pyca(self, privkey: _PycaSigPrivateKey, data: bytes) -> bytes:
        if isinstance(privkey, rsa.RSAPrivateKey):
            return privkey.sign(data, self.padding, self.hash_alg)
        raise ValueError(f"invalid private key for RSA: {privkey}")

    @override
    def _verify_pyca(self, pubkey: _PycaSigPublicKey, signature: bytes, data: bytes) -> None:
        if isinstance(pubkey, rsa.RSAPublicKey):
            return pubkey.verify(signature, data, self.padding, self.hash_alg)
        raise ValueError(f"invalid public key for PycaEdDSA: {pubkey}")


def pyca_to_bytes(key: _PycaSigPrivateKey|_PycaSigPublicKey) -> bytes:
    if isinstance(key, _PycaSigPrivateKey):
        return key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    else:
        return key.public_bytes(Encoding.DER,
                                PublicFormat.SubjectPublicKeyInfo)

def pyca_from_bytes_public(raw: bytes) -> _PycaSigPublicKey:
    pubkey = load_der_public_key(raw)
    if isinstance(pubkey, _PycaSigPublicKey):
        return pubkey
    raise ValueError("unrecognized key type:", pubkey)

def pyca_from_bytes_private(raw: bytes) -> _PycaSigPrivateKey:
    prikey = load_pem_private_key(raw, None)
    if isinstance(prikey, _PycaSigPrivateKey):
        return prikey
    raise ValueError("unrecognized key type:", prikey)

def extract_x509_pubkey(raw_cert: bytes) -> bytes:
    """Given a DER-encoded certificate, extracts bytes of the public key."""
    pubkey = x509.load_der_x509_certificate(raw_cert).public_key()
    if isinstance(pubkey, _PycaSigPublicKey):
        return pyca_to_bytes(pubkey)
    raise ValueError("unrecognized key type in x509 cert:", pubkey)

def get_sig_alg(scheme: SignatureScheme) -> SigAlg:
    """Given a SignatureScheme, returns an object to do digital signature verification.
    The returned object sigscheme will have:
        sigscheme.gen_private() -> privkey
        sigscheme.get_public(privkey) -> pubkey
        sigscheme.sign(privkey, data) -> bytes
        sigscheme.verify(pubkey, signature, data) -> bool
            (*** note we are using a return value here instead of exceptions
                 as is more typical in secure implementations!)
    """
    match scheme:
        case SignatureScheme.ECDSA_SECP256R1_SHA256:
            return _PycaECDSA(SECP256R1(), SHA256(), 256)
        case SignatureScheme.ECDSA_SECP384R1_SHA384:
            return _PycaECDSA(SECP384R1(), SHA384(), 384)
        case SignatureScheme.ECDSA_SECP521R1_SHA512:
            return _PycaECDSA(SECP521R1(), SHA512(), 512)

        case SignatureScheme.ED25519:
            return _PycaEdDSA(Ed25519PrivateKey, 32)
        case SignatureScheme.ED448:
            return _PycaEdDSA(Ed448PrivateKey, 57)

        case (SignatureScheme.RSA_PSS_RSAE_SHA256 | SignatureScheme.RSA_PSS_PSS_SHA256):
            return _PycaRSA(_pss_padder, SHA256())
        case (SignatureScheme.RSA_PSS_RSAE_SHA384 | SignatureScheme.RSA_PSS_PSS_SHA384()):
            return _PycaRSA(_pss_padder, SHA384())
        case (SignatureScheme.RSA_PSS_RSAE_SHA512 | SignatureScheme.RSA_PSS_PSS_SHA512()):
            return _PycaRSA(_pss_padder, SHA512())

        case SignatureScheme.RSA_PKCS1_SHA256:
            return _PycaRSA(_pkcs_padder, SHA256())
        case SignatureScheme.RSA_PKCS1_SHA384:
            return _PycaRSA(_pkcs_padder, SHA384())
        case SignatureScheme.RSA_PKCS1_SHA512:
            return _PycaRSA(_pkcs_padder, SHA512())

        case _:
            raise ValueError(f"no implementation for signatures in {scheme}")


DEFAULT_SIGNATURE_SCHEMES: tuple[SignatureScheme,...] = (
	SignatureScheme.ECDSA_SECP256R1_SHA256,
	SignatureScheme.ECDSA_SECP384R1_SHA384,
	SignatureScheme.ECDSA_SECP521R1_SHA512,
	SignatureScheme.ED25519,
	SignatureScheme.ED448,
	SignatureScheme.RSA_PSS_PSS_SHA256,
	SignatureScheme.RSA_PSS_PSS_SHA384,
	SignatureScheme.RSA_PSS_PSS_SHA512,
	SignatureScheme.RSA_PSS_RSAE_SHA256,
	SignatureScheme.RSA_PSS_RSAE_SHA384,
	SignatureScheme.RSA_PSS_RSAE_SHA512,
	SignatureScheme.RSA_PKCS1_SHA256,
	SignatureScheme.RSA_PKCS1_SHA384,
	SignatureScheme.RSA_PKCS1_SHA512,
)

class HashObject(ABC):
    @abstractmethod
    def update(self, msg: bytes) -> None: ...

    @abstractmethod
    def digest(self) -> bytes: ...

class Hasher(ABC):
    @abstractproperty
    def digest_size(self) -> int: ...

    @abstractmethod
    def hasher(self, msg: bytes = b'') -> HashObject: ...

    @abstractmethod
    def hmac_hash(self, key: bytes, msg: bytes) -> bytes: ...

    @abstractmethod
    def hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes: ...

@dataclass
class _PycaHasher(HashObject):
    hash_obj: Hash

    def __init__(self, hash_obj: Hash, msg: bytes) -> None:
        self.hash_obj = hash_obj
        if msg:
            self.update(msg)

    @override
    def update(self, msg: bytes) -> None:
        self.hash_obj.update(msg)

    @override
    def digest(self) -> bytes:
        return self.hash_obj.copy().finalize()

@dataclass(frozen=True)
class _PycaHash(Hasher):
    hash_alg: HashAlgorithm

    @override
    @property
    def digest_size(self) -> int:
        return self.hash_alg.digest_size

    @override
    def hasher(self, msg: bytes = b'') -> HashObject:
        return _PycaHasher(Hash(self.hash_alg), msg)

    @override
    def hmac_hash(self, key: bytes, msg: bytes) -> bytes:
        # rfc2104
        h = HMAC(key=key, algorithm=self.hash_alg)
        h.update(msg)
        return h.finalize()

    @override
    def hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        # rfc5869
        h = HKDFExpand(algorithm=self.hash_alg, length=length, info=info)
        return h.derive(key_material=prk)


def get_hash_alg(cipher_suite: CipherSuite) -> Hasher:
    """Given a CipherSuite, returns an object to do hashing.
    """
    match cipher_suite:
        case (CipherSuite.TLS_AES_128_GCM_SHA256
              | CipherSuite.TLS_CHACHA20_POLY1305_SHA256
              | CipherSuite.TLS_AES_128_CCM_SHA256
              | CipherSuite.TLS_AES_128_CCM_8_SHA256):
            return _PycaHash(SHA256())
        case CipherSuite.TLS_AES_256_GCM_SHA384:
            return _PycaHash(SHA384())
    raise ValueError(f"no hash implementation for cipher suite {cipher_suite}")


class AeadCipher(ABC):
    @abstractproperty
    def key_length(self) -> int: ...

    @abstractproperty
    def iv_length(self) -> int: ...

    @abstractmethod
    def ctext_size(self, ptext_size: int) -> int: ...

    @abstractmethod
    def encrypt(self, key: bytes, iv: bytes, ptext: bytes, adata: bytes) -> bytes: ...

    @abstractmethod
    def decrypt(self, key: bytes, iv: bytes, ctext: bytes, adata: bytes) -> bytes: ...

class _PycaCipher(Protocol):
    def encrypt(self, iv: bytes, ptext: bytes, adata: bytes) -> bytes: ...
    def decrypt(self, iv: bytes, ctext: bytes, adata: bytes) -> bytes: ...


@dataclass(frozen=True)
class _PycaAead(AeadCipher):
    cipher_alg: Callable[[bytes], _PycaCipher]
    key_len: int
    iv_len: int = 12
    tag_len: int = 16

    @override
    @property
    def key_length(self) -> int:
        return self.key_len

    @override
    @property
    def iv_length(self) -> int:
        return self.iv_len

    @override
    def ctext_size(self, ptext_size: int) -> int:
        return ptext_size + self.tag_len

    @override
    def encrypt(self, key: bytes, iv: bytes, ptext: bytes, adata: bytes) -> bytes:
        return self.cipher_alg(key).encrypt(iv, ptext, adata)

    @override
    def decrypt(self, key: bytes, iv: bytes, ctext: bytes, adata: bytes) -> bytes:
        return self.cipher_alg(key).decrypt(iv, ctext, adata)


def get_cipher_alg(cipher_suite: CipherSuite) -> AeadCipher:
    """Given a CipherSuite, returns an object to do encryption.
    The returned object cipher will have the following:
    (All values are bytes, with sizes as specified in [] when relevant.)
    """
    match cipher_suite:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
            return _PycaAead(AESGCM, 16)
        case CipherSuite.TLS_AES_256_GCM_SHA384:
            return _PycaAead(AESGCM, 32)
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return _PycaAead(ChaCha20Poly1305, 32)
        case CipherSuite.TLS_AES_128_CCM_SHA256:
            return _PycaAead(AESCCM, 16)
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
            return _PycaAead(AESCCM, 16, tag_len=8)
    raise ValueError(f"no cipher implementation for cipher suite {cipher_suite}")


DEFAULT_CIPHER_SUITES: tuple[CipherSuite, ...] = (
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.LEGACY_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
)


class KeyEncaps(ABC):
    @abstractmethod
    def gen_private(self, rgen: Random) -> bytes: ...

    @abstractmethod
    def get_public(self, private: bytes) -> bytes: ...

def _get_pyhpke_cs(
    kem_id: pyhpke.KEMId = pyhpke.KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id: pyhpke.KDFId = pyhpke.KDFId.HKDF_SHA256,
    aead_id: pyhpke.AEADId = pyhpke.AEADId.CHACHA20_POLY1305,
) -> pyhpke.CipherSuite:
    return pyhpke.CipherSuite.new(kem_id, kdf_id, aead_id)

class _Pyhpke_Kem(KeyEncaps):
    def __init__(self, kem_id: pyhpke.KEMId):
        self._kem = _get_pyhpke_cs(kem_id=kem_id).kem

    @override
    def gen_private(self, rgen: Random) -> bytes:
        keypair = self._kem.derive_key_pair(rgen.randbytes(64))
        return PyhpkeKeypair.create(
            private = keypair.private_key.to_private_bytes(),
            public = keypair.public_key.to_public_bytes(),
        ).pack()

    @override
    def get_public(self, private: bytes) -> bytes:
        return PyhpkeKeypair.unpack(private).public

def get_kem_alg(kem_id: HpkeKemId) -> KeyEncaps:
    """Given a kem_id, returns an object to do key encapsulation.
    """
    return _Pyhpke_Kem(pyhpke.KEMId(kem_id.value))

DEFAULT_KEM = HpkeKemId.DHKEM_X25519_HKDF_SHA256

DEFAULT_HPKE_CSUITES: tuple[tuple[HpkeKdfId,HpkeAeadId],...] = (
    (HpkeKdfId.HKDF_SHA256, HpkeAeadId.AES_256_GCM),
    (HpkeKdfId.HKDF_SHA256, HpkeAeadId.CHACHA20_POLY1305),
)

DEFAULT_KEX_MODES: tuple[PskKeyExchangeMode,...] = (
    PskKeyExchangeMode.PSK_DHE_KE,
)

@dataclass
class StreamCipher:
    cipher: AeadCipher
    hash_alg: Hasher
    secret: bytes
    counter: int = 0

    @cached_property
    def key(self) -> bytes:
        # rfc8446, sect 7.3
        return hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = self.secret,
            label    = b'key',
            cont     = b'',
            length   = self.cipher.key_length,
        )

    @cached_property
    def iv(self) -> bytes:
        # rfc8446, sect 7.3
        return hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = self.secret,
            label    = b'iv',
            cont     = b'',
            length   = self.cipher.iv_length,
        )

    def __post_init__(self) -> None:
        logger.info(f'started StreamCipher with key {self.key.hex()} and iv {self.iv.hex()}')

    def _next_nonce(self) -> bytes:
        nonce = bytes(a ^ b for a,b in
                      zip(self.iv, self.counter.to_bytes(len(self.iv))))
        self.counter += 1
        return nonce

    def encrypt(self, ptext: bytes, adata: bytes) -> bytes:
        assert self.key is not None, "need to rekey before encrypting"
        return self.cipher.encrypt(
            key   = self.key,
            iv    = self._next_nonce(),
            ptext = ptext,
            adata = adata,
            )

    def decrypt(self, ctext: bytes, adata: bytes) -> bytes:
        assert self.key is not None, "need to rekey before decrypting"
        return self.cipher.decrypt(
            key   = self.key,
            iv    = self._next_nonce(),
            ctext = ctext,
            adata = adata,
            )


def hkdf_extract(hash_alg: Hasher, salt: bytes, ikm: bytes) -> bytes:
    # rfc5869
    return hash_alg.hmac_hash(key=salt, msg=ikm)

def hkdf_expand_label(hash_alg: Hasher, secret: bytes, label: bytes, cont: bytes, length: int) -> bytes:
    # rfc8446 sect 7.1
    info = HkdfLabel.create(
        length = length,
        label   = b'tls13 ' + label,
        context = cont,
    ).pack()
    return hash_alg.hkdf_expand(prk=secret, info=info, length=length)

def derive_secret(hash_alg: Hasher, secret: bytes, label: bytes, msg_digest: bytes) -> bytes:
    # rfc8446 sect 7.1
    return hkdf_expand_label(hash_alg, secret=secret, label=label,
                             cont=msg_digest, length=hash_alg.digest_size)


def gen_cert(name: str, sig_alg: SignatureScheme, rgen: Random) -> CertSecrets:
    """Generates a new self-signed X509 certificate.

    A fresh signature keypair is generated and the private key
    is returned in a bytes encoding.

    The cert is valid for 10 years.

    Returns a CertSecrets tuple."""
    sigscheme = get_sig_alg(sig_alg)
    private_key = sigscheme.gen_private(rgen)
    # https://github.com/pyca/cryptography/blob/main/src/cryptography/x509/base.py#L847-L848
    serialno = rgen.randrange(2**(20*8-1))
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .not_valid_before(datetime(year=2025,month=1,day=1))
        .not_valid_after(datetime(year=2035,month=1,day=1))
        .serial_number(serialno)
        .public_key(pyca_from_bytes_public(sigscheme.get_public(private_key)))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
        .sign(private_key=pyca_from_bytes_private(private_key), algorithm=SHA256()))
    return CertSecrets.create(
        sig_alg = sig_alg.uncreate(),
        private_key = private_key,
        cert_der = cert.public_bytes(Encoding.DER),
    )

def gen_ech_config(
    public_name: str,
    config_id: int,
    maximum_name_length: int,
    kem_id: HpkeKemId,
    cipher_suites: Iterable[tuple[HpkeKdfId,HpkeAeadId]],
    rgen: Random,
) -> EchSecrets:
    """Generates an ECHConfig struct and corresponding private key."""
    kem = get_kem_alg(kem_id)
    seckey = kem.gen_private(rgen)
    pubkey = kem.get_public(seckey)
    return EchSecrets.create(
        config = Draft24ECHConfig.create(
            key_config = (
                config_id,
                kem_id,
                pubkey,
                cipher_suites,
            ),
            maximum_name_length = maximum_name_length,
            public_name = public_name,
            extensions = [],
        ),
        private_key = seckey,
    )

def gen_server_secrets(
    name: str ='localhost',
    sig_alg: SignatureScheme = DEFAULT_SIGNATURE_SCHEMES[0],
    config_id: int|None = None, # default, choose randomly
    maximum_name_length: int = 128,
    kem_id: HpkeKemId = DEFAULT_KEM,
    cipher_suites: Iterable[tuple[HpkeKdfId,HpkeAeadId]] = DEFAULT_HPKE_CSUITES,
    rgen: Random|None = None, # default, SystemRandom
) -> ServerSecrets:
    """Generates a fresh certificate and ECH config."""
    if rgen is None:
        rgen = SystemRandom()
    if config_id is None:
        config_id = rgen.randrange(2**8)

    return ServerSecrets.create(
        cert = gen_cert(name, sig_alg, rgen).uncreate(),
        eches = [gen_ech_config(name, config_id, maximum_name_length, kem_id, cipher_suites, rgen).uncreate()],
    )
