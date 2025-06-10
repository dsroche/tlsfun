"""Key derivation and key schedule logic for TLS 1.3

Includes code for pre-shared keys (i.e. tickets)."""

import time
import json
import os
from dataclasses import dataclass, field
from collections.abc import Iterable
from functools import cached_property

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from util import b64enc, b64dec, pformat
from spec import UnpackError
from tls_common import *
from tls13_spec import (
    Handshake,
    ExtensionTypes,
    HandshakeTypes,
    PskBinders,
    CipherSuite,
    PskKeyExchangeMode,
    Ticket,
    TicketInfoStruct,
    ClientExtension,
    PreSharedKeyClientExtension,
    ClientHelloHandshake,
    PskIdentity,
    PskBinders,
    ServerTicketPlaintext,
    ServerTicketCiphertext,
    ClientExtensionVariant,
    HandshakeVariant,
)
from tls_crypto import (
    get_hash_alg,
    StreamCipher,
    hkdf_extract,
    hkdf_expand_label,
    derive_secret,
    Hasher,
    DEFAULT_KEX_MODES,
)


@dataclass(frozen=True)
class TicketInfo(TicketInfoStruct):
    def add_psk_ext(self, chello: ClientHelloHandshake, send_time: float|None = None) -> ClientHelloHandshake:
        """Returns a new ClientHello Hansshake object with the PSK extension filled in."""
        extensions: list[ClientExtensionVariant] = list(chello.data.extensions.uncreate())
        if any(ext.typ == ExtensionTypes.PRE_SHARED_KEY for ext in extensions):
            raise ValueError(f"client hello should not contain PSK extension yet")

        # compute values for dummy psk extension
        if send_time is None:
            send_time = time.time()
        oage = (round((send_time - self.creation) * 1000) + self.mask) % 2**32
        dummy_binder = b'\xdd' * get_hash_alg(self.csuite).digest_size

        # construct extension with dummy binder
        dummy_psk_ext = PreSharedKeyClientExtension.create(
            identities = [(self.ticket_id, oage)],
            binders = [dummy_binder],
        )

        # add dummy extension to chello
        dummy_chello = chello.replace(extensions = extensions + [dummy_psk_ext])

        # compute actual binder key and psk extension
        actual_binder = self.get_binder_key(dummy_chello)
        actual_psk_ext = dummy_psk_ext.replace(binders = [actual_binder])
        actual_chello = chello.replace(extensions = extensions + [actual_psk_ext])

        logger.info(f'inserting psk with id {self.ticket_id[:12].hex()}... and  binder {actual_binder.hex()} into client hello')
        return actual_chello

    def get_binder_key(self, chello: ClientHelloHandshake, prefix:Iterable[tuple[HandshakeVariant,bool]]=()) -> bytes:
        """Computes the binder key for this ticket within the given (unpacked) client hello.

        prefix is (optionally) a transcript prefix, e.g. from a hello retry.
        """

        # find the index
        for ext in chello.data.extensions.uncreate():
            match ext:
                case PreSharedKeyClientExtension() as psk_ext:
                    break
        else:
            raise TlsError("no PSK extension found in ClientHello")

        for index, ident in enumerate(psk_ext.data.identities):
            if ident.identity == self.ticket_id:
                break
        else:
            raise TlsError(f"ticket {pformat(self.ticket_id)} not found in given PSK extension; got {[pformat(ident.identity) for ident in psk_ext.data.identities]}")

        return calc_binder_key(chello, index, self.secret, self.csuite, prefix)

HSTLookup = tuple[HandshakeTypes,bool] | HandshakeTypes | int

class HandshakeTranscript:
    def __init__(self) -> None:
        self._hash_alg: Hasher|None = None
        self._backlog: list[tuple[HandshakeVariant,bool]] = []

    @property
    def hash_alg(self) -> Hasher:
        assert self._hash_alg is not None
        return self._hash_alg

    @hash_alg.setter
    def hash_alg(self, ha: Hasher) -> None:
        assert self._hash_alg is None
        self._hash_alg = ha
        self._running = self._hash_alg.hasher()
        self._history: list[bytes] = [self._running.digest()]
        self._lookup: dict[tuple[HandshakeTypes, bool], bytes] = {}
        for hs, from_client in self._backlog:
            self.add(hs, from_client)
        del self._backlog

    def add_partial(self, data: bytes) -> bytes:
        self._running.update(data)
        return self._running.digest()

    def add(self, hs: HandshakeVariant, from_client: bool) -> None:
        if self._hash_alg is None:
            self._backlog.append((hs, from_client))
        else:
            current = self.add_partial(hs.pack())
            self._lookup[hs.typ, from_client] = current
            self._history.append(current)

    def __getitem__(self, key: HSTLookup) -> bytes:
        match key:
            case tuple():
                return self._lookup[key]
            case HandshakeTypes():
                return self._lookup[key, False]
            case int():
                return self._history[key]

class KeyCalcMissing(KeyError):
    def __init__(self, member_name: str) -> None:
        super().__init__(f"Need to set field '{member_name}' to compute this value")

@dataclass
class KeyCalc:
    # rfc8446#section-7.1

    hs_trans: HandshakeTranscript
    ticket_counter: int = 0
    _cipher_suite: CipherSuite|None = None
    _secrets: dict[str, bytes] = field(default_factory=dict)

    @property
    def cipher_suite(self) -> CipherSuite:
        if self._cipher_suite is None:
            raise KeyCalcMissing("cipher_suite")
        return self._cipher_suite

    @cipher_suite.setter
    def cipher_suite(self, cs: CipherSuite) -> None:
        assert self._cipher_suite is None
        self._cipher_suite = cs
        self.hs_trans.hash_alg = self.hash_alg

    def _get_secret(self, name: str) -> bytes:
        try:
            return self._secrets[name]
        except KeyError:
            raise KeyCalcMissing(name) from None

    def _set_secret(self, name: str, value: bytes) -> None:
        assert name not in self._secrets, f"value of {name} is already set"
        self._secrets[name] = value

    @property
    def psk(self) -> bytes:
        return self._get_secret('psk')

    def set_psk(self, value: bytes|None) -> None:
        self._set_secret('psk', self.zero if value is None else value)

    @property
    def kex_secret(self) -> bytes:
        return self._get_secret('kex_secret')

    def set_kex_secret(self, value: bytes|None) -> None:
        self._set_secret('kex_secret', self.zero if value is None else value)

    @cached_property
    def hash_alg(self) -> Hasher:
        return get_hash_alg(self.cipher_suite)

    @cached_property
    def zero(self) -> bytes:
        return b'\x00' * self.hash_alg.digest_size

    @cached_property
    def early_secret(self) -> bytes:
        return hkdf_extract(self.hash_alg, salt=self.zero, ikm=self.psk)

    @cached_property
    def handshake_secret(self) -> bytes:
        return hkdf_extract(
            hash_alg = self.hash_alg,
            salt = self.derived0,
            ikm = self.kex_secret,
        )

    @cached_property
    def master_secret(self) -> bytes:
        return hkdf_extract(
            hash_alg = self.hash_alg,
            salt = self.derived1,
            ikm = self.zero,
        )

    @cached_property
    def server_cv_message(self) -> bytes:
        # rfc8446#section-4.4.3
        return b''.join([
            b'\x20'*64,
            b'TLS 1.3, server CertificateVerify',
            b'\x00',
            self.hs_trans[HandshakeTypes.CERTIFICATE, False],
        ])

    @cached_property
    def server_finished_verify(self) -> bytes:
        base_key = self.server_handshake_traffic_secret
        if self.psk is self.zero:
            thash = self.hs_trans[
                HandshakeTypes.CERTIFICATE_VERIFY, False]
        else:
            thash = self.hs_trans[
                HandshakeTypes.ENCRYPTED_EXTENSIONS, False]
        return self.get_verify_data(base_key, thash)

    @cached_property
    def client_finished_verify(self) -> bytes:
        base_key = self.client_handshake_traffic_secret
        thash = self.hs_trans[HandshakeTypes.FINISHED, False]
        return self.get_verify_data(base_key, thash)

    def _derive(self, secret: bytes, text: bytes, lookup: HSTLookup) -> bytes:
        return derive_secret(
            hash_alg   = self.hash_alg,
            secret     = secret,
            label      = text,
            msg_digest = self.hs_trans[lookup],
        )

    @cached_property
    def binder_key(self) -> bytes:
        return self._derive(self.early_secret, b'res binder', 0)

    @cached_property
    def client_early_traffic_secret(self) -> bytes:
        return self._derive(self.early_secret, b'c e traffic', HandshakeTypes.CLIENT_HELLO)

    @cached_property
    def derived0(self) -> bytes:
        return self._derive(self.early_secret, b'derived', 0)

    @cached_property
    def client_handshake_traffic_secret(self) -> bytes:
        return self._derive(self.handshake_secret, b'c hs traffic', HandshakeTypes.SERVER_HELLO)

    @cached_property
    def server_handshake_traffic_secret(self) -> bytes:
        return self._derive(self.handshake_secret, b's hs traffic', HandshakeTypes.SERVER_HELLO)

    @cached_property
    def derived1(self) -> bytes:
        return self._derive(self.handshake_secret, b'derived', 0)

    @cached_property
    def client_application_traffic_secret(self) -> bytes:
        return self._derive(self.master_secret, b'c ap traffic', (HandshakeTypes.FINISHED, False))

    @cached_property
    def server_application_traffic_secret(self) -> bytes:
        return self._derive(self.master_secret, b's ap traffic', (HandshakeTypes.FINISHED, False))

    @cached_property
    def resumption_master_secret(self) -> bytes:
        return self._derive(self.master_secret, b'res master', (HandshakeTypes.FINISHED, True))

    def ticket_secret(self, ticket_nonce: bytes) -> bytes:
        # rfc8446#section-4.6.1
        return hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = self.resumption_master_secret,
            label    = b'resumption',
            cont     = ticket_nonce,
            length   = self.hash_alg.digest_size,
        )

    def ticket_info(self, ticket: Ticket, modes:Iterable[PskKeyExchangeMode]=DEFAULT_KEX_MODES, creation: int|None = None) -> TicketInfo:
        # rfc8446#section-4.6.1
        return TicketInfo.create(
            ticket_id = ticket.ticket,
            secret    = self.ticket_secret(ticket.ticket_nonce),
            csuite    = self.cipher_suite,
            modes     = modes,
            mask      = ticket.ticket_age_add,
            lifetime  = ticket.ticket_lifetime,
            creation  = (round(time.time()) if creation is None else creation),
        )

    def get_verify_data(self, base_key: bytes, transcript_hash: bytes) -> bytes:
        # rfc8446#section-4.4
        finished_key = hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = base_key,
            label    = b'finished',
            cont     = b'',
            length   = self.hash_alg.digest_size,
        )
        return self.hash_alg.hmac_hash(key=finished_key, msg=transcript_hash)


class ServerTicketer:
    """Stores server-side data needed to issue and redeem resumption tickets.

    This is implemented using a (fresh) symmetric encryption key.
    Each ticket value is an encryption of the resumption secret and cipher suite.
    """

    _AEAD = ChaCha20Poly1305
    _NONCE_LENGTH = 12
    _GRACE = 60*10 # grace period (in seconds) for ticket age checks

    def __init__(self) -> None:
        self._cipher = self._AEAD(self._AEAD.generate_key())
        logger.info("Generated a random key for symmetric encryption of tickets.")
        self._used = set[bytes]()

    def _get_current_time(self, hint: float|None) -> float:
        return time.time() if hint is None else hint

    def gen_ticket(self, secret: bytes, nonce: bytes, lifetime: int, csuite: CipherSuite, current_time: float|None=None) -> Ticket:
        """Generates a fresh Ticket struct to send to the client.

        secret: ticket resumption PSK
        nonce: ticket_nonce value (unique within session, used to compute secret)
        lifetime: seconds until ticket expires
        csuite: cipher suite used in this session
        current_time: current time in seconds (None to use current system time)
        """
        current_time = self._get_current_time(current_time)
        expiration = current_time + lifetime

        ptext = ServerTicketPlaintext.create(
            cipher_suite = csuite,
            expiration = round(expiration),
            psk = secret,
        )

        iv = os.urandom(self._NONCE_LENGTH)
        inner_ctext = self._cipher.encrypt(iv, ptext.pack(), iv)

        ctext = ServerTicketCiphertext.create(
            inner_ciphertext = inner_ctext,
            iv = iv,
        )

        return Ticket.create(
            ticket_lifetime = lifetime,
            ticket_age_add = int.from_bytes(os.urandom(4)),
            ticket_nonce = nonce,
            ticket = ctext.pack(),
            extensions = [],
        )

    def use_ticket(self, psk_identity: PskIdentity, csuite: CipherSuite, current_time: float|None=None) -> bytes|None:
        current_time = self._get_current_time(current_time)

        ctext = psk_identity.identity
        # NB psk_identity.obfuscated_ticket_age is ignored

        if ctext in self._used:
            logger.info('INVALID TICKET: already used')
            return None

        try:
            outer = ServerTicketCiphertext.unpack(ctext)
        except UnpackError:
            logger.info('INVALID TICKET: unable to parse client ticket ctext')
            return None

        try:
            inner = ServerTicketPlaintext.unpack(
                self._cipher.decrypt(outer.iv, outer.inner_ciphertext, outer.iv))
        except InvalidTag:
            logger.info('INVALID TICKET: unable to decrypt client ticket')
            return None
        except ValueError:
            logger.info('INVALID TICKET: unable to parse client inner ticket')
            return None

        if inner.cipher_suite != csuite:
            logger.info('INVALID TICKET: cipher suite mismatch')
            return None

        if current_time > inner.expiration + self._GRACE:
            logger.info('INVALID TICKET: past expiration date')
            return None

        logger.info(f'received valid ticket {pformat(ctext)}; marking as used')
        self._used.add(ctext)
        return inner.psk


def calc_binder_key(chello: ClientHelloHandshake, index: int, secret: bytes, csuite: CipherSuite, prefix: Iterable[tuple[HandshakeVariant,bool]] = ()) -> bytes:
    """Computes the binder key at given index within given (unpacked) client hello.

    The actual binder keys must be filled in (and with the proper lengths)
    but will be ignored.

    secret is the actual PSK secret, and csuite is the cipher suite to use
    (should be associated to the PSK).

    Prefix is optionally a transcript prefix before the client hello,
    such as from a hello retry request.
    """
    hst = HandshakeTranscript()
    kc = KeyCalc(hst)
    kc.cipher_suite = csuite
    for hs, from_client in prefix:
        hst.add(hs, from_client)

    exts = list(chello.data.extensions)
    if not exts:
        raise TlsError("Missing PSK extension in client hello")

    match exts[-1].variant:
        case PreSharedKeyClientExtension() as pske:
            pass
        case _:
            raise TlsError("Last extension in client hello should be PSK")

    if index >= len(pske.data.identities) or len(pske.data.binders.data) != len(pske.data.identities):
        raise TlsError("index out of bounds or mismatch in PSK extension")

    raw_hello = chello.pack()
    pbinds = pske.data.binders.pack()
    assert raw_hello.endswith(pbinds)

    digest = hst.add_partial(raw_hello[:-len(pbinds)])

    kc.set_psk(secret)
    binder = kc.get_verify_data(kc.binder_key, digest)

    if len(binder) != len(pske.data.binders.data[index]):
        raise TlsError("binder key in client hello has the wrong length")

    return binder
