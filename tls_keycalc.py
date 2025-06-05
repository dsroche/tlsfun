"""Key derivation and key schedule logic for TLS 1.3

Includes code for pre-shared keys (i.e. tickets)."""

import time
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from util import b64enc, b64dec
from tls_common import *
from tls13_spec import (
    Handshake,
    ExtensionType,
    HandshakeType,
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
)
from tls_crypto import (
    get_hash_alg,
    StreamCipher,
    hkdf_extract,
    hkdf_expand_label,
    derive_secret,
)


@dataclass(frozen=True)
class TicketInfo(TicketInfoStruct):
    def add_psk_ext(self, chello: ClientHelloHandshake, send_time: float|None = None) -> ClientHelloHandshake:
        """Returns a new ClientHello Hansshake object with the PSK extension filled in."""
        extensions: list[ClientExtension] = list(chello.data.extensions.uncreate())
        if any(ext.typ == ExtensionType.PRE_SHARED_KEY for ext in extensions):
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
        dummy_chello = chello.replace(extensions = extensions + [dummy_psk_ext.parent()])

        # compute actual binder key and psk extension
        actual_binder = self.get_binder_key(dummy_chello)
        actual_psk_ext = dummy_psk_ext.replace(binders = [actual_binder])
        actual_chello = chello.replace(extensions = extensions + [actual_psk_ext.parent()])

        logger.info(f'inserting psk with id {self.ticket_id[:12].hex()}... and  binder {actual_binder.hex()} into client hello')
        return actual_chello

    def get_binder_key(self, chello, prefix=b''):
        """Computes the binder key for this ticket within the given (unpacked) client hello.

        prefix is (optionally) a transcript prefix, e.g. from a hello retry.
        """

        # find the index
        try:
            psk_ext = next(filter(
                (lambda ext: ext.typ == ExtensionType.PRE_SHARED_KEY),
                chello.body.extensions))
            index = next(i for i,ident in enumerate(psk_ext.data.identities)
                         if ident.identity == self.ticket_id)
        except StopIteration:
            raise TlsError("this ticket id not found in given client hello") from None

        return calc_binder_key(chello, index, self._secret, self._csuite, prefix)


class HandshakeTranscript:
    def __init__(self):
        self._hash_alg = None
        self._backlog = []

    @property
    def hash_alg(self):
        return self._hash_alg

    @hash_alg.setter
    def hash_alg(self, ha):
        if self._hash_alg is not None:
            raise ValueError("hash_alg already set")
        self._hash_alg = ha
        self._running = self._hash_alg.hasher()
        self._history = [self._running.digest()]
        self._lookup = {}
        for item in self._backlog:
            self.add(*item)
        del self._backlog

    def add(self, typ, from_client, data):
        if self._hash_alg is None:
            self._backlog.append((typ, from_client, data))
        else:
            self._running.update(data)
            current = self._running.digest()
            self._lookup[typ, from_client] = current
            self._history.append(current)

    def __getitem__(self, key):
        match key:
            case (HandshakeType(), bool()):
                return self._lookup[key]
            case HandshakeType():
                return self._lookup[key, False]
            case int():
                return self._history[key]
            case _:
                raise KeyError("invalid key type; should be (typ,bool), typ, or int")


class KeyCalc:
    # rfc8446#section-7.1

    _DERIVATIONS = {
        'binder_key':
            ('early_secret', b'res binder', 0),
        'client_early_traffic_secret':
            ('early_secret', b'c e traffic', HandshakeType.CLIENT_HELLO),
        'derived0':
            ('early_secret', b'derived', 0),
        'client_handshake_traffic_secret':
            ('handshake_secret', b'c hs traffic', HandshakeType.SERVER_HELLO),
        'server_handshake_traffic_secret':
            ('handshake_secret', b's hs traffic', HandshakeType.SERVER_HELLO),
        'derived1':
            ('handshake_secret', b'derived', 0),
        'client_application_traffic_secret':
            ('master_secret', b'c ap traffic', (HandshakeType.FINISHED, False)),
        'server_application_traffic_secret':
            ('master_secret', b's ap traffic', (HandshakeType.FINISHED, False)),
        'resumption_master_secret':
            ('master_secret', b'res master', (HandshakeType.FINISHED, True)),
    }

    def __init__(self, hs_trans):
        super().__setattr__('_mem', {})
        self._hs_trans = hs_trans
        self._ticket_counter = [0]

    def ticket_secret(self, ticket_nonce):
        # rfc8446#section-4.6.1
        return hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = self.resumption_master_secret,
            label    = b'resumption',
            cont     = ticket_nonce,
            length   = self.hash_alg.digest_size,
        )

    def ticket_info(self, ticket, *args, **kwargs):
        # rfc8446#section-4.6.1
        return TicketInfo(
            ticket_id = ticket.ticket,
            secret    = self.ticket_secret(ticket.ticket_nonce),
            csuite    = self.cipher_suite,
            mask      = ticket.ticket_age_add,
            lifetime  = ticket.ticket_lifetime,
            *args, **kwargs)

    def get_verify_data(self, base_key, transcript_hash):
        # rfc8446#section-4.4
        finished_key = hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = base_key,
            label    = b'finished',
            cont     = b'',
            length   = self.hash_alg.digest_size,
        )
        return self.hash_alg.hmac_hash(key=finished_key, msg=transcript_hash)

    def __getattr__(self, name):
        try:
            return self._mem[name]
        except KeyError:
            pass
        match name:
            case 'zero':
                value = b'\x00' * self.hash_alg.digest_size
            case 'early_secret':
                value = hkdf_extract(self.hash_alg, salt=self.zero, ikm=self.psk)
            case 'handshake_secret':
                value = hkdf_extract(
                    hash_alg = self.hash_alg,
                    salt = self.derived0,
                    ikm = self.kex_secret,
                )
            case 'master_secret':
                value = hkdf_extract(
                    hash_alg = self.hash_alg,
                    salt = self.derived1,
                    ikm = self.zero,
                )
            case 'server_cv_message':
                # rfc8446#section-4.4.3
                return b''.join([
                    b'\x20'*64,
                    b'TLS 1.3, server CertificateVerify',
                    b'\x00',
                    self._hs_trans[HandshakeType.CERTIFICATE, False],
                ])
            case 'server_finished_verify':
                base_key = self.server_handshake_traffic_secret
                if self.psk is self.zero:
                    thash = self._hs_trans[
                        HandshakeType.CERTIFICATE_VERIFY, False]
                else:
                    thash = self._hs_trans[
                        HandshakeType.ENCRYPTED_EXTENSIONS, False]
                return self.get_verify_data(base_key, thash)
            case 'client_finished_verify':
                base_key = self.client_handshake_traffic_secret
                thash = self._hs_trans[HandshakeType.FINISHED, False]
                return self.get_verify_data(base_key, thash)
            case _:
                try:
                    secret, text, lookup = self._DERIVATIONS[name]
                except KeyError:
                    raise KeyError(f'cannot compute this key until {name} is known') from None
                value = derive_secret(
                    hash_alg   = self.hash_alg,
                    secret     = getattr(self, secret),
                    label      = text,
                    msg_digest = self._hs_trans[lookup],
                )
        logger.info(f'calculated {name} = {value[:10].hex()}...{value[-10:].hex()}')
        self._mem[name] = value
        return value

    def __setattr__(self, name, value):
        if name in self._mem:
            raise ValueError(f'value for {name} already set')
        elif name == 'cipher_suite':
            self._hs_trans.hash_alg = self.hash_alg = get_hash_alg(value)
        elif value is None:
            value = self.zero
        self._mem[name] = value


_ServerTicketPlaintext = Struct(
    cipher_suite = CipherSuite,
    expiration = Integer(8),
    psk = Bounded(2, Raw),
)

_ServerTicketCiphertext = Struct(
    inner_ciphertext = Bounded(2, Raw),
    iv = Bounded(1, Raw),
)


class ServerTicketer:
    """Stores server-side data needed to issue and redeem resumption tickets.

    This is implemented using a (fresh) symmetric encryption key.
    Each ticket value is an encryption of the resumption secret and cipher suite.
    """

    _AEAD = ChaCha20Poly1305
    _NONCE_LENGTH = 12
    _GRACE = 60*10 # grace period (in seconds) for ticket age checks

    def __init__(self):
        self._cipher = self._AEAD(self._AEAD.generate_key())
        logger.info("Generated a random key for symmetric encryption of tickets.")
        self._used = set()

    def _get_current_time(self, hint):
        return time.time() if hint is None else hint

    def gen_ticket(self, secret, nonce, lifetime, csuite, current_time=None):
        """Generates a fresh Ticket struct to send to the client.

        secret: ticket resumption PSK
        nonce: ticket_nonce value (unique within session, used to compute secret)
        lifetime: seconds until ticket expires
        csuite: cipher suite used in this session
        current_time: current time in seconds (None to use current system time)
        """
        current_time = self._get_current_time(current_time)
        expiration = current_time + lifetime

        ptext = _ServerTicketPlaintext.pack(
            cipher_suite = csuite,
            expiration = round(expiration),
            psk = secret,
        )

        iv = os.urandom(self._NONCE_LENGTH)
        inner_ctext = self._cipher.encrypt(iv, ptext, iv)

        ctext = _ServerTicketCiphertext.pack(
            inner_ciphertext = inner_ctext,
            iv = iv,
        )

        return Ticket.prepack(
            ticket_lifetime = lifetime,
            ticket_age_add = int.from_bytes(os.urandom(4)),
            ticket_nonce = nonce,
            ticket = ctext,
            extensions = [],
        )

    def use_ticket(self, psk_identity, csuite, current_time=None):
        current_time = self._get_current_time(current_time)

        ctext = psk_identity.identity
        # NB psk_identity.obfuscated_ticket_age is ignored

        if ctext in self._used:
            logger.info('INVALID TICKET: already used')
            return None

        try:
            outer = _ServerTicketCiphertext.unpack(ctext)
        except UnpackError:
            logger.info('INVALID TICKET: unable to parse client ticket ctext')
            return None

        try:
            inner = _ServerTicketPlaintext.unpack(
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


def calc_binder_key(chello, index, secret, csuite, prefix=b''):
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
    hst.add(HandshakeType.SERVER_HELLO, False, prefix)

    exts = chello.body.extensions
    if not exts or exts[-1].typ != ExtensionType.PRE_SHARED_KEY:
        raise TlsError("PSK extension must come last in client hello")

    pske = exts[-1].data
    if index >= len(pske.identities) or len(pske.binders) != len(pske.identities):
        raise TlsError("index out of bounds or mismatch in PSK extension")

    raw_hello = Handshake.pack(chello)
    pbinds = PskBinders.pack(pske.binders)
    assert raw_hello.endswith(pbinds)
    hst.add(HandshakeType.CLIENT_HELLO, True, raw_hello[:-len(pbinds)])

    kc.psk = secret
    binder = kc.get_verify_data(kc.binder_key, hst[-1])

    if len(binder) != len(pske.binders[index]):
        raise TlsError("binder key in client hello has the wrong length")

    return binder

