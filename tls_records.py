"""Record-level transmission logic for TLS 1.3."""

from collections import namedtuple

from tls_common import *
from util import SetOnce
from spec import force_write, UnpackError
from tls13_spec import (
    Record,
    ContentType,
    RecordHeader,
    Version,
    InnerPlaintext,
)
from tls_crypto import StreamCipher

class RecordReader:
    hs_buffer = SetOnce()

    def __init__(self, file, transcript, app_data_buffer):
        self._file = file
        self._transcript = transcript
        self._app_data_buffer = app_data_buffer
        self._unwrapper = None
        self._key_count = -1

    def rekey(self, cipher, hash_alg, secret):
        logger.info(f"rekeying record reader to key {secret.hex()[:16]}...")
        self._unwrapper = StreamCipher(cipher, hash_alg, secret)
        self._key_count += 1

    def get_next_record(self):
        logger.info('trying to fetch a record from the incoming stream')
        try:
            record = Record.unpack_from(self._file)
        except (UnpackError, EOFError) as e:
            raise TlsError("error reading or unpacking record from server") from e

        (typ,vers), payload = record
        logger.info(f'Fetched a length-{len(payload)} record of type {typ}')
        wrapped = False
        padding = 0

        if typ == ContentType.APPLICATION_DATA:
            if self._unwrapper is None:
                raise TlsError("got APPLICATION_DATA before setting encryption keys")
            wrapped = True
            header = RecordHeader.pack(typ, vers, len(payload))
            ptext = self._unwrapper.decrypt(payload, header)
            typ, payload, padding = InnerPlaintext.unpack(ptext)
            logger.info(f'Decrypted record to length-{len(payload)} of type {typ} with padding {padding}')
            kc = self._key_count
        else:
            if self._unwrapper is not None and typ != ContentType.CHANGE_CIPHER_SPEC:
                raise TlsError(f"got unwrapped {typ} record but decryption key has been established")
            kc = -1

        self._transcript.add(
            typ         = typ,
            payload     = payload,
            from_client = False,
            key_count   = kc,
            padding     = padding,
            raw         = Record.pack(record),
        )

        return typ, payload

    def fetch(self):
        typ, payload = self.get_next_record()

        match typ:
            case ContentType.CHANGE_CIPHER_SPEC:
                pass # ignore these ones
            case ContentType.ALERT:
                raise TlsError(f"Received ALERT: {payload}")
            case ContentType.HANDSHAKE:
                self.hs_buffer.add(payload)
            case ContentType.APPLICATION_DATA:
                self._app_data_buffer.add(payload)
            case _:
                raise TlsError(f"Unexpected message type {typ} received")


class RecordWriter:
    def __init__(self, file, transcript):
        self._file = file
        self._transcript = transcript
        self._wrapper = None
        self._key_count = -1

    @property
    def max_payload(self):
        return 2**14 - 17

    def rekey(self, cipher, hash_alg, secret):
        logger.info(f"rekeying record writer to key {secret.hex()[:16]}...")
        self._wrapper = StreamCipher(cipher, hash_alg, secret)
        self._key_count += 1

    def send(self, typ, payload, vers=Version.TLS_1_2, padding=0):
        wrapped = self._wrapper is not None and typ != ContentType.CHANGE_CIPHER_SPEC
        if wrapped:
            ptext = InnerPlaintext.pack(typ=typ, data=payload, padding=padding)
            header = RecordHeader.pack(
                typ  = ContentType.APPLICATION_DATA,
                vers = Version.TLS_1_2,
                size = self._wrapper._cipher.ctext_size(len(ptext))
            )
            ctext = self._wrapper.encrypt(ptext, header)
            logger.info(f'------ encrypted ptext {ptext.hex()[:10]}...{ptext.hex()[-10:]}[len(ptext)] to ctext {ctext.hex()[:10]}...')
            raw = header + ctext
            Record.unpack(raw) # double check, could be removed
        else:
            if padding:
                raise ValueError("can't pad unwrapped record")
            raw = Record.pack((typ, vers), payload)

        self._transcript.add(
            typ         = typ,
            payload     = payload,
            from_client = True,
            key_count   = (self._key_count if wrapped else -1),
            padding     = padding,
            raw         = raw,
        )

        force_write(self._file, raw)
        logger.info(f'sent a size-{len(payload)} payload {"" if wrapped else "un"}wrapped in a size-{len(raw)} record')


class DataBuffer:
    def __init__(self):
        self._buf = bytearray()

    def __bool__(self):
        return bool(self._buf)

    def add(self, payload):
        self._buf.extend(payload)

    def get(self, maxsize):
        chunk = self._buf[:maxsize]
        del self._buf[:maxsize]
        return chunk


class HandshakeBuffer(DataBuffer):
    def __init__(self, owner):
        super().__init__()
        self._owner = owner # e.g. ClientHandshake, will receive hs payloads

    def add(self, payload):
        super().add(payload)

        # try to break off any complete handshake messages
        while len(self._buf) >= 4:
            size = 4 + int.from_bytes(self._buf[1:4])
            if len(self._buf) < size:
                break
            self._owner.process_hs_payload(self.get(size))


RecordEntry = namedtuple(
        'RecordEntry',
        'typ payload from_client key_count padding raw')

class RecordTranscript:
    def __init__(self, client_secrets):
        self.records = [client_secrets]

    def add(self, **kwargs):
        self.records.append(RecordEntry(**kwargs))


class Connection:
    def __init__(self, secrets, handshake):
        self._transcript = RecordTranscript(secrets)
        self._app_data_in = DataBuffer()
        self._handshake = handshake

    @property
    def transcript(self):
        return self._transcript

    def connect_socket(self, sock):
        self.connect_files(
            sock.makefile('rb'),
            sock.makefile('wb'),
        )

    def connect_files(self, instream, outstream):
        if self._handshake.started:
            raise ValueError("already started! can't connect again")

        self._rreader = RecordReader(instream, self._transcript, self._app_data_in)
        self._rwriter = RecordWriter(outstream, self._transcript)

        self._handshake.begin(self._rreader, self._rwriter)

        while not self._handshake.connected:
            self._rreader.fetch()

    def send(self, appdata):
        if not self._handshake.can_send:
            raise ValueError("can't send application data yet")
        buf = bytearray(appdata)
        maxp = self._rwriter.max_payload
        while buf:
            chunk = buf[:maxp]
            self._rwriter.send(typ=ContentType.APPLICATION_DATA,
                               payload=bytes(buf[:maxp]))
            del buf[:maxp]
        return len(appdata)

    def recv(self, maxsize):
        if not self._handshake.can_recv:
            raise ValueError("can't receive application data yet")
        while not self._app_data_in:
            self._rreader.fetch()
        return self._app_data_in.get(maxsize)
