"""Record-level transmission logic for TLS 1.3."""

from collections import namedtuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import override

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
from tls_crypto import AeadCipher, Hasher, StreamCipher

class PayloadProcessor(ABC):
    @abstractmethod
    def process_hs_payload(payload: bytes) -> None: ...

@dataclass
class DataBuffer:
    _buf: bytearray = field(default_factory=bytearray)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def add(self, payload: bytes) -> None:
        self._buf.extend(payload)

    def get(self, maxsize: int) -> bytes:
        chunk = self._buf[:maxsize]
        del self._buf[:maxsize]
        return chunk

@dataclass
class HandshakeBuffer(DataBuffer):
    owner: PayloadProcessor|None = None

    @override
    def add(self, payload: bytes) -> None:
        super().add(payload)

        # try to break off any complete handshake messages
        while len(self._buf) >= 4:
            size = 4 + int.from_bytes(self._buf[1:4])
            if len(self._buf) < size:
                break
            if self.owner is not None:
                self.owner.process_hs_payload(self.get(size))


@dataclass
class RecordReader:
    _file: BinaryIO
    _transcript: HandshakeTranscript
    _app_data_buffer: DataBuffer
    _unwrapper: StreamCipher|None = None
    _key_count: int = -1
    _hs_buffer: HandshakeBuffer|None = None

    @property
    def hs_buffer(self) -> HandshakeBuffer:
        assert self._hs_buffer is not None
        return self._hs_buffer

    @hs_buffer.setter
    def hs_buffer(self, val: HandshakeBuffer) -> None:
        assert self._hs_buffer is None
        self._hs_buffer = val

    def rekey(self, cipher: AeadCipher, hash_alg: Hasher, secret: bytes):
        logger.info(f"rekeying record reader to key {secret.hex()[:16]}...")
        self._unwrapper = StreamCipher(cipher, hash_alg, secret)
        self._key_count += 1

    def get_next_record(self) -> Record:
        logger.info('trying to fetch a record from the incoming stream')
        try:
            record = Record.unpack_from(self._file)
        except (UnpackError, EOFError) as e:
            raise TlsError("error reading or unpacking record from server") from e

        logger.info(f'Fetched a record of type {record.typ}')
        wrapped = False
        padding = 0

        match record.variant:
            case ChangeCipherSpecRecord() as ccsrec:
                pass #TODO
            case HandshakeRecord() as hsrec:
                pass #TODO
            case ApplicationDataRecord() as adrec:
                if self._unwrapper is None:
                    raise TlsError("got APPLICATION_DATA before setting encryption keys")
                wrapped = True
                header = RecordHeader.create(adrec.typ, adrec.version, len(adrec.payload))
                ptext = self._unwrapper.decrypt(adrec.payload, header.pack())
                typ, payload, padding = InnerPlaintext.unpack(ptext)
                logger.info(f'Decrypted record to length-{len(payload)} of type {typ} with padding {padding}')
                kc = self._key_count
            case AlertRecord() as alrec:
                pass #TODO

        if typ == ContentType.APPLICATION_DATA:
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
