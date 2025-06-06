"""Record-level transmission logic for TLS 1.3."""

from collections import namedtuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import override, ClassVar, BinaryIO

from tls_common import *
import spec
from spec import force_write, UnpackError, Fill, Raw
from tls13_spec import (
    Record,
    ContentType,
    RecordHeader,
    Version,
    InnerPlaintextBase,
    Uint16,
    ApplicationDataRecord,
    ChangeCipherSpecRecord,
    HandshakeRecord,
)
from tls_crypto import AeadCipher, Hasher, StreamCipher
from tls_keycalc import HandshakeTranscript

class PayloadProcessor(ABC):
    @abstractmethod
    def process_hs_payload(self, payload: bytes) -> None: ...

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

class Record(RecordBase):
    def header(self) -> RecordHeader:
        return RecordHeader.create(
            typ = self.typ,
            version = self.version,
            size = len(self.payload),
        )

class InnerPlaintext(InnerPlaintextBase):
    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        ct_len = ContentType._BYTE_LENGTH
        prefix_len = len(raw.rstrip(b'\x00'))
        if prefix_len < ct_len:
            raise UnpackError(f"need at least {ct_len} bytes in prefix, got {raw.hex()}")
        pay_len = prefix_len - ct_len
        return cls(
            payload = Raw.unpack(raw[:pay_len]),
            typ = ContentType.unpack(raw[pay_len:prefix_len]),
            padding = Fill.unpack(raw[prefix_len:]),
        )

    @override
    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError

    def to_record(self, vers: Version) -> Record:
        return Record.create(
            typ = self.typ,
            version = vers,
            payload = self.payload,
        )

@dataclass
class RecordTranscript:
    secrets: StoredSecrets
    is_client: bool
    records: list[RecordEntry] = field(default_factory=list)

    @classmethod
    def client(cls, secrets: ClientSecrets) -> Self:
        return cls(
            secrets = ClientStoredSecrets(data=secrets).parent(),
            is_client = True,
        )

    @classmethod
    def server(cls, secrets: ServerSecrets) -> Self:
        return cls(
            secrets = ClientStoredSecrets(data=secrets).parent(),
            is_client = False,
        )

    #TODO FIXME HERE
    def add_unwrapped(self, record: Record, sent: bool, key_count: int, padding: int):
        self.records.append(RecordEntry.create(
            record = record,
            from_client = (sent if self.is_client else not sent),
            key_count = key_count,
            padding = padding,
        )

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

    def rekey(self, cipher: AeadCipher, hash_alg: Hasher, secret: bytes) -> None:
        logger.info(f"rekeying record reader to key {secret.hex()[:16]}...")
        self._unwrapper = StreamCipher(cipher, hash_alg, secret)
        self._key_count += 1

    def get_next_record(self) -> Record:
        logger.info('trying to fetch a record from the incoming stream')
        try:
            record, _ = Record.unpack_from(self._file)
        except (UnpackError, EOFError) as e:
            raise TlsError("error reading or unpacking record from server") from e

        logger.info(f'Fetched a size-{len(record.payload)} record of type {record.typ}')

        wrapped = False
        kc = -1
        padding = 0

        if record.typ == RecordType.APPLICATION_DATA and self._unwrapper is not None:
            wrapped = True
            ipt = InnerPlaintext.unpack(
                self._unwrapper.decrypt(
                    ctext = adrec.payload,
                    adata = record.header().pack(),
                )
            )
            record = ipt.to_record(record.version)
            kc = self._key_count
            padding = ipt.padding.size
            logger.info(f'Decrypted record to length-{len(record.payload)} of type {record.typ} with padding {padding}')

        self._transcript.add(
            record      = record,
            from_client = False,
            key_count   = kc,
            padding     = padding,
        )

        return record

    def fetch(self) -> None:
        record = self.get_next_record()

        match record.variant:
            case ChangeCipherSpecRecord():
                pass # ignore these messages
            case AlertRecord(data=alrec):
                raise TlsError(f"Received ALERT: {alrec.payload}")
            case HandshakeRecord(data=hs):
                self.hs_buffer.add(hs)
            case ApplicationDataRecord(data=payload):
                self._app_data_buffer.add(payload)
            case _:
                assert False, "unrecognized record variant"


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
