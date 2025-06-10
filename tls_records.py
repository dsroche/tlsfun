"""Record-level transmission logic for TLS 1.3."""

from collections import namedtuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod, abstractproperty
from typing import override, ClassVar, BinaryIO, Self
import socket

from tls_common import *
import spec
from spec import force_write, UnpackError, Fill, Raw, LimitReader
from tls13_spec import (
    Record,
    ContentType,
    RecordHeader,
    Version,
    InnerPlaintextBase,
    RecordEntry,
    Transcript,
    Alert,
)
from tls_crypto import AeadCipher, Hasher, StreamCipher
from tls_keycalc import KeyCalc, KeyCalcMissing

HOST_NAME_TYPE = 0 # for SNI extension
CCS_PAYLOAD = b'\x01'
DEFAULT_LEGACY_VERSION = Version.TLS_1_2
DEFAULT_LEGACY_COMPRESSION = [0]

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

def get_header(record: Record) -> RecordHeader:
    return RecordHeader.create(
        typ = record.typ,
        version = record.version,
        size = len(record.payload),
    )

class InnerPlaintext(InnerPlaintextBase):
    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        ct_len = ContentType._BYTE_LENGTH
        prefix_len = len(raw.rstrip(b'\x00'))
        if prefix_len < ct_len:
            raise UnpackError(raw, f"need at least {ct_len} bytes in prefix, got {raw.hex()}")
        pay_len = prefix_len - ct_len
        return cls(
            payload = Raw.unpack(raw[:pay_len]),
            typ = ContentType.unpack(raw[pay_len:prefix_len]),
            padding = Fill.unpack(raw[prefix_len:]),
        )

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        raise NotImplementedError

    def to_record(self, version: Version) -> Record:
        return Record.create(
            typ = self.typ,
            version = version,
            payload = self.payload,
        )

@dataclass
class RecordTranscript:
    is_client: bool
    keys: KeyCalc|None = None
    records: list[RecordEntry] = field(default_factory=list)

    def add(self, raw: bytes, record: Record, sent: bool) -> None:
        self.records.append(RecordEntry.create(
            raw = raw,
            record = record.uncreate(),
            from_client = (sent if self.is_client else not sent),
        ))

    def get(self) -> Transcript:
        psk = b''
        kex_secret = b''
        if self.keys is not None:
            try:
                psk = self.keys.psk
            except KeyCalcMissing:
                pass
            try:
                kex_secret = self.keys.kex_secret
            except KeyCalcMissing:
                pass
        return Transcript.create(
            psk = psk,
            kex_secret = kex_secret,
            records = (record.uncreate() for record in self.records),
        )


@dataclass
class RecordReader:
    _file: BinaryIO
    _transcript: RecordTranscript
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
        record_src = LimitReader(self._file)
        try:
            record = Record.unpack_from(record_src)
        except (UnpackError, EOFError) as e:
            raise TlsError("error reading or unpacking record from server") from e
        raw: bytes = record_src.got

        logger.info(f'Fetched a size-{len(raw)} record of type {record.typ}')

        if record.typ == ContentType.APPLICATION_DATA and self._unwrapper is not None:
            wrapped = True
            ipt = InnerPlaintext.unpack(
                self._unwrapper.decrypt(
                    ctext = record.payload,
                    adata = get_header(record).pack(),
                )
            )
            record = ipt.to_record(record.version)
            logger.info(f'Decrypted record to length-{len(record.payload)} of type {record.typ} with padding {ipt.padding.size}')

        self._transcript.add(
            raw    = raw,
            record = record,
            sent   = False,
        )

        return record

    def fetch(self) -> None:
        record = self.get_next_record()

        match record.typ:
            case ContentType.CHANGE_CIPHER_SPEC:
                if record.payload != CCS_PAYLOAD:
                    raise TlsError(f"CCS payload should be {CCS_PAYLOAD.hex()} but got {record.payload.hex()}")
                return # ignore these messages
            case ContentType.HANDSHAKE:
                self.hs_buffer.add(record.payload)
            case ContentType.ALERT:
                alert = Alert.unpack(record.payload)
                raise TlsError(f"Received ALERT: {alert}")
            case ContentType.APPLICATION_DATA:
                self._app_data_buffer.add(record.payload)
            case _:
                raise TlsError(f"Received unexpected record of type {record.typ}")

@dataclass
class RecordWriter:
    file: BinaryIO
    transcript: RecordTranscript
    wrapper: StreamCipher|None = None
    key_count: int = -1

    @property
    def max_payload(self) -> int:
        return 2**14 - 17

    def rekey(self, cipher: AeadCipher, hash_alg: Hasher, secret: bytes) -> None:
        logger.info(f"rekeying record writer to key {secret.hex()[:16]}...")
        self.wrapper = StreamCipher(cipher, hash_alg, secret)
        self.key_count += 1

    def send(self, record: Record, padding: int = 0) -> None:
        if self.wrapper is not None and record.typ != ContentType.CHANGE_CIPHER_SPEC:
            if record.version != DEFAULT_LEGACY_VERSION:
                raise ValueError(f"wrapped records should always have version {repr(DEFAULT_LEGACY_VERSION)}")
            ptext = InnerPlaintext.create(
                payload = record.payload,
                typ     = record.typ,
                padding = padding,
            ).pack()
            header = RecordHeader.create(
                typ     = ContentType.APPLICATION_DATA,
                version = DEFAULT_LEGACY_VERSION,
                size    = self.wrapper.cipher.ctext_size(len(ptext))
            ).pack()
            ctext = self.wrapper.encrypt(ptext, header)
            logger.info(f'------ encrypted ptext {ptext.hex()[:10]}...{ptext.hex()[-10:]}[len(ptext)] to ctext {ctext.hex()[:10]}...')
            raw = header + ctext
        else:
            if padding:
                raise ValueError("can't pad unwrapped record")
            raw = record.pack()

        self.transcript.add(
            raw    = raw,
            record = record,
            sent   = True,
        )

        force_write(self.file, raw)
        logger.info(f'sent a size-{len(record.payload)} payload in a size-{len(raw)} record')

class AbstractHandshake(ABC):
    @abstractproperty
    def started(self) -> bool: ...
    @abstractproperty
    def connected(self) -> bool: ...
    @abstractproperty
    def can_send(self) -> bool: ...
    @abstractproperty
    def can_recv(self) -> bool: ...
    @abstractmethod
    def begin(self, reader: RecordReader, writer: RecordWriter) -> None: ...

@dataclass
class Connection:
    transcript: RecordTranscript
    handshake: AbstractHandshake
    app_data_in: DataBuffer = field(default_factory=DataBuffer)
    _rreader: RecordReader = field(init=False)
    _rwriter: RecordWriter = field(init=False)

    def connect_socket(self, sock: socket.socket) -> None:
        self.connect_files(
            sock.makefile('rb'),
            sock.makefile('wb'),
        )

    def connect_files(self, instream: BinaryIO, outstream: BinaryIO) -> None:
        if self.handshake.started:
            raise ValueError("already started! can't connect again")

        self._rreader = RecordReader(instream, self.transcript, self.app_data_in)
        self._rwriter = RecordWriter(outstream, self.transcript)

        self.handshake.begin(self._rreader, self._rwriter)

        while not self.handshake.connected:
            self._rreader.fetch()

    def send(self, appdata: bytes) -> int:
        if not self.handshake.can_send:
            raise ValueError("can't send application data yet")
        buf = bytearray(appdata)
        maxp = self._rwriter.max_payload
        while buf:
            chunk = buf[:maxp]
            self._rwriter.send(Record.create(
                typ = ContentType.APPLICATION_DATA,
                version = DEFAULT_LEGACY_VERSION,
                payload = bytes(buf[:maxp])
            ))
            del buf[:maxp]
        return len(appdata)

    def recv(self, maxsize: int) -> bytes:
        if not self.handshake.can_recv:
            raise ValueError("can't receive application data yet")
        while not self.app_data_in:
            self._rreader.fetch()
        return self.app_data_in.get(maxsize)
