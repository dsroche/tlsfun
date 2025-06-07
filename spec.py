from typing import Self, BinaryIO, TextIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar, override
from dataclasses import dataclass, field
import dataclasses
from io import BytesIO
from sys import stdout
from enum import IntEnum
import functools
from textwrap import dedent
from util import pformat

type Json = int | float | str | bool | None | list[Json] | dict[str, Json]

ERROR_VAL = '!!! ERROR HERE !!!'

@dataclass
class UnpackError(ValueError):
    source: bytes|Json
    description: str
    partial: Json = ERROR_VAL

    @override
    def __str__(self) -> str:
        return dedent(f"""\
            Error unpacking {pformat(self.source, byteslen=40)}
            Partial result:
            {pformat(self.partial)}
            """)

@dataclass
class LimitReader:
    src: BinaryIO
    limit: int|None = None
    got: bytearray = field(default_factory=bytearray)

    def read(self, size: int) -> bytes:
        if self.limit is not None and self.limit < size:
            limited = self.limit
            self.read(limited)
            raise UnpackError(self.got, f"tried to read {size} bytes but limit was {limited}")
        raw = self.src.read(size)
        self.got.extend(raw)
        if len(raw) != size:
            raise UnpackError(self.got, f"tried to read {size} bytes but only got {len(raw)}")
        if self.limit is not None:
            self.limit -= size
        return raw

    @classmethod
    def from_raw(cls, raw: bytes) -> Self:
        return cls(src = BytesIO(raw), limit = len(raw))

    def assert_used_up(self) -> None:
        if self.limit is None:
            raise ValueError("can't check used_up when there is no limit")
        elif self.limit != 0:
            limited = self.limit
            extra = self.read(limited)
            raise UnpackError(self.got, f"extra bytes that should have been used up: {pformat(extra)}")


def force_write(dest: BinaryIO, data: bytes) -> None:
    written = dest.write(data)
    if written != len(data):
        raise ValueError(f"Error trying to write {len(data)} bytes; only wrote {written}")
    dest.flush()

class Spec:
    _CREATE_FROM: tuple[tuple[str, type[Any]], ...] | None = None

    def jsonify(self) -> Json:
        raise NotImplementedError

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        raise NotImplementedError

    def packed_size(self) -> int:
        return len(self.pack())

    def pack(self) -> bytes:
        raise NotImplementedError

    def pack_to(self, dest: BinaryIO) -> int:
        raw = self.pack()
        force_write(dest, raw)
        return len(raw)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        raise NotImplementedError

    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        raise NotImplementedError

class _Wrapper[T: Spec](Spec):
    _DATA_TYPE: type[T]

    def __init__(self, data: T) -> None:
        if not isinstance(data, self._DATA_TYPE):
            raise ValueError("expected type {self._DATA_TYPE}, got {data}")
        self._data = data

    @property
    def data(self) -> T:
        return self._data

    @override
    def jsonify(self) -> Json:
        return self.data.jsonify()

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        return cls(data = cls._DATA_TYPE.from_json(obj))

    @override
    def packed_size(self) -> int:
        return self.data.packed_size()

    @override
    def pack(self) -> bytes:
        return self.data.pack()

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return self.data.pack_to(dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(data = cls._DATA_TYPE.unpack(raw))

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        return cls(data=cls._DATA_TYPE.unpack_from(src))

class _Fixed(Spec):
    _BYTE_LENGTH: int

    @override
    def packed_size(self) -> int:
        return self._BYTE_LENGTH

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        return cls.unpack(src.read(cls._BYTE_LENGTH))

class Empty(_Fixed):
    _BYTE_LENGTH: int = 0
    _CREATE_FROM = ()

    @classmethod
    def create(cls) -> Self:
        return cls()

    def uncreate(self) -> tuple[()]:
        return ()

    @override
    def jsonify(self) -> Json:
        return None

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if obj is not None:
            raise UnpackError(obj, "Empty should be None")
        return cls()

    @override
    def pack(self) -> bytes:
        return b''

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return 0

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw):
            raise UnpackError(raw, "Empty should be b''")
        return cls()

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        return cls()

class Bool(_Fixed):
    _BYTE_LENGTH = 1
    _CREATE_FROM = (('value', bool),)

    def __init__(self, value: bool) -> None:
        self._value = value

    @property
    def value(self) -> bool:
        return self._value

    @classmethod
    def create(cls, value: bool) -> Self:
        return cls(value)

    def uncreate(self) -> bool:
        return self.value

    @override
    def jsonify(self) -> Json:
        return self.value

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, bool):
            return cls(obj)
        else:
            raise UnpackError(obj, "bool should be bool")

    @override
    def pack(self) -> bytes:
        return int(self.value).to_bytes(self._BYTE_LENGTH)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls._BYTE_LENGTH:
            raise UnpackError(raw, "expected {cls._BYTE_LENGTH} bytes got {raw.hex()}")
        match int.from_bytes(raw):
            case 0:
                return cls(False)
            case 1:
                return cls(True)
            case x:
                raise UnpackError(raw, "bool must be 0 or 1")

class _Integral(_Fixed, int):
    _CREATE_FROM = (('value', int),)

    def __new__(cls, value: int) -> Self:
        return int.__new__(cls, value)

    def __init__(self, value: int) -> None:
        _Fixed.__init__(self)
        upper = 2**(self._BYTE_LENGTH * 8)
        if not (0 <= value < upper):
            raise ValueError("{value} is not between 0 and {upper}")

    @classmethod
    def create(cls, value: int) -> Self:
        return cls(value)

    def uncreate(self) -> int:
        return self

    @override
    def jsonify(self) -> Json:
        return self

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, int):
            return cls(obj)
        else:
            raise UnpackError(obj, "expected int, got {obj}")

    @override
    def pack(self) -> bytes:
        return self.to_bytes(self._BYTE_LENGTH)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls._BYTE_LENGTH:
            raise UnpackError(raw, "expected {cls._BYTE_LENGTH} bytes, got {raw.hex()}")
        return cls(int.from_bytes(raw))

class String(Spec, str):
    _CREATE_FROM = (('value', str),)

    @classmethod
    def create(cls, value: str) -> Self:
        return cls(value)

    def uncreate(self) -> str:
        return self

    @override
    def jsonify(self) -> Json:
        return self

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, str):
            return cls(obj)
        raise UnpackError(obj, "expected string, got {obj}")

    @override
    def packed_size(self) -> int:
        return len(self.encode('utf8'))

    @override
    def pack(self) -> bytes:
        return self.encode('utf8')

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        raw = self.encode('utf8')
        force_write(dest, raw)
        return len(raw)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(raw.decode('utf8'))

class Fill(Spec):
    _CREATE_FROM = (('size', int),)

    def __init__(self, size: int) -> None:
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    @classmethod
    def create(cls, size: int) -> Self:
        return cls(size)

    def uncreate(self) -> int:
        return self.size

    @override
    def jsonify(self) -> Json:
        return self.size

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, int):
            return cls(obj)
        raise UnpackError(obj, "Json representation of Fill must be int")

    @override
    def packed_size(self) -> int:
        return self.size

    @override
    def pack(self) -> bytes:
        return b'\x00' * self.size

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if any(raw):
            raise UnpackError(raw, "Fill should be all zero bytes")
        return cls(len(raw))


class Raw(Spec, bytes):
    _CREATE_FROM = (('value', bytes),)

    @classmethod
    def create(cls, value: bytes) -> Self:
        return cls(value)

    def uncreate(self) -> bytes:
        return self

    @override
    def jsonify(self) -> Json:
        return self.hex()

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, str):
            return cls(bytes.fromhex(obj))
        raise UnpackError(obj, "expected hex string, got {obj}")

    @override
    def packed_size(self) -> int:
        return len(self)

    @override
    def pack(self) -> bytes:
        return self

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        force_write(dest, self)
        return len(self)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(raw)

class _FixRaw(Raw, _Fixed):
    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        return Raw.__new__(cls, *args, **kwargs)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if len(self) != self._BYTE_LENGTH:
            raise ValueError("expected {self._BYTE_LENGTH} bytes, got {self.hex()}")

class _Sequence[T: Spec](Spec, tuple[T,...]):
    _ITEM_TYPE: type[T]

    @override
    def jsonify(self) -> Json:
        return [item.jsonify() for item in self]

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, list):
            return cls(cls._ITEM_TYPE.from_json(entry) for entry in obj)
        raise UnpackError(obj, "expected list of {cls._ITEM_TYPE}, got {obj}")

    @override
    def packed_size(self) -> int:
        return sum(item.packed_size() for item in self)

    @override
    def pack(self) -> bytes:
        return b''.join(item.pack() for item in self)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return sum(item.pack_to(dest) for item in self)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        buf = LimitReader.from_raw(raw)
        def elts() -> Iterable[T]:
            while buf.limit:
                yield cls._ITEM_TYPE.unpack_from(buf)
        return cls(elts())

@dataclass(frozen=True)
class _StructBase(Spec):
    _member_names: ClassVar[tuple[str,...]]
    _member_types: ClassVar[tuple[type[Spec],...]]
    _member_values: tuple[Spec,...] = field(init=False, repr=False, hash=False, compare=False)

    def __post_init__(self) -> None:
        accum: list[Spec] = []
        for (name, typ) in zip(self._member_names, self._member_types):
            obj = getattr(self, name)
            if isinstance(obj, typ):
                accum.append(obj)
            else:
                raise ValueError(f'expected type {typ} for {name} field in {type(self).__name__}, got {obj}')
        super().__setattr__('_member_values', tuple(accum))

    @override
    def jsonify(self) -> Json:
        return {name: value.jsonify()
                for (name,value) in zip(self._member_names, self._member_values)}

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, dict):
            accum = {name: typ.from_json(obj[name])
                     for (name,typ) in zip(cls._member_names, cls._member_types)}
            return cls(**accum)
        raise UnpackError(obj, "expected dict, got {obj}")

    @override
    def packed_size(self) -> int:
        return sum(value.packed_size() for value in self._member_values)

    @override
    def pack(self) -> bytes:
        return b''.join(value.pack() for value in self._member_values)

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return sum(value.pack_to(dest) for value in self._member_values)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        buf = LimitReader.from_raw(raw)
        offset = 0
        # XXX mypy doesn't know about __func__
        instance = _StructBase.unpack_from.__func__(cls, buf) # type: ignore
        # XXX mypy doesn't realize that instance must be of type Self here
        assert isinstance(instance, cls)
        buf.assert_used_up()
        return instance

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        accum = {}
        for (name, typ) in zip(cls._member_names, cls._member_types):
            accum[name] = typ.unpack_from(src)
        return cls(**accum)

class _SpecEnum(_Fixed, IntEnum):
    pass

class _Const[T: Spec](Spec):
    VALUE: T

    @override
    def jsonify(self) -> Json:
        return self.VALUE.jsonify()

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        expected = cls.VALUE.jsonify()
        if obj != expected:
            raise UnpackError(obj, f"expected {expected}, got {obj}")
        return cls()

    @override
    def packed_size(self) -> int:
        return self.VALUE.packed_size()

    @override
    def pack(self) -> bytes:
        return self.VALUE.pack()

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return self.VALUE.pack_to(dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        expected = cls.VALUE.pack()
        if raw != expected:
            raise UnpackError(raw, f"expected {expected.hex()}, got {raw.hex()}")
        return cls()

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        raw = cls.VALUE.pack()
        got = src.read(len(raw))
        if got != raw:
            raise UnpackError(got, "expected const {pformat(raw)}, got {pformat(got)}")
        return cls()

class _Selectee[S: _SpecEnum, T: Spec](Spec):
    _SELECT_TYPE: type[S]
    _DATA_TYPE: type[T]

    def __init__(self, typ: S, data: T) -> None:
        self._typ: S = typ
        self._data: T = data

    @property
    def typ(self) -> S:
        return self._typ

    @property
    def data(self) -> T:
        return self._data

    @override
    def jsonify(self) -> Json:
        return {'typ': self.typ.jsonify(), 'data': self.data.jsonify()}

    @classmethod
    def _check_typ(cls, typ: S) -> S:
        return typ

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        match obj:
            case {'typ': jtyp, 'data': data, **rest}:
                if rest:
                    raise ValueError
                typ = cls._check_typ(cls._SELECT_TYPE.from_json(jtyp))
                return cls(typ=typ, data=cls._DATA_TYPE.from_json(data))
        raise ValueError

    @override
    def packed_size(self) -> int:
        return self.typ.packed_size() + self.data.packed_size()

    @override
    def pack(self) -> bytes:
        return self.typ.pack() + self.data.pack()

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return self.typ.pack_to(dest) + self.data.pack_to(dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        tlen = cls._SELECT_TYPE._BYTE_LENGTH
        if len(raw) < tlen:
            raise ValueError
        typ = cls._check_typ(cls._SELECT_TYPE.unpack(raw[:tlen]))
        return cls(typ=typ, data=cls._DATA_TYPE.unpack(raw[tlen:]))

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        typ = cls._SELECT_TYPE.unpack_from(src)
        return cls.unpack_from_data(typ, src)

    @classmethod
    def unpack_from_data(cls, typ: S, src: LimitReader) -> Self:
        return cls(typ = cls._check_typ(typ),
                   data = cls._DATA_TYPE.unpack_from(src))

class _SpecificSelectee[S: _SpecEnum, T: Spec](_Selectee[S, T]):
    _SELECTOR: S

    def __init__(self, typ: S|None = None, data: T|None = None) -> None:
        assert data is not None
        super().__init__(self._SELECTOR, data)
        if typ is not None and typ != self._SELECTOR:
            raise ValueError

    @override
    @classmethod
    def _check_typ(cls, typ: S) -> S:
        if typ == cls._SELECTOR:
            return typ
        raise ValueError

class _Select[S: _SpecEnum](Spec):
    _SELECT_TYPE: type[S]
    _GENERIC_TYPE: type[_Selectee[S,Spec]] | None
    _SELECTEES: dict[S, type[_Selectee[S,Spec]]]

    def __init__(self, value: _Selectee[S,Spec]) -> None:
        self._value: _Selectee[S,Spec] = value

    @property
    def typ(self) -> S:
        return self._value.typ

    @property
    def data(self) -> Spec:
        return self._value.data

    @override
    def jsonify(self) -> Json:
        return self._value.jsonify()

    @classmethod
    def _get_value_cls(cls, selector: S) -> type[_Selectee[S,Spec]]:
        try:
            return cls._SELECTEES[selector]
        except KeyError:
            if cls._GENERIC_TYPE is None:
                raise ValueError(f'got unexpected selector {repr(selector)} with no generic')
            else:
                return cls._GENERIC_TYPE

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        match obj:
            case {'typ': typ}:
                selector = cls._SELECT_TYPE.from_json(typ)
                value_cls = cls._get_value_cls(selector)
                return cls(value_cls.from_json(obj))
        raise ValueError

    @override
    def packed_size(self) -> int:
        return self._value.packed_size()

    @override
    def pack(self) -> bytes:
        return self._value.pack()

    @override
    def pack_to(self, dest: BinaryIO) -> int:
        return self._value.pack_to(dest)

    @override
    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        slen = cls._SELECT_TYPE._BYTE_LENGTH
        if len(raw) < slen:
            raise ValueError
        selector = cls._SELECT_TYPE.unpack(raw[:slen])
        value_cls = cls._get_value_cls(selector)
        return cls(value_cls.unpack(raw))

    @override
    @classmethod
    def unpack_from(cls, src: LimitReader) -> Self:
        selector = cls._SELECT_TYPE.unpack_from(src)
        return cls(cls._get_value_cls(selector).unpack_from_data(selector, src))
