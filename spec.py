from typing import Self, BinaryIO, TextIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar, override
from dataclasses import dataclass, field
import dataclasses
from io import BytesIO
from sys import stdout
from enum import IntEnum
import functools
from textwrap import dedent

type Json = int | float | str | bool | None | list[Json] | dict[str, Json]

def kwdict[T](**kwargs: T) -> dict[str, T]:
    return kwargs

def force_read(src: BinaryIO, size: int) -> bytes:
    got = src.read(size)
    if len(got) != size:
        raise ValueError
    return got

def force_write(dest: BinaryIO, data: bytes) -> None:
    written = dest.write(data)
    if written != len(data):
        raise ValueError
    dest.flush()

class Spec:
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

class FullSpec(Spec):
    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError

class _Wrapper[T: FullSpec](FullSpec):
    _DATA_TYPE: type[T]

    def __init__(self, data: T) -> None:
        if not isinstance(data, self._DATA_TYPE):
            raise ValueError
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
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        data, size = cls._DATA_TYPE.unpack_from(src, limit)
        return cls(data=data), size

class _Fixed(FullSpec):
    _BYTE_LENGTH: int

    def packed_size(self) -> int:
        return self._BYTE_LENGTH

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        if limit is not None and limit < cls._BYTE_LENGTH:
            raise ValueError
        raw = force_read(src, cls._BYTE_LENGTH)
        return cls.unpack(raw), cls._BYTE_LENGTH

class Empty(_Fixed):
    _BYTE_LENGTH: int = 0

    @override
    def jsonify(self) -> Json:
        return None

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if obj is not None:
            raise ValueError
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
            raise ValueError
        return cls()

    @override
    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        return (cls(), 0)

class _Integral(_Fixed, int):
    def __new__(cls, value: int) -> Self:
        return int.__new__(cls, value)

    def __init__(self, value: int) -> None:
        _Fixed.__init__(self)
        if not (0 <= value < 2**(self._BYTE_LENGTH * 8)):
            raise ValueError

    def jsonify(self) -> Json:
        return self

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, int):
            return cls(obj)
        else:
            raise ValueError

    def packed_size(self) -> int:
        return self._BYTE_LENGTH

    def pack(self) -> bytes:
        return self.to_bytes(self._BYTE_LENGTH)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls._BYTE_LENGTH:
            raise ValueError
        return cls(int.from_bytes(raw))

class String(Spec, str):
    @override
    def jsonify(self) -> Json:
        return self

    @override
    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, str):
            return cls(obj)
        raise ValueError

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

class Raw(Spec, bytes):
    def jsonify(self) -> Json:
        return self.hex()

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, str):
            return cls(bytes.fromhex(obj))
        raise ValueError

    def packed_size(self) -> int:
        return len(self)

    def pack(self) -> bytes:
        return self

    def pack_to(self, dest: BinaryIO) -> int:
        force_write(dest, self)
        return len(self)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(raw)

class _FixRaw(Raw, _Fixed):
    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        return Raw.__new__(cls, *args, **kwargs)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if len(self) != self._BYTE_LENGTH:
            raise ValueError

class _Sequence[T: FullSpec](Spec, tuple[T,...]):
    _ITEM_TYPE: type[T]

    @override
    def jsonify(self) -> Json:
        return [item.jsonify() for item in self]

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, list):
            return cls(cls._ITEM_TYPE.from_json(entry) for entry in obj)
        raise ValueError

    def packed_size(self) -> int:
        return sum(item.packed_size() for item in self)

    def pack(self) -> bytes:
        return b''.join(item.pack() for item in self)

    def pack_to(self, dest: BinaryIO) -> int:
        return sum(item.pack_to(dest) for item in self)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        buf = BytesIO(raw)
        def elts() -> Iterable[T]:
            while buf.tell() != len(raw):
                item, _ = cls._ITEM_TYPE.unpack_from(buf)
                yield item
        return cls(elts())

@dataclass(frozen=True)
class _StructBase(FullSpec):
    _member_names: ClassVar[tuple[str,...]]
    _member_types: ClassVar[tuple[type[FullSpec],...]]
    _member_values: tuple[FullSpec,...] = field(init=False, repr=False, hash=False, compare=False)

    def __post_init__(self) -> None:
        accum: list[FullSpec] = []
        for (name, typ) in zip(self._member_names, self._member_types):
            obj = getattr(self, name)
            if isinstance(obj, typ):
                accum.append(obj)
            else:
                raise ValueError
        super().__setattr__('_member_values', tuple(accum))

    def jsonify(self) -> Json:
        return {name: value.jsonify()
                for (name,value) in zip(self._member_names, self._member_values)}

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, dict):
            accum = {name: typ.from_json(obj[name])
                     for (name,typ) in zip(cls._member_names, cls._member_types)}
            return cls(**accum)
        raise ValueError

    def packed_size(self) -> int:
        return sum(value.packed_size() for value in self._member_values)

    def pack(self) -> bytes:
        return b''.join(value.pack() for value in self._member_values)

    def pack_to(self, dest: BinaryIO) -> int:
        return sum(value.pack_to(dest) for value in self._member_values)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        buf = BytesIO(raw)
        offset = 0
        # XXX mypy doesn't know about __func__
        instance, got = _StructBase.unpack_from.__func__(cls, buf, len(raw)) # type: ignore
        # XXX mypy doesn't realize that instance must be of type Self here
        assert isinstance(instance, cls)
        if got != len(raw):
            raise ValueError
        return instance

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        consumed = 0
        accum = {}
        for (name, typ) in zip(cls._member_names, cls._member_types):
            accum[name], got = typ.unpack_from(src, None if limit is None else (limit - consumed))
            consumed += got
        return cls(**accum), consumed

class _SpecEnum(_Fixed, IntEnum):
    pass

class _Const[T: Spec](FullSpec):
    VALUE: T

    def jsonify(self) -> Json:
        return self.VALUE.jsonify()

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if obj != cls.VALUE.jsonify():
            raise ValueError
        return cls()

    def packed_size(self) -> int:
        return self.VALUE.packed_size()

    def pack(self) -> bytes:
        return self.VALUE.pack()

    def pack_to(self, dest: BinaryIO) -> int:
        return self.VALUE.pack_to(dest)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if raw != cls.VALUE.pack():
            raise ValueError
        return cls()

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raw = cls.VALUE.pack()
        if limit is not None and limit < len(raw):
            raise ValueError
        if force_read(src, len(raw)) != raw:
            raise ValueError
        return cls(), len(raw)

class _Selectee[S: _SpecEnum, T: FullSpec](FullSpec):
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
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        typ, tlen = cls._SELECT_TYPE.unpack_from(src, limit)
        return cls.unpack_from_data(typ, src, (None if limit is None else limit-tlen))

    @classmethod
    def unpack_from_data(cls, typ: S, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        typ = cls._check_typ(typ)
        data, dlen = cls._DATA_TYPE.unpack_from(src, limit)
        return cls(typ=typ, data=data), cls._SELECT_TYPE._BYTE_LENGTH + dlen

class _SpecificSelectee[S: _SpecEnum, T: FullSpec](_Selectee[S, T]):
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

class _Select[S: _SpecEnum](FullSpec):
    _SELECT_TYPE: type[S]
    _DEFAULT_TYPE: type[_Selectee[S,FullSpec]] | None
    _SELECTEES: dict[S, type[_Selectee[S,FullSpec]]]

    def __init__(self, value: _Selectee[S,FullSpec]) -> None:
        self._value: _Selectee[S,FullSpec] = value

    @property
    def typ(self) -> S:
        return self._value.typ

    @property
    def data(self) -> FullSpec:
        return self._value.data

    def jsonify(self) -> Json:
        return self._value.jsonify()

    @classmethod
    def _get_value_cls(cls, selector: S) -> type[_Selectee[S,FullSpec]]:
        try:
            return cls._SELECTEES[selector]
        except KeyError:
            if cls._DEFAULT_TYPE is None:
                raise ValueError(f'got unexpected selector {repr(selector)} with no default')
            else:
                return cls._DEFAULT_TYPE

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        match obj:
            case {'typ': typ}:
                selector = cls._SELECT_TYPE.from_json(typ)
                value_cls = cls._get_value_cls(selector)
                return cls(value_cls.from_json(obj))
        raise ValueError

    def packed_size(self) -> int:
        return self._value.packed_size()

    def pack(self) -> bytes:
        return self._value.pack()

    def pack_to(self, dest: BinaryIO) -> int:
        return self._value.pack_to(dest)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        slen = cls._SELECT_TYPE._BYTE_LENGTH
        if len(raw) < slen:
            raise ValueError
        selector = cls._SELECT_TYPE.unpack(raw[:slen])
        value_cls = cls._get_value_cls(selector)
        return cls(value_cls.unpack(raw))

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        selector, slen = cls._SELECT_TYPE.unpack_from(src, limit)
        value_cls = cls._get_value_cls(selector)
        value, got = value_cls.unpack_from_data(selector, src, (None if limit is None else limit-slen))
        return cls(value), got



'''
class Spec:
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

class FullSpec(Spec):
    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError
'''
