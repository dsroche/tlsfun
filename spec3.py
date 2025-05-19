from typing import Self, BinaryIO, get_args, Iterable, Protocol
from dataclasses import dataclass, fields
from io import BytesIO
from enum import IntEnum

type Json = int | float | str | bool | None | list[Json] | dict[str, Json]


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

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None) -> tuple[Self, int]:
        raise NotImplementedError


class FixedSize(Spec):
    FIXED_SIZE: int

    def packed_size(self) -> int:
        return self.FIXED_SIZE

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None) -> tuple[Self, int]:
        if limit is not None and limit < cls.FIXED_SIZE:
            raise ValueError
        return cls.unpack(force_read(src, cls.FIXED_SIZE)), cls.FIXED_SIZE


class Uint(FixedSize, int):
    def __new__(cls, value: int) -> Self:
        return int.__new__(cls, value)

    def __init__(self, value: int) -> None:
        FixedSize.__init__(self)
        if not (0 <= value < 2**(self.FIXED_SIZE*8)):
            raise ValueError

    def jsonify(self) -> Json:
        return self

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, int):
            return cls(obj)
        else:
            raise ValueError

    def pack(self) -> bytes:
        return self.to_bytes(self.FIXED_SIZE)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls.FIXED_SIZE:
            raise ValueError
        return cls(int.from_bytes(raw))


class Uint8(Uint):
    FIXED_SIZE: int = 1

class Uint16(Uint):
    FIXED_SIZE: int = 2

class Uint24(Uint):
    FIXED_SIZE: int = 3

class Uint32(Uint):
    FIXED_SIZE: int = 4


class _Sequence[T: Spec](Spec, tuple[T]):
    ITEM_TYPE: type[T]

    def __new__(cls, values: Iterable[T]) -> Self:
        return tuple.__new__(cls, values)

    def __init__(self, values: Iterable[T]) -> None:
        Spec.__init__(self)
        for x in self:
            if not isinstance(x, self.ITEM_TYPE):
                raise ValueError

    def jsonify(self) -> Json:
        return [x.jsonify() for x in self]

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, (list, tuple)):
            return cls(cls.ITEM_TYPE.from_json(x) for x in obj)
        else:
            raise ValueError

    def packed_size(self) -> int:
        return sum(x.packed_size() for x in self)

    def pack(self) -> bytes:
        return b''.join(x.pack() for x in self)

    def pack_to(self, dest: BinaryIO) -> int:
        raw = self.pack()
        force_write(dest, raw)
        return len(raw)

    @classmethod
    def _unpack_items(cls, raw: bytes) -> Iterable[T]:
        buf = BytesIO(raw)
        while buf.tell() < len(raw):
            item, _ = cls.ITEM_TYPE.unpack_from(buf, None)
            yield item

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(cls._unpack_items(raw))

def Sequence[T: Spec](cls: type[T]) -> type[_Sequence[T]]:
    class SequenceType(_Sequence[T]):
        ITEM_TYPE = cls
    return SequenceType


class _Bounded(Spec):
    LENGTH_TYPE: type[Uint]

    def packed_size(self) -> int:
        return self.LENGTH_TYPE.FIXED_SIZE + super().packed_size()

    def pack(self) -> bytes:
        raw = super().pack()
        return self.LENGTH_TYPE(len(raw)).pack() + raw

    def pack_to(self, dest: BinaryIO) -> int:
        length = self.LENGTH_TYPE(super().packed_size())
        a = length.pack_to(dest)
        b = super().pack_to(dest)
        assert a == self.LENGTH_TYPE.FIXED_SIZE and b == length
        return a + b

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        lenlen = cls.LENGTH_TYPE.FIXED_SIZE
        if len(raw) < lenlen:
            raise ValueError
        length = cls.LENGTH_TYPE.unpack(raw[:lenlen])
        if len(raw) != lenlen + length:
            raise ValueError
        return super().unpack(raw[lenlen:])

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None) -> tuple[Self, int]:
        length, lenlen = cls.LENGTH_TYPE.unpack_from(src, limit)
        totlen = length + lenlen
        if limit is not None and limit < totlen:
            raise ValueError
        return super().unpack(force_read(src, length)), totlen

def BoundedSeq[T: Spec](length_type: type[Uint], cls: type[T]) -> type[_Sequence[T]]:
    class BoundedSeqType(_Bounded, _Sequence[T]):
        LENGTH_TYPE = length_type
        ITEM_TYPE = cls
    return BoundedSeqType


class O:
    SOMETHING = 4

class A(O, IntEnum):

    def foo(self) -> int:
        return self.value + 7

    @classmethod
    def bar(cls) -> Self:
        return cls(3)

class W(FixedSize, IntEnum):
    @classmethod
    def foo(cls) -> Self:
        return cls(7)

class X(W):
    x = 7
    y = 9

class B(A):
    x = 3

class C(A):
    y = 4
    x = 10

class _spec_int:
    def __init__(self, length: int) -> None:
        self._length = length

    def __call__[T: int](self, cls: type[T]) -> type[T]:
        def jsonify(self2: T) -> Json:
            return self2
        def from_json(cls2: type[T], obj: Json) -> T:
            if isinstance(obj, int):
                return cls2(obj)
            else:
                raise ValueError
        def pack(self2: T) -> bytes:
            return self2.to_bytes(self._length)
        def unpack(cls2: type[T], raw: bytes) -> T:
            return cls2(int.from_bytes(raw))
        setattr(cls, 'FIXED_SIZE', self._length)
        setattr(cls, 'jsonify', jsonify)
        setattr(cls, 'from_json', classmethod(from_json))
        setattr(cls, 'pack', pack)
        setattr(cls, 'unpack', classmethod(unpack))
        return cls

@_spec_int(2)
class Enum2(FixedSize, IntEnum):
    pass

class Thing2(Enum2):
    x = 10
    y = 20
