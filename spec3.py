from typing import Self, BinaryIO, Type, get_args, Iterable
from dataclasses import dataclass, fields
from io import BytesIO

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

    def __init__(self) -> None:
        assert self.FIXED_SIZE >= 0

    def packed_size(self) -> int:
        return self.FIXED_SIZE

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None) -> tuple[Self, int]:
        if limit is not None and limit < cls.FIXED_SIZE:
            raise ValueError
        return cls.unpack(force_read(src, cls.FIXED_SIZE)), cls.FIXED_SIZE


class _Uint(FixedSize, int):
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
    def unpack(cls, raw: bytes) -> Uint16:
        if len(raw) != cls.FIXED_SIZE:
            raise ValueError
        return Uint16(int.from_bytes(raw))


class Uint8(_Uint):
    FIXED_SIZE: int = 1

class Uint16(_Uint):
    FIXED_SIZE: int = 2


class _Sequence[T: Spec](Spec, list[T]):
    ITEM_TYPE: Type[T]

    def __init__(self, values: Iterable[T]) -> None:
        list.__init__(self, values)

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
    def unpack(cls, raw: bytes) -> Self:
        buf = BytesIO(raw)
        building = []
        while buf.tell() < len(raw):
            item, _ = cls.ITEM_TYPE.unpack_from(buf, None)
            building.append(item)
        return cls(building)


class Uint8Seq(_Sequence[Uint8]):
    ITEM_TYPE = Uint8

class Uint16Seq(_Sequence[Uint16]):
    ITEM_TYPE = Uint16


class _Bounded(Uint8Seq):
    LENGTH_TYPE: Type[_Uint] = Uint16

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

class B2U8Seq(Uint8Seq):
    LENGTH_TYPE: Type[_Uint] = Uint16

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
