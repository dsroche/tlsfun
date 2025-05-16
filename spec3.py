from typing import Self, BinaryIO, Type
from dataclasses import dataclass, fields

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
        if isinstance(self, Json):
            return self
        raise NotImplementedError

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if issubclass(type(obj), cls):
            return cls(obj)
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
    def unpack_from(cls, src: BinaryIO) -> tuple[Self, int]:
        raise NotImplementedError


class _FixedSize:
    def __init__(self, size: int):
        self._size = size

    def __call__(self, cls: type) -> Type[Spec]:
        cls.__annotations__['BYTE_LENGTH'] = int
        setattr(cls, 'BYTE_LENGTH', self._size)

        def unpack_from(cls2: Type[Spec], src: BinaryIO) -> tuple[Spec, int]:
            print("HELLO")
            return cls2.unpack(force_read(src, cls2.BYTE_LENGTH)), cls2.BYTE_LENGTH

        setattr(cls, 'unpack_from', classmethod(unpack_from))

        return cls


@_FixedSize(2)
class Uint16(Spec, int):
    def __new__(cls, value: int):
        if not (0 <= value < 2**16):
            raise ValueError
        return int.__new__(cls, value)

    def pack(self) -> bytes:
        return self.to_bytes(self.BYTE_LENGTH)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls.BYTE_LENGTH:
            raise ValueError
        return Uint16(int.from_bytes(raw))
