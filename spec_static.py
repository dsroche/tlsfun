from typing import Self, BinaryIO, TextIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar
from dataclasses import dataclass, field
import dataclasses
from io import BytesIO
from sys import stdout
from enum import IntEnum
import functools
from textwrap import dedent

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

class FullSpec(Spec):
    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError

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

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError
