from typing import BinaryIO, Any, Type, TypeVar, Protocol, runtime_checkable
from dataclasses import dataclass, fields
from enum import Enum
from io import BytesIO


@runtime_checkable
class _HasValue(Protocol):
    @property
    def value(self) -> Any: ...

@runtime_checkable
@dataclass
class _DcInst(Protocol):
    pass


class UnpackError(ValueError):
    pass


def jsonify(obj, byteslen=None):
    if isinstance(obj, bytes):
        if byteslen is not None and len(obj) > byteslen:
            return f"{obj[:byteslen//2].hex()}...{obj[-byteslen//2:].hex()}"
        else:
            return obj.hex()
    elif isinstance(obj, tuple):
        if hasattr(obj, '_asdict'):
            return jsonify(obj._asdict(), byteslen)
        else:
            return [jsonify(value, byteslen) for value in obj]
    elif isinstance(obj, dict):
        return {key: jsonify(value, byteslen) for key,value in obj.items()}
    elif isinstance(obj, list):
        return [jsonify(value, byteslen) for value in obj]
    else:
        return str(obj)

def pp(obj, byteslen=32, **kwargs):
    pprint.pp(jsonify(obj, byteslen), **kwargs)

def pformat(obj, byteslen=32, **kwargs):
    return pprint.pformat(jsonify(obj, byteslen), sort_dicts=False, **kwargs)


def force_read(src: BinaryIO, size: int) -> bytes:
    got = src.read(size)
    if len(got) != size:
        raise (ValueError if len(got) else EOFError)(f"expected {size} bytes, got {len(got)} bytes {pformat(got)}")
    return got

def force_write(dest: BinaryIO, raw: bytes) -> None:
    written = dest.write(raw)
    if written != len(raw):
        raise BrokenPipeError(f'tried to write {len(raw)} bytes {pformat(raw)}, but only wrote {written}')
    dest.flush()



_SpecT = TypeVar('_SpecT', bound='_Spec')

class _Spec:
    def to_json(self) -> Any:
        raise NotImplementedError

    @classmethod
    def from_json(cls: Type[_SpecT], obj: Any) -> _SpecT:
        raise NotImplementedError

    def packed_size(self) -> int:
        raise NotImplementedError

    def pack(self) -> bytes:
        raise NotImplementedError

    def pack_to(self, ofile: BinaryIO) -> int:
        raw = self.pack()
        force_write(ofile, raw)
        return len(raw)

    @classmethod
    def unpack(cls: Type[_SpecT], raw: bytes) -> _SpecT:
        raise NotImplementedError

    @classmethod
    def unpack_from(cls: Type[_SpecT], ifile: BinaryIO, limit: int|None = None) -> tuple[_SpecT, int]:
        raise NotImplementedError


class _Primitive(_Spec):
    def to_json(self: _HasValue) -> Any:
        return self.value

    @classmethod
    def from_json(cls, obj):
        return cls(obj)

    def __str__(self):
        return str(self.value)


class _FixedSize(_Spec):
    BYTE_LENGTH: int = 0

    def packed_size(self) -> int:
        return self.BYTE_LENGTH

    @classmethod
    def unpack_from(cls, ifile, limit = None):
        if limit is not None and limit < cls.BYTE_LENGTH:
            raise EOFError(f"not enough bytes to unpack: needed {cls.BYTE_LENGTH} but limit is {limit}")
        raw = force_read(ifile, cls.BYTE_LENGTH)
        return (cls.unpack(raw), cls.BYTE_LENGTH)


class _Integral(_Primitive, _FixedSize):
    def __int__(self):
        return self.value

    def pack(self):
        return self.value.to_bytes(self.BYTE_LENGTH)

    @classmethod
    def unpack(cls, raw):
        if len(raw) != cls.BYTE_LENGTH:
            raise UnpackError(f"expected {cls.BYTE_LENGTH} bytes to unpack, got {len(raw)}")
        return cls(int.from_bytes(raw))


class _Integral2(_Integral):
    BYTE_LENGTH = 2


@dataclass(frozen=True)
class _Integer:
    value: int

    def __post_init__(self):
        if not (0 <= self.value < 2**(self.BYTE_LENGTH * 8)):
            raise ValueError(f"value {self.value} outside of range for {type(self).__name__}")

class Integer2(_Integral2, _Integer):
    pass


class _VarSize(_Spec):
    def pack(self):
        buf = BytesIO()
        self.pack_to(buf)
        return buf.getvalue()

    @classmethod
    def unpack(cls, raw):
        buf = BytesIO(raw)
        inst, got = cls.unpack_from(buf, len(raw))
        if got != len(raw):
            raise UnpackError(f"too  many bytes to unpack; got {len(raw)} but only used {got}")
        return inst


class _Struct(_VarSize):
    def to_json(self: _DcInst) -> Any:
        return {fld.name: getattr(self, fld.name).to_json()
                for fld in fields(self)}

    @classmethod
    def from_json(cls: type[_DcInst], obj: Any):
        return cls(**{fld.name: fld.type.from_json(obj[fld.name])
                      for fld in fields(cls)})

    def packed_size(self) -> int:
        return sum(getattr(self, fld.name).packed_size() for fld in fields(self))

    def pack_to(self, ofile):
        size = 0
        for fld in fields(self):
            size += getattr(self, fld.name).pack_to(ofile)
        return size

    @classmethod
    def unpack_from(cls, ifile, limit = None):
        building = {}
        remaining = limit
        got = 0
        for fld in fields(cls):
            building[fld.name], used = fld.type.unpack_from(ifile, remaining)
            if remaining is not None:
                remaining -= used
            got += used
        return (cls(**building), got)


class _Bounded2Struct(_Struct):
    SIZE_TYPE = Integer2

    def packed_size(self):
        return self.SIZE_TYPE.BYTE_LENGTH + super().packed_size()

    def pack_to(self, ofile: BinaryIO) -> int:
        wrote = self.SIZE_TYPE(super().packed_size()).pack_to(ofile)
        wrote += super().pack_to(ofile)
        return wrote

    @classmethod
    def unpack_from(cls: Type[_SpecT], ifile: BinaryIO, limit: int|None) -> tuple[_SpecT, int]:
        remaining = limit
        szobj, got = cls.SIZE_TYPE.unpack_from(ifile, remaining)
        if remaining is not None:
            remaining -= got
        size = szobj.value
        if remaining is not None and remaining < size:
            raise EOFError(f'need at least {size} bytes but only {remaining} remain')
        result, got2 = super().unpack_from(ifile, size)
        if got2 != size:
            raise UnpoackError(f'expected to use {size} bytes but only needed {got2}')
        return (result, got + got2)






class HpkeKdfId(_Integral2, Enum):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003

class HpkeAeadId(_Integral2, Enum):
    AES_128_GCM       = 0x0001
    AES_256_GCM       = 0x0002
    CHACHA20_POLY1305 = 0x0003


@dataclass(frozen=True, kw_only=True)
class HpkeSymmetricCipherSuite(_Struct):
    kdf_id: HpkeKdfId
    aead_id: HpkeAeadId

@dataclass
class A(_Bounded2Struct):
    x : Integer2
    y : Integer2
