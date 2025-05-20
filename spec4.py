from typing import Self, BinaryIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar
from dataclasses import dataclass
import dataclasses
from io import BytesIO
from enum import IntEnum

from tls_common import *

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

@dataclass(frozen=True)
class _Has_Value[T](Protocol):
    value: T

class Spec[T](_Has_Value[T]):
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
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        raise NotImplementedError

@dataclass(frozen=True)
class FixedSize[T](Spec[T]):
    _FIXED_SIZE: ClassVar[int]

    def packed_size(self) -> int:
        return self._FIXED_SIZE

    @classmethod
    def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
        if limit is not None and limit < cls._FIXED_SIZE:
            raise ValueError
        raw = force_read(src, cls._FIXED_SIZE)
        return cls.unpack(raw), cls._FIXED_SIZE

class Primitive[T: (int | str)](Spec[T]):
    def jsonify(self) -> Json:
        return self.value

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        try:
            return cls(value=obj) # type: ignore
        except (ValueError, TypeError):
            raise ValueError from None

class Uint(Primitive[int], FixedSize[int]):
    def __post_init__(self) -> None:
        if not (0 <= self.value < 2**(self._FIXED_SIZE * 8)):
            raise ValueError

    def pack(self) -> bytes:
        return self.value.to_bytes(self._FIXED_SIZE)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        if len(raw) != cls._FIXED_SIZE:
            raise ValueError
        return cls(value=int.from_bytes(raw))

@dataclass(frozen=True)
class Uint8(Uint):
    _FIXED_SIZE = 1

@dataclass(frozen=True)
class Uint16(Uint):
    _FIXED_SIZE = 2

@dataclass(frozen=True)
class Raw(Spec[bytes]):
    value: bytes

    def jsonify(self) -> Json:
        return self.value.hex()

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if isinstance(obj, str):
            return cls(value=bytes.fromhex(obj))
        raise ValueError

    def packed_size(self) -> int:
        return len(self.value)

    def pack(self) -> bytes:
        return self.value

    def pack_to(self, dest: BinaryIO) -> int:
        force_write(dest, self.value)
        return len(self.value)

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(value=raw)

@dataclass(frozen=True)
class String(Primitive[str]):
    value: str

    def pack(self) -> bytes:
        return self.value.encode('utf8')

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        return cls(raw.decode('utf8'))

def Sequence[T: Spec[Any]](item_cls: type[T]) -> type[Spec[tuple[T,...]]]:
    @dataclass(frozen=True)
    class SequenceType(Spec[tuple[T,...]]):
        value: tuple[T,...]

        def jsonify(self) -> Json:
            return list(item.jsonify() for item in self.value)

        @classmethod
        def from_json(cls, obj: Json) -> Self:
            if isinstance(obj, list):
                return cls(value=tuple(item_cls.from_json(item)
                                       for item in obj))
            raise ValueError

        def packed_size(self) -> int:
            return sum(item.packed_size() for item in self.value)

        def pack(self) -> bytes:
            return b''.join(item.pack() for item in self.value)

        def pack_to(self, dest: BinaryIO) -> int:
            return sum(item.pack_to(dest) for item in self.value)

        @classmethod
        def _unpack_items(cls, raw: bytes) -> Iterable[T]:
            src = BytesIO(raw)
            remain = len(raw)
            while remain > 0:
                item, got = item_cls.unpack_from(src, remain)
                yield item
                remain -= got

        @classmethod
        def unpack(cls, raw: bytes) -> Self:
            return cls(value=tuple(cls._unpack_items(raw)))

    SequenceType.__name__ = f'Sequence({item_cls.__name__})' #TODO fix repr stuff
    return SequenceType

def Bounded[T](length_cls: type[Uint], inner_cls: type[Spec[T]]) -> type[Spec[T]]:
    lenlen = length_cls._FIXED_SIZE

    @dataclass(frozen=True)
    class BoundedType(Spec[T]):
        def _inner(self) -> Spec[T]:
            return inner_cls(value = self.value)

        @classmethod
        def _outer(cls, item: Spec[T]) -> Self:
            return cls(value = item.value)

        def jsonify(self) -> Json:
            return self._inner().jsonify()

        @classmethod
        def from_json(cls, obj: Json) -> Self:
            return cls._outer(inner_cls.from_json(obj))

        def packed_size(self) -> int:
            return lenlen + self._inner().packed_size()

        def pack(self) -> bytes:
            raw = self._inner().pack()
            return length_cls(len(raw)).pack() + raw

        def pack_to(self, dest: BinaryIO) -> int:
            return (length_cls(self._inner().packed_size()).pack_to(dest)
                    + self._inner().pack_to(dest))

        @classmethod
        def unpack(cls, raw: bytes) -> Self:
            if len(raw) < lenlen:
                raise ValueError
            length = length_cls.unpack(raw[:lenlen]).value
            if len(raw) != lenlen + length:
                raise ValueError
            return cls._outer(inner_cls.unpack(raw[lenlen:]))

        @classmethod
        def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
            len_obj, got1 = length_cls.unpack_from(src, limit)
            length = len_obj.value
            if limit is not None and limit < got1 + length:
                raise ValueError
            raw = force_read(src, length)
            return cls._outer(inner_cls.unpack(raw)), got1 + length

    return BoundedType

Raw8 = Bounded(Uint8, Raw)
Raw16 = Bounded(Uint16, Raw)
String8 = Bounded(Uint8, String)
String16 = Bounded(Uint16, String)

''' FIXME
def Seq8[T](inner_cls: type[T]) -> type[Spec[tuple[T,...]]]:
    return Bounded(Uint8, Sequence(inner_cls))
def Seq16[T](inner_cls: type[T]) -> type[Spec[tuple[T,...]]]:
    return Bounded(Uint16, Sequence(inner_cls))
'''

def Seq16[T](inner_cls: type[T]) -> type[Spec[tuple[T,...]]]:
    return Bounded(Uint16, Sequence(inner_cls)) # type: ignore

def all_tests() -> None:
    #A = Bounded(Uint16, Sequence(Uint8))
    A = Seq16(Uint8)
    test_spec(A, (Uint8(10), Uint8(20)), [10,20], '00020a14')
    test_spec(Uint8, 33, 33, '21')
    test_spec(Uint16, 50, 50, '0032')
    test_spec(Raw8, b'abc', '616263', '03616263')
    test_spec(Raw16, b'', '', '0000')
    test_spec(String8, 'abcd', 'abcd', '0461626364')
    test_spec(String16, 'bb', 'bb', '00026262')

def check[T](a: T, b: T) -> None:
    if isinstance(a, bytes) and isinstance(b, bytes):
        check(a.hex(), b.hex())
    elif a != b:
        raise AssertionError(f'got {a} expected {b}')

def test_spec[T](
    cls: type[Spec[T]],
    orig: T,
    js: Json,
    rawhex: str,
    streaming: bool = True,
) -> None:
    raw = bytes.fromhex(rawhex)
    a = cls(value=orig)
    check(a.jsonify(), js)
    check(cls.from_json(js).jsonify(), js)
    check(a.pack(), raw)
    check(a.unpack(raw).pack(), raw)
    check(a.packed_size(), len(raw))
    if streaming:
        buf = BytesIO()
        a.pack_to(buf)
        check(buf.getvalue(), raw)
        buf.seek(0)
        item, count = cls.unpack_from(buf)
        check(count, len(raw))
        check(item.jsonify(), js)

if __name__ == '__main__':
    all_tests()
    print('all tests passed')

''' TODO



'''

'''


class Raw8(_Bounded, Raw):
    LENGTH_TYPE = Uint8

class Raw16(_Bounded, Raw):
    LENGTH_TYPE = Uint16

class String8(_Bounded, String):
    LENGTH_TYPE = Uint8

def BoundedSeq[T: Spec](length_type: type[Uint], cls: type[T]) -> type[_Sequence[T]]:
    class BoundedSeqType(_Bounded, _Sequence[T]):
        LENGTH_TYPE = length_type
        ITEM_TYPE = cls
    return BoundedSeqType


class _spec_int:
    """Decorator for IntEnum based enumerations.
    Essentially the same as Uint, but needs to be in a decorator
    because the order of inheritance is different.
    (In turn, because subclasses of Enum can't have declared class fields
    like FIXED_LENGTH.)
    """
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

class unknown:
    """Decorator for enums to produce a warning and a default member
    when an unrecognized constant value is seen."""
    def __init__(self, default: str) -> None:
        self._default = default

    def __call__[T: IntEnum](self, cls: type[T]) -> type[T]:
        default: T = getattr(cls, self._default)
        def missing(cls2: type[T], value: Any) -> T:
            logger.warn(f"Unexpected value {value} for {cls2}; returning {repr(default)}")
            return default
        setattr(cls, '_missing_', classmethod(missing))
        return cls


@_spec_int(1)
class Enum8(FixedSize, IntEnum):
    """Base class for enumerations with 8-bit encodings."""

@_spec_int(2)
class Enum16(FixedSize, IntEnum):
    """Base class for enumerations with 16-bit encodings."""
    pass


@dataclass_transform(frozen_default=True, kw_only_default=True)
def Struct2[T: Spec](cls0: type[T]) -> type[T]:
    @dataclass(frozen=True, kw_only=True)
    class StructBase(Spec):
        _x: ClassVar[list[str]] = []
    cls1 = type(cls0.__name__, (StructBase, cls0), {})
    cls2: type[T] = dataclass(frozen=True, kw_only=True)(cls1)
    return cls2

@Struct2
class C(Spec):
    x : Uint8
    y : String8


@dataclass(frozen=True, kw_only=True)
class StructBase(Spec):
    _struct_types: ClassVar[list[tuple[str, type[Spec]]]] = []
    _struct_members: list[tuple[str, Spec]] = dataclasses.field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for (name, typ) in self._struct_types:
            member = getattr(self, name)
            if isinstance(member, typ):
                self._struct_members.append((name, member))
            else:
                raise ValueError(f'expected {typ}, got {repr(member)}')

    def jsonify(self) -> Json:
        return {name: member.jsonify()
                for (name, member) in self._struct_members}

    @classmethod
    def from_json(cls, obj: Json) -> Self:
        if not isinstance(obj, dict):
            raise ValueError
        building: dict[str, Spec] = {}
        for (name, typ) in cls._struct_types:
            building[name] = typ.from_json(obj[name])
        # NB mypy doesn't understand dataclass constructors
        return cls(**building) # type: ignore

    def packed_size(self) -> int:
        return sum(member.packed_size()
                   for (_, member) in self._struct_members)

    def pack(self) -> bytes:
        return b''.join(member.pack()
                        for (_, member) in self._struct_members)

    def pack_to(self, dest: BinaryIO) -> int:
        written = 0
        for (_, member) in self._struct_members:
            written += member.pack_to(dest)
        return written

    @classmethod
    def unpack(cls, raw: bytes) -> Self:
        kwargs: dict[str, Spec] = {}
        buf = BytesIO(raw)
        for (name, typ) in cls._struct_types:
            kwargs[name], _ = typ.unpack_from(buf, None)
        # NB mypy doesn't understand dataclass constructors
        return cls(**kwargs) # type: ignore


@dataclass_transform(frozen_default=True, kw_only_default=True)
def Struct[T: StructBase](cls: type[T]) -> type[T]:
    cls1 = dataclass(frozen=True)(cls)
    for fld in dataclasses.fields(cls1):
        if fld.name == '_struct_members':
            continue
        elif isinstance(fld.type, type) and issubclass(fld.type, Spec):
            cls1._struct_types.append((fld.name, fld.type))
        else:
            raise TypeError("fields of Struct must be Spec subclasses.")
    return cls1


class HpkeKdfId(Enum16):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003

class HpkeAeadId(Enum16):
    AES_128_GCM       = 0x0001
    AES_256_GCM       = 0x0002
    CHACHA20_POLY1305 = 0x0003

class HpkeKemId(Enum16):
    DHKEM_P256_HKDF_SHA256   = 0x0010
    DHKEM_P384_HKDF_SHA384   = 0x0011
    DHKEM_P521_HKDF_SHA512   = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512   = 0x0021

@unknown('UNSUPPORTED')
class ECHConfigExtensionType(Enum16):
    UNSUPPORTED = 0xffff

@Struct
class HpkeSymmetricCipherSuite(StructBase):
    kdf_id  : HpkeKdfId
    aead_id : HpkeAeadId

@Struct
class ECHExtension(StructBase):
    typ  : ECHConfigExtensionType
    data : Raw16

class HpkeSymmetricCipherSuiteList(_Bounded, _Sequence[HpkeSymmetricCipherSuite]):
    LENGTH_TYPE = Uint16
    ITEM_TYPE = HpkeSymmetricCipherSuite


@BS(Uint16, ECHExtension)
class ECHExtensionList:
    pass

@Struct
class ECHKeyConfig(StructBase):
    config_id     : Uint8
    kem_id        : HpkeKemId
    public_key    : Raw16
    #cipher_suites : BoundedSeq(Uint16, HpkeSymmetricCipherSuite)
    cipher_suites : HpkeSymmetricCipherSuiteList #FIXME

@Struct
class ECHConfigExtension(StructBase):
    typ : ECHConfigExtensionType
    data : Raw16

@Struct
class ECHConfig24(StructBase):
    key_config : ECHKeyConfig
    maximum_name_length : Uint8
    public_name : String8
    extensions : ECHExtensionList

################XXX
@Struct
class A(StructBase):
    x : Uint16
    y : String8

#a = A.from_json({'x': 3, 'y': 'hello'})
################XXX
'''
