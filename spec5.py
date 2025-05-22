from typing import Self, BinaryIO, TextIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar, override
from dataclasses import dataclass, field
import dataclasses
from io import BytesIO
from enum import IntEnum
import functools
from textwrap import dedent
import spec_static
from spec_static import *

@dataclass(frozen=True)
class _Name:
    _used: dict[str, int] = field(repr=False)
    _stub: str
    _index: int

    def __str__(self) -> str:
        if self._used[self._stub] == 1:
            return self._stub
        else:
            return f"{self._stub}_{self._index}"

@dataclass(init=False, repr=False, eq=False, match_args=False, unsafe_hash=True)
class GenSpec:
    _name: _Name|None = field(default=None, init=False, hash=False)

    def _name_hint(self) -> str|None:
        return None

    def generate(self, dest: TextIO) -> None:
        raise NotImplementedError

    def prereqs(self) -> Iterable['GenSpec']:
        return ()

class _Names:
    def __init__(self) -> None:
        self._used: dict[str, int] = {}

    def assign_name(self, gs: GenSpec, suggestion: str|None = None) -> None:
        if gs._name is None:
            stub = suggestion
            if stub is None:
                stub = gs._name_hint()
                if stub is None:
                    stub = 'Spec'
            try:
                index = self._used[stub]
            except KeyError:
                index = 0
            self._used[stub] = index + 1
            gs._name = _Name(self._used, stub, index)

def flyweight[T](cls: type[T]) -> type[T]:
    """Decorator to create only one instance of the class with the same init() arguments."""
    original_new = cls.__new__
    new_args = original_new is not object.__new__

    instances: dict[tuple[type[T], tuple[Any,...], frozenset[tuple[str,Any]]], T] = {}

    @functools.wraps(original_new)
    def __new__(cls2: type[T], *args: Any, **kwargs: Any) -> T:
        key = (cls2, args, frozenset(kwargs.items()))
        try:
            return instances[key]
        except KeyError:
            pass
        if new_args:
            instance = original_new(cls2, *args, **kwargs)
        else:
            instance = original_new(cls2)
        instances[key] = instance
        return instance

    def get_instances(cls2: type[T]) -> Iterable[T]:
        return instances.values()

    setattr(cls, '__new__', __new__)
    setattr(cls, 'get_instances', classmethod(get_instances))

    return cls

@flyweight
@dataclass(unsafe_hash=True)
class Uint(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    def _name_hint(self) -> str:
        return f'Uint{self.bit_length}'

    def generate(self, dest: TextIO) -> None:
        assert self._name is not None
        dest.write(dedent(f"""\
            class {self._name}(spec_static._Integral):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

@flyweight
@dataclass
class _FixedX(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    def _name_hint(self) -> str:
        return f'_Fixed{self.bit_length}'

    def generate(self, dest: TextIO) -> None:
        dest.write(dedent(f"""\
            class {self._name}(spec_static._Fixed):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

@flyweight
@dataclass
class _SpecEnumX(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        self._parent: _FixedX = _FixedX(self.bit_length)

    @override
    def _name_hint(self) -> str:
        return f'_SpecEnum{self.bit_length}'

    @override
    def generate(self, dest: TextIO) -> None:
        dest.write(dedent(f"""\
            class {self._name}({self._parent._name}, enum.IntEnum):
                def jsonify(self) -> Json:
                    return self

                @classmethod
                def from_json(cls, obj: Json) -> Self:
                    if isinstance(obj, int):
                        return cls(obj)
                    else:
                        raise ValueError

                def pack(self) -> bytes:
                    return self.to_bytes(self._BYTE_LENGTH)

                @classmethod
                def unpack(cls, raw: bytes) -> Self:
                    if len(raw) != cls._BYTE_LENGTH:
                        raise ValueError
                    return cls(int.from_bytes(raw))
            """))

    @override
    def prereqs(self) -> Iterable[GenSpec]:
        return (self._parent,)

class EnumSpec(GenSpec):
    def __init__(self, bit_length: int, **kwargs: int) -> None:
        self._parent: _SpecEnumX = _SpecEnumX(bit_length)
        self._members: tuple[tuple[str, int], ...] = tuple(kwargs.items())

    @override
    def _name_hint(self) -> str:
        return f'Enumeration{self._parent.bit_length}'

    @override
    def generate(self, dest: TextIO) -> None:
        dest.write(f"class {self._name}({self._parent._name}):\n")
        for (name, value) in self._members:
            dest.write(f"    {name} = {value}\n")

    @override
    def prereqs(self) -> Iterable[GenSpec]:
        yield self._parent

type _Nested = GenSpec | type[Spec] | str

def nested_name_hint(typ: _Nested) -> str:
    match typ:
        case GenSpec():
            hint = typ._name_hint()
            return type(typ).__name__ if hint is None else hint
        case type():
            return typ.__name__
        case str():
            return typ

def nested_name(typ: _Nested) -> str:
    match typ:
        case GenSpec():
            assert typ._name is not None
            return str(typ._name)
        case type():
            return f'{typ.__module__}.{typ.__name__}'
        case str():
            return typ


@flyweight
@dataclass
class _BoundedX(GenSpec):
    inner_type: _Nested

    @override
    def _name_hint(self) -> str:
        return f'_Bounded{nested_name_hint(self.inner_type)}'

    @override
    def generate(self, dest: TextIO) -> None:
        nn = nested_name(self.inner_type)
        dest.write(dedent(f"""\
            class {self._name}(FullSpec, {nn}):
                _LENGTH_TYPE: type[spec_static._Integral]

                def packed_size(self) -> int:
                    return self._LENGTH_TYPE._BYTE_LENGTH + super().packed_size()

                def pack(self) -> bytes:
                    raw = super().pack()
                    return self._LENGTH_TYPE(len(raw)).pack() + raw

                def pack_to(self, dest: BinaryIO) -> int:
                    raw = super().pack()
                    return (
                        self._LENGTH_TYPE(super().packed_size()).pack_to(dest)
                        + super().pack_to(dest))

                @classmethod
                def unpack(cls, raw: bytes) -> Self:
                    lenlen = cls._LENGTH_TYPE._BYTE_LENGTH
                    if len(raw) < lenlen:
                        raise ValueError
                    length = cls._LENGTH_TYPE.unpack(raw[:lenlen])
                    if len(raw) != lenlen + length:
                        raise ValueError
                    return cls({nn}.unpack(raw[lenlen:]))

                @classmethod
                def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
                    length, lenlen = cls._LENGTH_TYPE.unpack_from(src, limit)
                    if limit is not None and limit - lenlen < length:
                        raise ValueError
                    raw = force_read(src, length)
                    return cls({nn}.unpack(raw)), lenlen + length
            """))

    @override
    def prereqs(self) -> Iterable[GenSpec]:
        if isinstance(self.inner_type, GenSpec):
            yield self.inner_type

@flyweight
@dataclass
class Bounded(GenSpec):
    bit_length: int
    inner_type: _Nested

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0
        self._length_type: GenSpec = Uint(self.bit_length)
        self._parent = _BoundedX(self.inner_type)

    @override
    def _name_hint(self) -> str:
        return f'{nested_name_hint(self.inner_type)}{self.bit_length}'

    @override
    def generate(self, dest: TextIO) -> None:
        dest.write(dedent(f"""\
            class {self._name}({nested_name(self._parent)}):
                _LENGTH_TYPE = {self._length_type._name}
            """))

    @override
    def prereqs(self) -> Iterable[GenSpec]:
        yield self._length_type
        yield self._parent

@flyweight
@dataclass(unsafe_hash=True)
class Sequence(GenSpec):
    item_type: _Nested

    @override
    def _name_hint(self) -> str:
        return f'{nested_name_hint(self.item_type)}Seq'

    @override
    def generate(self, dest: TextIO) -> None:
        nn = nested_name(self.item_type)
        dest.write(dedent(f"""\
            class {self._name}(spec_static._Sequence[{nn}]):
                _ITEM_TYPE = {nn}
            """))

@dataclass
class _Struct(GenSpec):
    schema: tuple[tuple[str, _Nested], ...]

    @override
    def _name_hint(self) -> str:
        return 'Struct'

    @override
    def generate(self, dest: TextIO) -> None:
        dest.write(dedent(f"""\
            @dataclass(frozen=True)
            class {self._name}(spec_static._StructBase):
                _member_names: ClassVar[tuple[str,...]] = ({','.join(repr(name) for (name,_) in self.schema)},)
                _member_types: ClassVar[tuple[type[FullSpec],...]] = ({','.join(nested_name(typ) for _,typ in self.schema)},)
            """))
        for name,typ in self.schema:
            dest.write(f'    {name}: {nested_name(typ)}\n')

    @override
    def prereqs(self) -> Iterable[GenSpec]:
        for _,typ in self.schema:
            if isinstance(typ, GenSpec):
                yield typ

def Struct(**kwargs: _Nested) -> _Struct:
    return _Struct(tuple(kwargs.items()))

@flyweight
@dataclass
class TODO(GenSpec):
    @override
    def _name_hint(self) -> str:
        raise NotImplementedError
    @override
    def generate(self, dest: TextIO) -> None:
        raise NotImplementedError
    @override
    def prereqs(self) -> Iterable[GenSpec]:
        raise NotImplementedError


def generate_specs(dest: TextIO, **kwargs: GenSpec) -> None:
    ns = _Names()
    togen: list[GenSpec] = []
    genset: set[int] = set()

    def crawl(spec: GenSpec) -> None:
        if id(spec) not in genset:
            genset.add(id(spec))
            for pre in spec.prereqs():
                ns.assign_name(pre)
                crawl(pre)
            togen.append(spec)

    for name, spec in kwargs.items():
        ns.assign_name(spec, name)
        crawl(spec)

    dest.write(dedent('''\
        # XXX AUTO-GENERATED - DO NOT EDIT! XXX
        from typing import Self, override, BinaryIO, ClassVar
        import enum
        import dataclasses
        from dataclasses import dataclass
        import spec_static
        from spec_static import *
        '''))

    for spec in togen:
        dest.write('\n')
        spec.generate(dest)
