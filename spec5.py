from typing import Self, BinaryIO, TextIO, get_args, Iterable, Protocol, Any, dataclass_transform, ClassVar, override
from dataclasses import dataclass, field
import dataclasses
from collections import Counter
from io import BytesIO
from enum import IntEnum
import functools
from textwrap import indent, dedent
import spec_static
from spec_static import *

type Nested = 'GenSpec' | type[Spec] | str

@dataclass
class Names:
    _stubs: dict['GenSpec', tuple[str, int]] = field(default_factory=dict)
    _counts: Counter[str] = field(default_factory=Counter)
    _assigned: bool = field(default=False)

    def stub(self, item: Nested, suggestion: str|None = None) -> str:
        match item:
            case GenSpec():
                self.register(item, suggestion)
                return self._stubs[item][0]
            case type():
                return item.__name__
            case str():
                return item

    def register(self, item: 'GenSpec', suggestion: str|None) -> None:
        if item in self._stubs:
            return # already registered
        if self._assigned:
            raise ValueError("Can't register new item after assigning names")
        prereq_stubs = [self.stub(prereq, psug)
                        for (prereq, psug) in item.prereqs()]
        stub = item._name_hint(prereq_stubs) if suggestion is None else suggestion
        count = self._counts[stub] + 1
        self._counts[stub] = count
        self._stubs[item] = (stub, count)

    def assign(self) -> None:
        self._assigned = True

    def __getitem__(self, item: Nested) -> str:
        if not self._assigned:
            raise ValueError("Can't get item names before calling .assign()")
        match item:
            case GenSpec():
                (stub, count) = self._stubs[item]
                if self._counts[stub] > 1:
                    return f"{stub}_{count}"
                else:
                    return stub
            case type():
                return item.__name__
            case str():
                return item

class GenSpec:
    def generate(self, dest: TextIO, names: Names) -> None:
        raise NotImplementedError

    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        return ()

    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return type(self).__name__

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
@dataclass(frozen=True)
class Uint(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Integral):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return f'Uint{self.bit_length}'

@flyweight
@dataclass(frozen=True)
class _FixedX(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Fixed):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return f'Fixed{self.bit_length}'

@flyweight
@dataclass(frozen=True)
class _SpecEnumX(GenSpec):
    bit_length: int

    @property
    def _parent(self) -> _FixedX:
        return _FixedX(self.bit_length)

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}, spec_static._SpecEnum):
                def jsonify(self) -> Json:
                    return self.name

                @classmethod
                def from_json(cls, obj: Json) -> Self:
                    if isinstance(obj, int):
                        return cls(obj)
                    elif isinstance(obj, str):
                        return cls[obj]
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
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self._parent, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return f'_SpecEnum{self.bit_length}'

@dataclass(frozen=True)
class _EnumSpec(GenSpec):
    _parent: _SpecEnumX
    _missing: str|None
    _members: tuple[tuple[str, int], ...]

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(f"class {names[self]}({names[self._parent]}):\n")
        for (name, value) in self._members:
            dest.write(f"    {name} = {value}\n")
        if self._missing is not None:
            dest.write(indent(dedent(f"""\
                @classmethod
                def _missing_(cls, value: Any) -> Self:
                    logger.warn(f"WARNING: Unrecognized {{cls.__name__}} value {{value}}")
                    return cls[{repr(self._missing)}]
                """), '    '))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self._parent, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return f'Enumeration{self._parent.bit_length}'

@dataclass
class EnumSpec:
    bit_length: int
    missing: str|None = None

    def __call__(self, **kwargs: int) -> _EnumSpec:
        return _EnumSpec(
            _parent = _SpecEnumX(self.bit_length),
            _missing = self.missing,
            _members = tuple(kwargs.items()),
        )


@flyweight
@dataclass(frozen=True)
class _BoundedX(GenSpec):
    inner_type: Nested

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        nn = names[self.inner_type]
        dest.write(dedent(f"""\
            class {names[self]}({nn}, FullSpec):
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
                    return super().unpack(raw[lenlen:])

                @classmethod
                def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
                    length, lenlen = cls._LENGTH_TYPE.unpack_from(src, limit)
                    if limit is not None and limit - lenlen < length:
                        raise ValueError
                    raw = force_read(src, length)
                    return super().unpack(raw), lenlen + length
            """))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self.inner_type, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        [istub] = pstubs
        return f'Bounded{istub}'

@flyweight
@dataclass(frozen=True)
class Bounded(GenSpec):
    bit_length: int
    inner_type: Nested

    @property
    def _length_type(self) -> Uint:
        return Uint(self.bit_length)

    @property
    def _parent(self) -> _BoundedX:
        return _BoundedX(self.inner_type)

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}):
                _LENGTH_TYPE = {names[self._length_type]}
            """))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self._length_type, None)
        yield (self._parent, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        [_, pstub] = pstubs
        istub = pstub[7:] if pstub.startswith('Bounded') else pstub
        return f'{istub}{self.bit_length}'

@flyweight
@dataclass(frozen=True)
class Sequence(GenSpec):
    item_type: Nested

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        nn = names[self.item_type]
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Sequence[{nn}]):
                _ITEM_TYPE = {nn}
            """))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self.item_type, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        [istub] = pstubs
        return f'{istub}Seq'

@dataclass(frozen=True)
class _Struct(GenSpec):
    schema: tuple[tuple[str, Nested], ...]

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        dest.write(dedent(f"""\
            @dataclass(frozen=True)
            class {names[self]}(spec_static._StructBase):
                _member_names: ClassVar[tuple[str,...]] = ({','.join(repr(name) for (name,_) in self.schema)},)
                _member_types: ClassVar[tuple[type[FullSpec],...]] = ({','.join(names[typ] for _,typ in self.schema)},)
            """))
        for name,typ in self.schema:
            dest.write(f'    {name}: {names[typ]}\n')

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        for name,typ in self.schema:
            yield (typ, name)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return 'Struct'

def Struct(**kwargs: Nested) -> _Struct:
    return _Struct(tuple(kwargs.items()))

@dataclass(frozen=True)
class _SelecteeGen(GenSpec):
    parent: GenSpec
    select_type: Nested
    selection: str
    data_type: Nested

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        sname = names[self.select_type]
        dname = names[self.data_type]
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Selectee[{sname}, {dname}]):
                _SELECTOR = {sname}.{self.selection}
                _DATA_TYPE = {dname}
            """))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self.select_type, None)
        yield (self.data_type, None)

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        return f'{self.selection}Selection'

class _SelectActual(GenSpec):
    def __init__(self, select_type: Nested, bit_length: int|None, **kwargs: Nested) -> None:
        self._select_type: Nested = select_type
        self._selectees: dict[str, _SelecteeGen] = {
            key: (_SelecteeGen(self, select_type, key, value)
                  if bit_length is None
                  else _SelecteeGen(self, select_type, key, Bounded(bit_length, value)))
            for (key,value) in kwargs.items()}

    @override
    def generate(self, dest: TextIO, names: Names) -> None:
        sname = names[self._select_type]
        tname = f'{names[self]}Variants'
        dest.write(dedent(f"""\
            type {tname} = {' | '.join(str(names[s]) for s in self._selectees.values())}

            class {names[self]}(spec_static._Select[{sname}]):
                _SELECT_TYPE = {sname}
                _SELECTEES = {{
            """))
        for key, s in self._selectees.items():
            dest.write(f"        {sname}.{key}: {names[s]},\n")
        dest.write("    }\n")
        dest.write(indent("    ", dedent(f"""\
                def __init__(self, value: {tname}) -> None:
                    super().__init__(value)
                    self._value: {tname} = value
                @property
                def value(self) -> {tname}:
                    return self._value
            """)))

    @override
    def prereqs(self) -> Iterable[tuple[Nested, str|None]]:
        yield (self._select_type, None)
        for s in self._selectees.values():
            yield (s, None) #TODO fill something in here for a name hint?? XXX

    @override
    def _name_hint(self, pstubs: Iterable[str]) -> str:
        sname = next(iter(pstubs))
        return sname[:-4] if sname.endswith('Type') else f'{sname}Obj'

@dataclass
class Select:
    select_type: Nested
    bit_length: int|None = field(default=None)

    def __call__(self, **kwargs: Nested) -> _SelectActual:
        return _SelectActual(self.select_type, self.bit_length, **kwargs)


@dataclass
class SourceGen:
    dest: TextIO
    ns: Names
    _written: set[GenSpec] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.dest.write(dedent('''
            # XXX AUTO-GENERATED - DO NOT EDIT! XXX
            from typing import Self, override, BinaryIO, ClassVar, Any
            import enum
            import dataclasses
            from dataclasses import dataclass
            import spec_static
            from spec_static import *
            '''))

    def write(self, spec: GenSpec) -> None:
        if spec not in self._written:
            for (pre, _) in spec.prereqs():
                if isinstance(pre, GenSpec):
                    self.write(pre)
            self._written.add(spec)
            self.dest.write('\n')
            spec.generate(self.dest, self.ns)

    def write_all(self, specs: Iterable[GenSpec]) -> None:
        for spec in specs:
            self.write(spec)


def generate_specs(dest: TextIO, **kwargs: GenSpec) -> None:
    ns = Names()
    togen: list[GenSpec] = []

    for (name, spec) in kwargs.items():
        ns.register(spec, name)
        togen.append(spec)

    ns.assign()

    SourceGen(dest, ns).write_all(togen)
