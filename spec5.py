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

def write_tuple(items: Iterable[str]) -> str:
    it = iter(items)
    try:
        first = next(it)
    except StopIteration:
        return '()'
    return f"({first}, {', '.join(it)})"

FORCE_RANK = float('inf')

@dataclass(frozen=True)
class NameRank:
    name: str
    rank: float

    def __or__(self, rhs: Self) -> Self:
        if self.rank >= rhs.rank:
            if rhs.rank == FORCE_RANK and rhs.name != self.name:
                raise ValueError(f"can't decide between names {self.name} and {rhs.name} with max rank")
            return self
        else:
            return rhs

class GenSpec:
    def generate(self, dest: TextIO, names: dict['GenSpec',str]) -> None:
        raise NotImplementedError

    def prereqs(self, names: 'Names') -> Iterable[Nested]:
        return ()

    def _name_hint(self, names: 'Names') -> NameRank:
        return NameRank(type(self).__name__, 1)

@dataclass
class Names:
    _order: list[GenSpec] = field(default_factory=list)
    _stubs: dict[GenSpec, NameRank] = field(default_factory=dict)

    def register(self, spec: GenSpec) -> None:
        if spec in self._stubs:
            return # already registered
        for prereq in spec.prereqs(self):
            if isinstance(prereq, GenSpec):
                self.register(prereq)
        self._order.append(spec)
        self._stubs[spec] = spec._name_hint(self)

    def suggest(self, spec: GenSpec, name: NameRank) -> None:
        self.register(spec)
        self._stubs[spec] |= name

    def current_stub(self, item: Nested) -> str:
        match item:
            case GenSpec():
                self.register(item)
                return self._stubs[item].name
            case type():
                return item.__name__
            case str():
                return item

    def assign(self) -> dict[GenSpec,str]:
        counts: Counter[str] = Counter()
        for spec in self._order:
            stub = self._stubs[spec].name
            counts[stub] += 1
        assignment = {}
        for spec in self._order:
            stub = self._stubs[spec].name
            count = counts[stub]
            if count == 1:
                assignment[spec] = stub
                index = 1
            else:
                index = 1 if (count > 1) else -count
                assignment[spec] = f'{stub}_{index}'
            counts[stub] = -index - 1
        return assignment

    def order(self) -> Iterable[GenSpec]:
        yield from self._order

def get_name(names: dict[GenSpec, str], spec: Nested) -> str:
    match spec:
        case GenSpec():
            return names[spec]
        case type():
            return f"{spec.__module__}.{spec.__name__}"
        case str():
            return spec


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
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Integral):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'Uint{self.bit_length}', 100)

@flyweight
@dataclass(frozen=True)
class _FixedX(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Fixed):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'Fixed{self.bit_length}', 100)

@flyweight
@dataclass(frozen=True)
class _SpecEnumX(GenSpec):
    bit_length: int

    @property
    def _parent(self) -> _FixedX:
        return _FixedX(self.bit_length)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
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
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self._parent

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'SpecEnum{self.bit_length}', 90)

@dataclass(frozen=True)
class _EnumSpec(GenSpec):
    _parent: _SpecEnumX
    _missing: str|None
    _members: tuple[tuple[str, int], ...]

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
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
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self._parent

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'Enum{self._parent.bit_length}', 90)

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
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        nn = get_name(names, self.inner_type)
        dest.write(dedent(f"""\
            class {names[self]}({nn}, FullSpec):
                _LENGTH_TYPES: tuple[type[spec_static._Integral],...]

                @override
                def packed_size(self) -> int:
                    return sum(LT._BYTE_LENGTH for LT in self._LENGTH_TYPES) + super().packed_size()

                @override
                def pack(self) -> bytes:
                    raw = super().pack()
                    length = len(raw)
                    parts = [raw]
                    for LT in reversed(self._LENGTH_TYPES):
                        parts.append(LT(length).pack())
                        length += LT._BYTE_LENGTH
                    parts.reverse()
                    return b''.join(parts)

                @override
                def pack_to(self, dest: BinaryIO) -> int:
                    return Spec.pack_to(self, dest)

                @override
                @classmethod
                def unpack(cls, raw: bytes) -> Self:
                    offset = 0
                    for LT in cls._LENGTH_TYPES:
                        lenlen = LT._BYTE_LENGTH
                        if len(raw) < offset + lenlen:
                            raise ValueError
                        length = LT.unpack(raw[offset:offset+lenlen])
                        if len(raw) != offset + lenlen + length:
                            raise ValueError
                        offset += lenlen
                    return super().unpack(raw[offset:])

                @classmethod
                def unpack_from(cls, src: BinaryIO, limit: int|None = None) -> tuple[Self, int]:
                    length: int|None = None
                    readlen = 0
                    for LT in cls._LENGTH_TYPES:
                        len2, lenlen = LT.unpack_from(src, limit)
                        if length is not None and length != lenlen + len2:
                            raise ValueError
                        length = len2
                        readlen += lenlen
                        if limit is not None:
                            limit -= lenlen
                            if limit < length:
                                raise ValueError
                    assert length is not None
                    raw = force_read(src, length)
                    return super().unpack(raw), readlen + length
            """))

    @override
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self.inner_type

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'Bounded{names.current_stub(self.inner_type)}', 80)

@flyweight
@dataclass(frozen=True)
class _Bounded(GenSpec):
    length_types: tuple[Uint,...]
    inner_type: Nested

    @property
    def _parent(self) -> _BoundedX:
        return _BoundedX(self.inner_type)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}):
                _LENGTH_TYPES = {write_tuple(names[lt] for lt in self.length_types)}
            """))

    @override
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self._parent
        yield from self.length_types

    @override
    def _name_hint(self, names: Names) -> NameRank:
        pstub = names.current_stub(self._parent)
        istub = pstub[7:] if pstub.startswith('Bounded') else pstub
        suffix = '_'.join(str(lt.bit_length) for lt in self.length_types)
        return NameRank(f'{istub}{suffix}', 80)

def Bounded(bit_length: int, inner_type: Nested) -> _Bounded:
    lt = Uint(bit_length)
    if isinstance(inner_type, _Bounded):
        return _Bounded((lt,) + inner_type.length_types,
                        inner_type.inner_type)
    else:
        return _Bounded((lt,), inner_type)

@flyweight
@dataclass(frozen=True)
class Sequence(GenSpec):
    item_type: Nested

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        nn = get_name(names, self.item_type)
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Sequence[{nn}]):
                _ITEM_TYPE = {nn}
            """))

    @override
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self.item_type

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'{names.current_stub(self.item_type)}Seq', 80)

@dataclass(frozen=True)
class _Struct(GenSpec):
    schema: tuple[tuple[str, Nested], ...]

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            @dataclass(frozen=True)
            class {names[self]}(spec_static._StructBase):
                _member_names: ClassVar[tuple[str,...]] = ({','.join(repr(name) for (name,_) in self.schema)},)
                _member_types: ClassVar[tuple[type[FullSpec],...]] = ({','.join(get_name(names,typ) for _,typ in self.schema)},)
            """))
        for name,typ in self.schema:
            dest.write(f'    {name}: {get_name(names,typ)}\n')

    @override
    def prereqs(self, names: Names) -> Iterable[Nested]:
        for name,typ in self.schema:
            if isinstance(typ, GenSpec):
                names.suggest(typ, NameRank(name, 20))
            yield typ

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank('Struct', 10)

def Struct(**kwargs: Nested) -> _Struct:
    return _Struct(tuple(kwargs.items()))

@dataclass(frozen=True)
class _SelecteeGen(GenSpec):
    parent: GenSpec
    select_type: Nested
    selection: str
    data_type: Nested

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        sname = get_name(names, self.select_type)
        dname = get_name(names, self.data_type)
        dest.write(dedent(f"""\
            class {names[self]}(spec_static._Selectee[{sname}, {dname}]):
                _SELECTOR = {sname}.{self.selection}
                _DATA_TYPE = {dname}
            """))

    @override
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self.select_type
        yield self.data_type

    @override
    def _name_hint(self, names: Names) -> NameRank:
        return NameRank(f'{self.selection}Selection', 30)

class _SelectActual(GenSpec):
    def __init__(self, select_type: Nested, bit_length: int|None, **kwargs: Nested) -> None:
        self._select_type: Nested = select_type
        self._selectees: dict[str, _SelecteeGen] = {
            key: (_SelecteeGen(self, select_type, key, value)
                  if bit_length is None
                  else _SelecteeGen(self, select_type, key, Bounded(bit_length, value)))
            for (key,value) in kwargs.items()}

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        sname = get_name(names, self._select_type)
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
    def prereqs(self, names: Names) -> Iterable[Nested]:
        yield self._select_type
        for (name,sgen) in self._selectees.items():
            names.suggest(sgen, NameRank(name, 40))
            yield sgen

    @override
    def _name_hint(self, names: Names) -> NameRank:
        sname = names.current_stub(self._select_type)
        return NameRank(sname[:-4]
                        if sname.endswith('Type')
                        else f'{sname}Obj',
                        60)

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
    names: dict[GenSpec,str]
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
            for pre in spec.prereqs(self.ns):
                if isinstance(pre, GenSpec):
                    self.write(pre)
            self._written.add(spec)
            self.dest.write('\n')
            spec.generate(self.dest, self.names)

    def write_all(self, specs: Iterable[GenSpec]) -> None:
        for spec in specs:
            self.write(spec)


def generate_specs(dest: TextIO, **kwargs: GenSpec) -> None:
    ns = Names()

    for (name, spec) in kwargs.items():
        ns.register(spec)
        ns.suggest(spec, NameRank(name, FORCE_RANK))

    names = ns.assign()

    SourceGen(dest, ns, names).write_all(ns.order())
