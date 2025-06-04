from typing import Self, BinaryIO, TextIO, Any, override
from collections.abc import Iterable
from functools import cached_property
from dataclasses import dataclass, field
from collections import Counter
from textwrap import indent, dedent
from util import (
    flyweight,
    write_tuple,
    exact_lstrip,
    exact_rstrip,
    camel_case,
)
from spec import Spec

type Nested = 'GenSpec' | type[Spec] | str

FORCE_RANK = float('inf')

@dataclass
class NameRank:
    name: str = field(default='Spec')
    rank: float = field(default=0.0)

    def update(self, name2: str, rank2: float|None = None) -> bool:
        if rank2 is None:
            rank2 = self.rank
        if rank2 >= self.rank:
            if self.rank == FORCE_RANK and name2 != self.name:
                raise ValueError(f"can't decide between names {self.name} and {name2} with max rank")
            self.name = name2
            self.rank = rank2
            return True
        else:
            return False

@dataclass(frozen=True)
class GenSpec:
    _name_stub: NameRank = field(default_factory=NameRank, kw_only=True, hash=False, compare=False)

    @property
    def stub(self) -> str:
        return self._name_stub.name

    @property
    def stub_rank(self) -> float:
        return self._name_stub.rank

    def update_stub(self, name: str, rank: float) -> bool:
        return self._name_stub.update(name, rank)

    def suggest(self, name: str, rank: float) -> bool:
        return self.update_stub(name, rank)

    def generate(self, dest: TextIO, names: dict['GenSpec',str]) -> None:
        raise NotImplementedError

    def prereqs(self) -> Iterable[Nested]:
        return ()

    def create_from(self, names: dict['GenSpec',str]) -> str|None:
        return None

def get_stub(typ: Nested) -> str:
    match typ:
        case GenSpec():
            return typ.stub
        case type():
            return typ.__name__
        case str():
            return typ

def get_name(spec: Nested|type[Any], names: dict[GenSpec, str]) -> str:
    match spec:
        case GenSpec():
            return names[spec]
        case type():
            mod = spec.__module__
            if mod == 'builtins':
                return spec.__name__
            else:
                return f'{mod}.{spec.__name__}'
        case str():
            return spec

def maybe_suggest(typ: Nested, name: str, rank: float) -> bool:
    if isinstance(typ, GenSpec):
        return typ.suggest(name, rank)
    elif rank == FORCE_RANK and name != get_stub(typ):
        raise ValueError(f"Can't force name of {get_stub(typ)} to {name}")
    else:
        return False

def get_create_from(typ: Nested, names: dict[GenSpec,str]) -> str|None:
    match typ:
        case GenSpec():
            return typ.create_from(names)
        case type():
            cft = typ._CREATE_FROM
            if cft is None:
                return None
            return get_name(cft, names)
        case str():
            return None # TODO try to resolve names??

@flyweight
@dataclass(frozen=True)
class Wrap(GenSpec):
    inner_type: Nested

    def __post_init__(self) -> None:
        self.update_stub(f'Wrap{get_stub(self.inner_type)}', 30)

    @override
    def create_from(self, names: dict[GenSpec,str]) -> str|None:
        return get_create_from(self.inner_type, names)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif maybe_suggest(self.inner_type, name, min(rank, 90)):
            return self.update_stub(f'Wrap{get_stub(self.inner_type)}', 30)
        else:
            return False

    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dt = get_name(self.inner_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._Wrapper[{get_name(self.inner_type, names)}]):
                _DATA_TYPE = {dt}
            """))
        cfn = self.create_from(names)
        if cfn is not None:
            dest.write(indent(dedent(f"""\
                _CREATE_FROM = {cfn}
                @classmethod
                def create(cls, value: {cfn}) -> Self:
                    return cls(data={dt}.create(value))
                """), '    '))

    def prereqs(self) -> Iterable[Nested]:
        yield self.inner_type


@flyweight
@dataclass(frozen=True)
class Uint(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0
        self.suggest(f'Uint{self.bit_length}', 100)

    @override
    def create_from(self, names: dict[GenSpec,str]) -> str:
        return 'int'

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec._Integral):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

@flyweight
@dataclass(frozen=True)
class _FixedX(GenSpec):
    bit_length: int

    def __post_init__(self) -> None:
        assert self.bit_length >= 0 and self.bit_length % 8 == 0
        self.suggest(f'Fixed{self.bit_length}', 100)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec._Fixed):
                _BYTE_LENGTH = {self.bit_length // 8}
            """))

@flyweight
@dataclass(frozen=True)
class FixRaw(GenSpec):
    byte_length: int

    def __post_init__(self) -> None:
        assert self.byte_length >= 0
        self.update_stub(f'F{self.byte_length}Raw', 100)

    @override
    def create_from(self, names: dict[GenSpec,str]) -> str:
        return 'bytes'

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}(spec._FixRaw):
                _BYTE_LENGTH = {self.byte_length}
            """))


@flyweight
@dataclass(frozen=True)
class _SpecEnumX(GenSpec):
    bit_length: int

    @property
    def _parent(self) -> _FixedX:
        return _FixedX(self.bit_length)

    def __post_init__(self) -> None:
        self.suggest(f'Enum{self.bit_length}', 100)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}, spec._SpecEnum):
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
    def prereqs(self) -> Iterable[Nested]:
        yield self._parent


@dataclass(frozen=True)
class _EnumSpec(GenSpec):
    _parent: _SpecEnumX
    _missing: str|None
    _members: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        self.suggest('EnumSpec', 5)

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
    def prereqs(self) -> Iterable[Nested]:
        yield self._parent

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

    def __post_init__(self) -> None:
        self.update_stub(f'Bounded{get_stub(self.inner_type)}', 70)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif maybe_suggest(self.inner_type, name, min(90, rank)):
            return self.update_stub(f'Bounded{get_stub(self.inner_type)}', 70)
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        nn = get_name(self.inner_type, names)
        dest.write(dedent(f"""\
            class {names[self]}({nn}, FullSpec):
                _LENGTH_TYPES: tuple[type[spec._Integral],...]

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
    def prereqs(self) -> Iterable[Nested]:
        yield self.inner_type

@flyweight
@dataclass(frozen=True)
class _Bounded(GenSpec):
    length_types: tuple[Uint,...]
    inner_type: Nested

    @property
    def _parent(self) -> _BoundedX:
        return _BoundedX(self.inner_type)

    @override
    def create_from(self, names: dict[GenSpec,str]) -> str|None:
        return get_create_from(self.inner_type, names)

    def _restub(self) -> bool:
        pstub = exact_lstrip(self._parent.stub, 'Bounded')
        prefix = ''.join(f'B{lt.bit_length}' for lt in self.length_types)
        return self.update_stub(f'{prefix}{pstub}', 70)

    def __post_init__(self) -> None:
        self._restub()

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif self._parent.suggest(name, min(rank, 90)):
            return self._restub()
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}):
                _LENGTH_TYPES = {write_tuple(names[lt] for lt in self.length_types)}
            """))

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self._parent
        yield from self.length_types

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

    def _name_suggestion(self) -> str:
        return f'Seq{get_stub(self.item_type)}'

    def __post_init__(self) -> None:
        self.update_stub(self._name_suggestion(), 70)

    def create_from_inner(self, names: dict[GenSpec,str]) -> str|None:
        return get_create_from(self.item_type, names)

    @override
    def create_from(self, names: dict[GenSpec,str]) -> str:
        icf = self.create_from_inner(names)
        if icf is None:
            icf = get_name(self.item_type, names)
        return f'Iterable[{icf}]'

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif maybe_suggest(self.item_type, exact_rstrip(name, 's'), min(rank, 90)):
            return self.update_stub(self._name_suggestion(), 70)
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        nn = get_name(self.item_type, names)
        cft = self.create_from(names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._Sequence[{nn}]):
                _CREATE_FROM = {cft}
                _ITEM_TYPE = {nn}
            """))
        if self.create_from_inner(names):
            dest.write(indent(dedent(f"""
                @classmethod
                def create(cls, value: {cft}) -> Self:
                    return cls({nn}.create(v) for v in value)
                """), '    '))
        else:
            dest.write(indent(dedent(f"""
                @classmethod
                def create(cls, value: {cft}) -> Self:
                    return cls(value)
                """), '    '))

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self.item_type

@dataclass(frozen=True)
class _Struct(GenSpec):
    schema: tuple[tuple[str, Nested], ...]

    def __post_init__(self) -> None:
        self.suggest('Struct', 10)
        for name,typ in self.schema:
            if isinstance(typ, GenSpec):
                typ.suggest(camel_case(name), 30)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        memb_names = [(name,
                       get_name(typ, names),
                       get_create_from(typ, names))
                      for name,typ in self.schema]
        dest.write(dedent(f"""\
            @dataclass(frozen=True)
            class {names[self]}(spec._StructBase):
                _member_names: ClassVar[tuple[str,...]] = ({','.join(repr(name) for (name,_) in self.schema)},)
                _member_types: ClassVar[tuple[type[FullSpec],...]] = ({','.join(tname for _,tname,__ in memb_names)},)
            """))

        for name,tname,_ in memb_names:
            dest.write(f'    {name}: {tname}\n')

        dest.write(indent(dedent(f"""
            @classmethod
            def create(cls,
            """), '    '))
        for name,tname,cfi in memb_names:
            dest.write(f'        {name}: {tname if cfi is None else cfi},\n')
        dest.write('    ) -> Self:\n')
        dest.write('        return cls(\n')
        for name,tname,cfi in memb_names:
            if cfi is None:
                dest.write(f'            {name} = {name},\n')
            else:
                dest.write(f'            {name} = {tname}.create({name}),\n')
        dest.write('        )\n')



    @override
    def prereqs(self) -> Iterable[Nested]:
        for _,typ in self.schema:
            yield typ

def Struct(**kwargs: Nested) -> _Struct:
    return _Struct(tuple(kwargs.items()))

@dataclass(frozen=True)
class _SelecteeDefault(GenSpec):
    select_type: Nested
    data_type: Nested

    def __post_init__(self) -> None:
        self.suggest(f'Default{get_stub(self.select_type)}Selection', 30)

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        dname = get_name(self.data_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._Selectee[{sname}, {dname}]):
                _SELECT_TYPE = {sname}
                _DATA_TYPE = {dname}
            """))

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self.select_type
        yield self.data_type

@dataclass(frozen=True)
class _SelecteeGen(_SelecteeDefault):
    selection: str

    @override
    def __post_init__(self) -> None:
        self.suggest(f'{self.selection}Selection', 30)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if self.update_stub(name, rank):
            maybe_suggest(self.data_type, f'{name}Data', 20)
            return True
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        dname = get_name(self.data_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._SpecificSelectee[{sname}, {dname}]):
                _SELECT_TYPE = {sname}
                _DATA_TYPE = {dname}
                _SELECTOR = {sname}.{self.selection}
            """))

@dataclass(frozen=True)
class _SelectActual(GenSpec):
    select_type: Nested
    default_type: _SelecteeDefault|None
    selectees: tuple[tuple[str, _SelecteeGen], ...]

    def __post_init__(self) -> None:
        sname = get_stub(self.select_type)
        self.update_stub(exact_rstrip(sname, 'Type', 'Obj'), 60)
        for name, sel in self.selectees:
            sel.suggest(camel_case(name) + self.stub, 40)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if self.update_stub(name, rank):
            stub = exact_rstrip(name, 'Obj')
            for sname, sgen in self.selectees:
                sgen.suggest(camel_case(sname) + stub, 40)
            return True
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: dict[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        dname = 'None' if self.default_type is None else names[self.default_type]
        tname = f'{names[self]}Variants'
        dest.write(dedent(f"""
            type {tname} = {' | '.join(str(names[s]) for _,s in self.selectees)}

            class {names[self]}(spec._Select[{sname}]):
                _SELECT_TYPE = {sname}
                _DEFAULT_TYPE = {dname}
                _SELECTEES = {{
            """))
        for key, s in self.selectees:
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
    def prereqs(self) -> Iterable[Nested]:
        yield self.select_type
        if self.default_type is not None:
            yield self.default_type
        for _,sel in self.selectees:
            yield sel

@dataclass
class Select:
    select_type: Nested
    bit_length: int|None = None
    default_type: Nested|None = None

    def _maybe_bounded(self, typ: Nested) -> Nested:
        if self.bit_length is None:
            return typ
        else:
            return Bounded(self.bit_length, typ)

    def __call__(self, **kwargs: Nested) -> _SelectActual:
        return _SelectActual(
            self.select_type,
            (None if self.default_type is None
             else _SelecteeDefault(self.select_type, self._maybe_bounded(self.default_type))),
            tuple((enum_key,
                   _SelecteeGen(self.select_type, self._maybe_bounded(typ), enum_key))
                  for (enum_key, typ) in kwargs.items()),
        )


@dataclass
class Names:
    _order: list[GenSpec] = field(default_factory=list)
    _registered: set[GenSpec] = field(default_factory=set)

    def register(self, spec: GenSpec) -> None:
        if spec in self._registered:
            return # already registered
        self._registered.add(spec)
        for prereq in spec.prereqs():
            if isinstance(prereq, GenSpec):
                self.register(prereq)
        self._order.append(spec)

    def assign(self) -> dict[GenSpec,str]:
        counts: Counter[str] = Counter()
        for spec in self._order:
            counts[spec.stub] += 1
        assignment = {}
        for spec in self._order:
            count = counts[spec.stub]
            if count == 1:
                assignment[spec] = spec.stub
                index = 1
            else:
                index = 1 if (count > 1) else -count
                assignment[spec] = f'{spec.stub}_{index}'
            counts[spec.stub] = -index - 1
        return assignment

    def order(self) -> Iterable[GenSpec]:
        yield from self._order

@dataclass
class SourceGen:
    dest: TextIO
    names: dict[GenSpec,str]
    _written: set[GenSpec] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.dest.write(dedent('''
            # XXX AUTO-GENERATED - DO NOT EDIT! XXX
            from typing import Self, override, BinaryIO, ClassVar, Any
            from collections.abc import Iterable
            import enum
            import dataclasses
            from dataclasses import dataclass
            import spec
            from spec import *
            '''))

    def write(self, spec: GenSpec) -> None:
        if spec not in self._written:
            for pre in spec.prereqs():
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
        spec.suggest(name, FORCE_RANK)
        ns.register(spec)

    SourceGen(dest, ns.assign()).write_all(ns.order())
