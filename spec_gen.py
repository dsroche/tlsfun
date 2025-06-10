from typing import Self, BinaryIO, TextIO, Any, override, ClassVar
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
    OneToOne,
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
    _name_stub: NameRank = field(default_factory=NameRank, init=False, hash=False)

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

    def generate(self, dest: TextIO, names: OneToOne['GenSpec',str]) -> None:
        raise NotImplementedError

    def prereqs(self) -> Iterable[Nested]:
        return ()

    def create_from(self, names: OneToOne['GenSpec',str]) -> Iterable[tuple[str,str]] | None:
        return None

@dataclass
class _ItemCreation:
    """helper class for create_from stuff when being used recursively"""
    item_type: Nested
    names: OneToOne[GenSpec,str]
    construct_name: str = 'value'

    @cached_property
    def _icf(self) -> Iterable[tuple[str,str]] | None:
        return get_create_from(self.item_type, self.names)

    @cached_property
    def construct(self) -> bool:
        return self._icf is None

    @cached_property
    def pairs(self) -> list[tuple[str,str]]:
        if self.construct:
            return [(self.construct_name, get_name(self.item_type, self.names))]
        else:
            assert self._icf is not None
            return list(self._icf)

    @cached_property
    def pairstring(self) -> str:
        return f'({"".join(f"({repr(name)}, {typ}), " for name,typ in self.pairs)})'

    @cached_property
    def args(self) -> str:
        return ''.join(f', {name}:{typ}' for name,typ in self.pairs)

    @cached_property
    def single(self) -> bool:
        return len(self.pairs) == 1

    @cached_property
    def item(self) -> str:
        if self.single:
            [(_,typ)] = self.pairs
            return typ
        elif self.pairs:
            return f'tuple[{",".join(typ for _,typ in self.pairs)}]'
        else:
            return 'tuple[()]'

    def create_line(self, creator: str, varname: str) -> str:
        if self.construct:
            return f'{varname}'
        elif self.single:
            return f'{creator}.create({varname})'
        else:
            return f'{creator}.create(*{varname})'

    def from_pairs(self, creator: str) -> str:
        if self.construct:
            return self.construct_name
        else:
            return f'{creator}.create({", ".join(name for name,_ in self.pairs)})'

    def to_pairs(self, varname: str) -> str:
        if self.construct:
            return varname
        else:
            return f'{varname}.uncreate()'

    def gen_replace(self, dest: TextIO) -> None:
        if self.single or not self.pairs:
            return # no replace method needed unless multiple parts
        dest.write(indent(dedent(f"""
            def replace(self, {', '.join(f'{name}: {tname}|None=None' for name,tname in self.pairs)}) -> Self:
                {', '.join(f'orig_{name}' for name,_ in self.pairs)} = self.uncreate()
                return self.create({', '.join(f'(orig_{name} if {name} is None else {name})' for name,_ in self.pairs)})
            """), '    '))

def get_stub(typ: Nested) -> str:
    match typ:
        case GenSpec():
            return typ.stub
        case type():
            return typ.__name__
        case str():
            return typ

def get_name(spec: Nested|type[Any], names: OneToOne[GenSpec, str]) -> str:
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

def get_create_from(typ: Nested, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]] | None:
    match typ:
        case GenSpec():
            return typ.create_from(names)
        case type():
            cft = typ._CREATE_FROM
            return (None if cft is None
                    else [(name, get_name(typ, names)) for (name,typ) in cft])
        case str():
            try:
                return names.get2(typ).create_from(names)
            except KeyError:
                return None

@flyweight
@dataclass(frozen=True)
class Wrap(GenSpec):
    inner_type: Nested

    def __post_init__(self) -> None:
        self.update_stub(f'Wrap{get_stub(self.inner_type)}', 30)

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]] | None:
        return _ItemCreation(self.inner_type, names).pairs

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif maybe_suggest(self.inner_type, name, min(rank, 90)):
            return self.update_stub(f'Wrap{get_stub(self.inner_type)}', 30)
        else:
            return False

    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        dt = get_name(self.inner_type, names)
        creat = _ItemCreation(self.inner_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._Wrapper[{get_name(self.inner_type, names)}]):
                _DATA_TYPE = {dt}

                @classmethod
                def create(cls{creat.args}) -> Self:
                    return cls(data={creat.from_pairs(dt)})

                def uncreate(self) -> {creat.item}:
                    return {creat.to_pairs('self.data')}
            """))
        creat.gen_replace(dest)

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
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]] | None:
        return (('value','int'),)

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
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
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
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
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]] | None:
        return (('value', 'bytes'),)

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
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
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        dest.write(dedent(f"""\
            class {names[self]}({names[self._parent]}, spec._SpecEnum):
                @override
                def jsonify(self) -> Json:
                    return self.name

                @override
                @classmethod
                def from_json(cls, obj: Json) -> Self:
                    if isinstance(obj, int):
                        return cls(obj)
                    elif isinstance(obj, str):
                        return cls[obj]
                    else:
                        raise ValueError

                @override
                def pack(self) -> bytes:
                    return self.to_bytes(self._BYTE_LENGTH)

                @override
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
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
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

@dataclass(frozen=True)
class _NamedConstEnum(GenSpec):
    members: tuple[tuple[str,int], ...]

    def __post_init__(self) -> None:
        self.suggest('NamedConstEnum', 10)

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        return (('value', 'int'),)

    @override
    def generate(self, dest: TextIO, names: OneToOne['GenSpec',str]) -> None:
        dest.write(f"class {names[self]}(enum.IntEnum):\n")
        for name,value in self.members:
            dest.write(f"    {name} = {value}\n")


@dataclass(frozen=True)
class _NamedConst(GenSpec):
    enum_type: _NamedConstEnum
    vt: Uint
    default: str|None
    alts: tuple[tuple[int, str],...]

    def __post_init__(self) -> None:
        self.update_stub('NamedConst', 10)

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        return (('value', 'int'),)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if self.update_stub(name, rank):
            self.enum_type.suggest(f"{self.stub}s", min(rank, 60))
            return True
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        tname = get_name(self.enum_type, names)
        vname = names[self.vt]
        dest.write(dedent(f"""\
            class {names[self]}(spec._NamedConstBase[{tname}, {vname}]):
                _T = {tname}
                _V = {vname}
            """))
        if self.alts:
            dest.write(f"    _alternate_values = {{{', '.join(f'{val}:{tname}.{name}' for val,name in self.alts)}}}\n")
        if self.default:
            dest.write(f"    _default_typ = {tname}.{self.default}\n")
        dest.write(indent(dedent(f"""
            def __init__(self, value: int) -> None:
                self._subclass_init(value)
            """), '    '))

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self.vt
        yield self.enum_type

@dataclass
class NamedConst:
    bit_length: int
    default: str|None = None

    def __call__(self, **kwargs: int|tuple[int,...]) -> _NamedConst:
        members = []
        alts = []
        all_values = set()

        def add_val(val: int) -> None:
            if val in all_values:
                raise ValueError(f"duplicate value {val}")
            elif not 0 <= val < 2**self.bit_length:
                raise ValueError(f"value {val} does not fit in {self.bit_length} bits")
            all_values.add(val)

        for name, second in kwargs.items():
            match second:
                case ():
                    raise ValueError(f"no values for {name}")
                case int() as val:
                    add_val(val)
                    members.append((name, val))
                case tuple() as values:
                    assert len(values) >= 1
                    for val in values:
                        add_val(val)
                    members.append((name, values[0]))
                    for val in values[1:]:
                        alts.append((val, name))

        match self.default:
            case str():
                if not any(name == self.default for (name,_) in members):
                    raise ValueError(f"default {self.default} not in enum list")

        return _NamedConst(
            enum_type = _NamedConstEnum(tuple(members)),
            vt        = Uint(self.bit_length),
            default   = self.default,
            alts      = tuple(alts),
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
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        nn = get_name(self.inner_type, names)
        dest.write(dedent(f"""\
            class {names[self]}({nn}, Spec):
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
                    try:
                        return super().unpack(raw[offset:])
                    except UnpackError as e:
                        raise e.above(raw, {{'bounded_size': length, 'data': e.partial}}) from e

                @override
                @classmethod
                def unpack_from(cls, src: LimitReader) -> Self:
                    lit = iter(cls._LENGTH_TYPES)
                    length = next(lit).unpack_from(src)
                    for LT in lit:
                        len2 = LT.unpack_from(src)
                        if length != LT._BYTE_LENGTH + len2:
                            raise UnpackError(src.got, f"bounded length should have been {{length - LT._BYTE_LENGTH}} but got {{len2}}")
                        length = len2
                    supraw = src.read(length)
                    try:
                        return super().unpack(supraw)
                    except UnpackError as e:
                        raise e.above(src.got, {{'bounded_size': length, 'data': e.partial}}) from e
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
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]] | None:
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
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
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

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        creat = _ItemCreation(self.item_type, names)
        return (('items', f'Iterable[{creat.item}]'),)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if rank == FORCE_RANK:
            return self.update_stub(name, rank)
        elif maybe_suggest(self.item_type, exact_rstrip(name, 's'), min(rank, 90)):
            return self.update_stub(self._name_suggestion(), 70)
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        nn = get_name(self.item_type, names)
        creat = _ItemCreation(self.item_type, names)
        items_t = f'Iterable[{creat.item}]'
        dest.write(dedent(f"""\
            class {names[self]}(spec._Sequence[{nn}]):
                _ITEM_TYPE = {nn}

                @classmethod
                def create(cls, items: {items_t}) -> Self:
                    return cls({creat.create_line(nn,'item')} for item in items)

                def uncreate(self) -> {items_t}:
                    for item in self:
                        yield {creat.to_pairs('item')}
            """))

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
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        return [(name, _ItemCreation(typ, names).item)
                for (name, typ) in self.schema]

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        members = [(name,
                    get_name(typ, names),
                    _ItemCreation(typ, names),
                   ) for name,typ in self.schema]
        dest.write(dedent(f"""\
            @dataclass(frozen=True)
            class {names[self]}(spec._StructBase):
                _member_names: ClassVar[tuple[str,...]] = ({','.join(repr(name) for (name,_) in self.schema)},)
                _member_types: ClassVar[tuple[type[Spec],...]] = ({','.join(tname for _,tname,_ in members)},)
            """))

        for name,tname,_ in members:
            dest.write(f'    {name}: {tname}\n')

        dest.write(indent(dedent(f"""
            def replace(self, {', '.join(f'{name}:{creat.item}|None=None' for name,_,creat in members)}) -> Self:
                return type(self)({', '.join(f'(self.{name} if {name} is None else {creat.create_line(tname,name)})' for name,tname,creat in members)})
            """), '    '))

        match members:
            case []:
                unc_type = 'tuple[()]'
            case [(_,_,creat)]:
                unc_type = creat.item
            case _:
                unc_type = f'tuple[{", ".join(creat.item for _,_,creat in members)}]'
        dest.write(indent(dedent(f"""
            @classmethod
            def create(cls,{','.join(f'{name}:{creat.item}' for name,_,creat in members)}) -> Self:
                return cls({', '.join(f'{name}={creat.create_line(tname,name)}' for name,tname,creat in members)})

            def uncreate(self) -> {unc_type}:
                return ({', '.join(creat.to_pairs(f'self.{name}') for name,_,creat in members)})
            """), '    '))

    @override
    def prereqs(self) -> Iterable[Nested]:
        for _,typ in self.schema:
            yield typ

def Struct(**kwargs: Nested) -> _Struct:
    return _Struct(tuple(kwargs.items()))

@dataclass(frozen=True)
class _SelecteeGeneric(GenSpec):
    count: int # used to ensure uniqueness
    select_type: Nested
    data_type: Nested
    parent: '_SelectActual|None' = field(init=False,hash=False,compare=False,default=None)

    def __post_init__(self) -> None:
        self.suggest(f'Generic{get_stub(self.select_type)}Selection', 30)

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        screat = _ItemCreation(self.select_type, names)
        dcreat = _ItemCreation(self.data_type, names)
        return (('typ', screat.item), ('data', dcreat.item))

    def set_parent(self, parent: '_SelectActual') -> None:
        assert self.parent is None, "shouldn't set parent twice"
        object.__setattr__(self, 'parent', parent)

    def _gen_parent(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        assert self.parent is not None, "parent was never set"
        pname = names[self.parent]
        dest.write(indent(dedent(f"""
            def parent(self) -> '{pname}':
                return {pname}(self)
            """), '    '))

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        dname = get_name(self.data_type, names)
        screat = _ItemCreation(self.select_type, names)
        dcreat = _ItemCreation(self.data_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._Selectee[{sname}, {dname}]):
                _SELECT_TYPE = {sname}
                _DATA_TYPE = {dname}

                @classmethod
                def create(cls, typ: {screat.item}, data: {dcreat.item}) -> Self:
                    return cls({screat.create_line(sname,'typ')}, {dcreat.create_line(dname,'data')})

                def uncreate(self) -> tuple[{screat.item}, {dcreat.item}]:
                    return ({screat.to_pairs('self.typ')}, {dcreat.to_pairs('self.data')})
            """))
        self._gen_parent(dest, names)

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self.select_type
        yield self.data_type

@dataclass(frozen=True)
class _SelecteeSpecific(_SelecteeGeneric):
    selection: str

    @override
    def __post_init__(self) -> None:
        self.suggest(f'{self.selection}Selection', 30)

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        return _ItemCreation(self.data_type, names).pairs

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if self.update_stub(name, rank):
            maybe_suggest(self.data_type, f'{name}Data', 20)
            return True
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        dname = get_name(self.data_type, names)
        assert self.parent is not None, "parent was never set for selectee"
        pname = names[self.parent]
        creat = _ItemCreation(self.data_type, names)
        dest.write(dedent(f"""\
            class {names[self]}(spec._SpecificSelectee[{sname}, {dname}]):
                _SELECT_TYPE = {sname}
                _DATA_TYPE = {dname}
                _SELECTOR = {sname}.{self.selection}

                @classmethod
                def create(cls{creat.args}) -> Self:
                    return cls(data={creat.from_pairs(dname)})

                def uncreate(self) -> {creat.item}:
                    return {creat.to_pairs('self.data')}
            """))
        self._gen_parent(dest, names)
        creat.gen_replace(dest)

@dataclass(frozen=True)
class _SelectActual(GenSpec):
    select_type: Nested
    generic_type: _SelecteeGeneric|None
    selectees: tuple[tuple[str, _SelecteeSpecific], ...]

    def __post_init__(self) -> None:
        sname = get_stub(self.select_type)
        self.update_stub(exact_rstrip(sname, 'Type', 'Obj'), 60)
        if self.generic_type is not None:
            self.generic_type.set_parent(self)
            self.generic_type.suggest('Generic' + self.stub, 40)
        for name, sel in self.selectees:
            sel.set_parent(self)
            sel.suggest(camel_case(name) + self.stub, 40)

    def _tname(self, names: OneToOne[GenSpec,str]) -> str:
        return f'{names[self]}Variant'

    @override
    def create_from(self, names: OneToOne[GenSpec,str]) -> Iterable[tuple[str,str]]:
        return (('variant', self._tname(names)),)

    @override
    def suggest(self, name: str, rank: float) -> bool:
        if self.update_stub(name, rank):
            stub = exact_rstrip(name, 'Obj')
            if self.generic_type is not None:
                self.generic_type.suggest('Generic' + stub, 40)
            for sname, sgen in self.selectees:
                sgen.suggest(camel_case(sname) + stub, 40)
            return True
        else:
            return False

    @override
    def generate(self, dest: TextIO, names: OneToOne[GenSpec,str]) -> None:
        sname = get_name(self.select_type, names)
        gname = 'None' if self.generic_type is None else names[self.generic_type]
        tname = self._tname(names)
        sel_types: list[_SelecteeGeneric] = [s for _,s in self.selectees]
        if self.generic_type is not None:
            sel_types.append(self.generic_type)
        dest.write(dedent(f"""
            {tname} = {' | '.join(names[s] for s in sel_types)}

            class {names[self]}(spec._Select[{sname}]):
                _SELECT_TYPE = {sname}
                _GENERIC_TYPE = {gname}
                _SELECTEES = {{{', '.join(f'{sname}.{key}:{names[s]}' for key,s in self.selectees)}}}

                def __init__(self, value: {tname}) -> None:
                    super().__init__(value)
                    self._value: {tname} = value

                @property
                def variant(self) -> {tname}:
                    return self._value

                @classmethod
                def create(cls, variant: {tname}) -> Self:
                    return cls(variant)

                def uncreate(self) -> {tname}:
                    return self.variant
            """))

    @override
    def prereqs(self) -> Iterable[Nested]:
        yield self.select_type
        if self.generic_type is not None:
            yield self.generic_type
        for _,sel in self.selectees:
            yield sel

@dataclass
class Select:
    select_type: Nested
    bit_length: int|None = None
    generic_type: Nested|None = None
    counter: ClassVar[int] = 0

    def _maybe_bounded(self, typ: Nested) -> Nested:
        if self.bit_length is None:
            return typ
        else:
            return Bounded(self.bit_length, typ)

    def __call__(self, **kwargs: Nested) -> _SelectActual:
        type(self).counter += 1
        count = type(self).counter
        return _SelectActual(
            self.select_type,
            (None if self.generic_type is None
             else _SelecteeGeneric(count, self.select_type, self._maybe_bounded(self.generic_type))),
            tuple((enum_key,
                   _SelecteeSpecific(count, self.select_type, self._maybe_bounded(typ), enum_key))
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

    def assign(self) -> OneToOne[GenSpec,str]:
        counts: Counter[str] = Counter()
        for spec in self._order:
            counts[spec.stub] += 1
        assignment = OneToOne[GenSpec,str]()
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
    names: OneToOne[GenSpec,str]
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
