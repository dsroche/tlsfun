"""Utilities to support translating network protocol specs into Python code.

The main base class is `Spec`, which has `pack` and `unpack` methods (among others)
to convert between byte-level representations (e.g. from a network socket)
and Python objects (typically dicts and lists).
"""


from collections import namedtuple
from io import BytesIO
import pprint


class _ErrorVal:
    def __repr__(self):
        return '!!!! ERROR HERE !!!!'
ERROR_VAL = _ErrorVal()

class ParseError(ValueError):
    def __init__(self, *args, partial = ERROR_VAL, **kwargs):
        super().__init__(*args, **kwargs)
        self.partial = partial

class UnpackError(ValueError):
    def __init__(self, what, partial):
        super().__init__(
            f"Error unpacking {what}.\n"
            f"Partial result:\n"
            f"{pformat(partial, byteslen=40)}")


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


class _NC:
    pass
NOT_CONST = _NC()


def kwdict(**kwargs):
    return kwargs


def force_read(src, size):
    got = src.read(size)
    if len(got) != size:
        raise (ValueError if len(got) else EOFError)(f"expected {size} bytes, got {len(got)} bytes {pformat(got)}")
    return got


def force_write(dest, raw):
    written = dest.write(raw)
    if written != len(raw):
        raise BrokenPipeError(f'tried to write {len(raw)} bytes {pformat(raw)}, but only wrote {writen}')
    dest.flush()


class Spec:
    _packed_size = None
    _is_constant = False

    def prepack(self, obj=None):
        return obj

    def pack(self, obj=None, *args, **kwargs):
        return self._pack(self.prepack(obj, *args, **kwargs))

    def _pack(self, obj):
        raise NotImplementedError

    def pack_to(self, dest, obj=None, *args, **kwargs):
        self._pack_to(dest, self.prepack(obj, *args, **kwargs))

    def _pack_to(self, dest, obj):
        force_write(dest, self._pack(obj))

    def unpack(self, raw):
        if isinstance(raw, str):
            raw = bytes.fromhex(raw)
        try:
            return self._unpack(raw)
        except ParseError as e:
            raise UnpackError(f"{len(raw)} bytes {pformat(raw)}",
                               e.partial) from e

    def _unpack(self, raw):
        raise NotImplementedError

    def unpack_from(self, src):
        try:
            return self._unpack_from(src)
        except ParseError as e:
            raise UnpackError("stream", e.partial) from e

    def _unpack_from(self, src):
        raise NotImplementedError

    def const(self, obj):
        return self if obj is NOT_CONST else Constant(obj, self.pack(obj))

    def convert(self, other_spec, obj, *args, **kwargs):
        return other_spec._unpack(self.pack(obj, *args, **kwargs))


class FixedSize(Spec):
    def __init__(self, packed_size):
        assert packed_size >= 0, "packed_size must be a nonnegative integer"
        self._packed_size = packed_size

    def _unpack_from(self, src):
        try:
            raw = force_read(src, self._packed_size)
        except ValueError as e:
            raise ParseError() from e
        return self._unpack(raw)


class Integer(FixedSize):
    def __init__(self, bytelen):
        super().__init__(bytelen)

    def _pack(self, number):
        return number.to_bytes(self._packed_size)

    def _unpack(self, raw):
        return int.from_bytes(raw)


class Constant(FixedSize):
    _is_constant = True

    def __init__(self, unpacked, packed):
        super().__init__(len(packed))
        self.unpacked = unpacked
        self._packed = packed

    def prepack(self, obj=None, *args, **kwargs):
        if args or kwargs or (obj is not None and obj != self.unpacked):
            raise ValueError(f"Trying to pack {obj} into constant {self.unpacked}")
        return self.unpacked

    def _pack(self, obj):
        assert obj is self.unpacked
        return self._packed

    def _unpack(self, raw):
        if raw != self._packed:
            raise ParseError(f"Expected constant for {self.unpacked} but got {pformat(raw)}")
        return self.unpacked


class Padding(Constant):
    def __init__(self, size):
        super().__init__(None, b'\x00' * size)


class VarSize(Spec):
    def _pack(self, obj):
        buf = BytesIO()
        self._pack_to(buf, obj)
        return buf.getvalue()

    def _unpack(self, raw):
        buf = BytesIO(raw)
        obj = self._unpack_from(buf)
        if buf.tell() != len(raw):
            raise ParseError(f"too many bytes to unpack; got {len(raw)} bytes {pformat(raw)} but only needed {buf.tell()}")
        return obj


class Struct(VarSize):
    def __init__(self, **members):
        self._types = list(members.values())
        self._is_constant = all(typ._is_constant for typ in self._types)
        self.Tuple = namedtuple(
            'Struct',
            members.keys(),
            defaults=([None] * len(self._types))
        )

    def prepack(self, obj=None, *args, **kwargs):
        if args:
            plain = self.Tuple(obj, *args, **kwargs)
        elif obj is None:
            plain = self.Tuple(**kwargs)
        elif kwargs:
            plain = self.Tuple(obj, **kwargs)
        elif isinstance(obj, dict):
            plain = self.Tuple(**obj)
        else:
            plain = self.Tuple(*obj)
        return self.Tuple(*(typ.prepack(item) for (item,typ) in zip(plain, self._types)))

    def _pack_to(self, dest, items):
        for item, typ in zip(items, self._types):
            typ._pack_to(dest, item)

    def _unpack_from(self, src):
        items = []
        for typ in self._types:
            try:
                item = typ._unpack_from(src)
            except EOFError as e:
                msg = f"expected {len(self._types)} items but only got {len(items)}"
                if items:
                    items.append(ERROR_VAL)
                    raise ParseError(msg, partial=self.Tuple(*items)) from e
                else:
                    raise
            except ParseError as e:
                items.append(e.partial)
                e.partial = self.Tuple(*items)
                raise
            items.append(item)
        return self.Tuple(*items)


class Select(VarSize):
    """A pair of fields, where the value of the first determines the second.
    In specification, the type for the second field should be a function
    which maps instances of the first type to types for the second field.
    """
    def __init__(self, **members):
        assert len(members) == 2, "Select must be a pair of fields"
        mit = iter(members.items())
        name1, self._type1 = next(mit)
        name2, self._t2fun = next(mit)
        self.Tuple = namedtuple(
            'Struct',
            [name1, name2],
            defaults = [None, None])

    def prepack(self, obj=None, *args, **kwargs):
        if args:
            plain = self.Tuple(obj, *args, **kwargs)
        elif obj is None:
            plain = self.Tuple(**kwargs)
        elif kwargs:
            plain = self.Tuple(obj, **kwargs)
        elif isinstance(obj, dict):
            plain = self.Tuple(**obj)
        else:
            plain = self.Tuple(*obj)
        val1 = self._type1.prepack(plain[0])
        val2 = self._t2fun(val1).prepack(plain[1])
        return self.Tuple(val1, val2)

    def _pack_to(self, dest, items):
        self._type1._pack_to(dest, items[0])
        self._t2fun(items[0])._pack_to(dest, items[1])

    def _unpack_from(self, src):
        try:
            val1 = self._type1._unpack_from(src)
        except ParseError as e:
            e.partial = self.Tuple(e.partial)
            raise
        try:
            t2 = self._t2fun(val1)
        except (ValueError, LookupError) as e:
            raise ParseError("could not determine val2 type", partial=self.Tuple(val1, ERROR_VAL)) from e
        try:
            val2 = t2._unpack_from(src)
        except ParseError as e:
            e.partial = self.Tuple(val1, e.partial)
            raise
        except EOFError as e:
            raise ParseError("missing second item", partial=self.Tuple(val1, ERROR_VAL)) from e
        return self.Tuple(val1, val2)


class SelectBounded:
    """Helper class for Select to create the function from a size bound and key/value pairs."""
    def __init__(self, size, lookups, allow_raw=True):
        self._size = size
        self._lookups = lookups
        self._allow_raw = True

    def __call__(self, val1):
        return Bounded(self._size, self._lookups.get(val1, Raw))


class Fill(Spec):
    def __init__(self, char=b'\x00'):
        self._char = char

    def _pack(self, size):
        return self._char * size

    def _unpack(self, raw):
        if raw != self._char * len(raw):
            raise ParseError(f"fill character must be all {self._char} but got {raw.hex()}")
        return len(raw)


class _Raw(Spec):
    def prepack(self, data):
        if isinstance(data, str):
            return bytes.fromhex(data)
        else:
            return data

    def _pack(self, data):
        assert isinstance(data, bytes)
        return data

    def _unpack(self, raw):
        return raw

Raw = _Raw()


class _String(Spec):
    def _pack(self, obj):
        return str(obj).encode('ascii')

    def _unpack(self, raw):
        try:
            return raw.decode('ascii')
        except ValueError as e:
            raise ParseError() from e

String = _String()


class Sequence(Spec):
    def __init__(self, typ):
        self._inner = typ

    def prepack(self, obj, *args):
        if args:
            items = [obj] + args
        else:
            items = obj
        return [self._inner.prepack(item) for item in items]

    def _pack(self, items):
        return b''.join(self._inner.pack(item) for item in items)

    def _unpack(self, raw):
        stream = BytesIO(raw)
        result = []
        while stream.tell() < len(raw):
            try:
                item = self._inner._unpack_from(stream)
            except ParseError as e:
                result.append(e.partial)
                e.partial = result
                raise
            result.append(item)
        return result


class Fix(FixedSize):
    """Converts Unbounded to FixedSize with a static length."""

    def __init__(self, size, inner):
        super().__init__(size)
        self._inner = inner

    def prepack(self, obj=None, *args, **kwargs):
        return self._inner.prepack(obj, *args, **kwargs)

    def _pack(self, obj):
        res = self._inner._pack(obj)
        if len(res) != self._packed_size:
            raise ValueError(f"packed size should be {self._packed_size}, but it is {len(res)}")
        return res

    def _unpack(self, raw):
        if len(raw) != self._packed_size:
            raise ParseError(f"expected {self._packed_size} bytes to unpack, got {len(raw)} bytes {pformat(raw)}")
        return self._inner._unpack(raw)


class Bounded(VarSize):
    """Converts Unbounded to Varaible with a fixed-size length prefix."""

    def __init__(self, lenlen, inner):
        self._lenlen = lenlen
        self._inner = inner

    def prepack(self, obj=None, *args, **kwargs):
        return self._inner.prepack(obj, *args, **kwargs)

    def _pack_to(self, dest, obj):
        raw = self._inner._pack(obj)
        force_write(dest, len(raw).to_bytes(self._lenlen))
        force_write(dest, raw)

    def _unpack_from(self, src):
        try:
            size = int.from_bytes(force_read(src, self._lenlen))
        except EOFError:
            raise
        except ValueError as e:
            raise ParseError("could not read Bounded length") from e
        try:
            raw = force_read(src, size)
        except ValueError as e:
            raise ParseError(f"could not read {size} bytes for Bounded") from e
        return self._inner._unpack(raw)
