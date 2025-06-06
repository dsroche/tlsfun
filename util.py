"""Various small utility or helper stuff not TLS specific."""

from collections.abc import Callable, Iterable, Hashable
from typing import Any, cast
from dataclasses import dataclass, field
import functools
import base64
import pprint

type _Pretty = str | list[_Pretty] | dict[str, _Pretty]

def _pretty_prep(obj: Any, byteslen: int|None=None) -> _Pretty :
    if isinstance(obj, bytes):
        if byteslen is not None and len(obj) > byteslen:
            return f"{obj[:byteslen//2].hex()}...{obj[-byteslen//2:].hex()}"
        else:
            return obj.hex()
    elif isinstance(obj, tuple):
        if hasattr(obj, '_asdict'):
            return _pretty_prep(obj._asdict(), byteslen)
        else:
            return [_pretty_prep(value, byteslen) for value in obj]
    elif isinstance(obj, dict):
        return {str(key): _pretty_prep(value, byteslen) for key,value in obj.items()}
    elif isinstance(obj, list):
        return [_pretty_prep(value, byteslen) for value in obj]
    else:
        return str(obj)

def pp(obj:Any, byteslen:int=32, **kwargs: Any) -> None:
    pprint.pp(_pretty_prep(obj, byteslen), **kwargs)

def pformat(obj:Any, byteslen:int=32, **kwargs: Any) -> str:
    return pprint.pformat(_pretty_prep(obj, byteslen), sort_dicts=False, **kwargs)

@dataclass
class OneToOne[K1: Hashable, K2: Hashable]:
    """A one-to-one mapping, i.e. two-way dictionary."""
    _forward: dict[K1,K2] = field(default_factory=dict)
    _reverse: dict[K2,K1] = field(default_factory=dict)

    def add(self, key1: K1, key2: K2) -> None:
        try:
            cur_k2 = self._forward[key1]
        except KeyError:
            pass
        else:
            if key2 == cur_k2:
                return
            raise ValueError(f"can't insert ({key1},{key2}) because ({key1},{cur_k2}) is already there")
        try:
            cur_k1 = self._reverse[key2]
        except KeyError:
            pass
        else:
            raise ValueError(f"can't insert ({key1},{key2}) because ({cur_k1},{key2}) is already there")
        self._forward[key1] = key2
        self._reverse[key2] = key1

    def contains1(self, key: K1) -> bool:
        return key in self._forward

    def contains2(self, key: K2) -> bool:
        return key in self._reverse

    def get1(self, key: K1, default: K2|None = None) -> K2:
        got = self._forward.get(key, default)
        if got is None:
            raise KeyError(str(key))
        return got

    def get2(self, key: K2, default: K1|None = None) -> K1:
        got = self._reverse.get(key, default)
        if got is None:
            raise KeyError(str(key))
        return got

    def __getitem__(self, key: K1) -> K2:
        return self.get1(key)

    def __setitem__(self, key1: K1, key2: K2) -> None:
        self.add(key1, key2)

    def __contains__(self, key: K1) -> bool:
        return self.contains1(key)

def b64enc(raw_bytes: bytes) -> str:
    return base64.b64encode(raw_bytes).decode('ascii')

def b64dec(b64_str: str) -> bytes:
    return base64.b64decode(b64_str)

def kwdict[T](**kwargs: T) -> dict[str, T]:
    return kwargs

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

def write_tuple(items: Iterable[str]) -> str:
    it = iter(items)
    try:
        first = next(it)
    except StopIteration:
        return '()'
    return f"({first}, {', '.join(it)})"

def exact_lstrip(orig: str, prefix: str) -> str:
    if orig.startswith(prefix):
        return orig[len(prefix):]
    else:
        return orig

def exact_rstrip(orig: str, suffix: str, new_suffix: str = '') -> str:
    if orig.endswith(suffix):
        return orig[:-len(suffix)]
    else:
        return orig + new_suffix

def camel_case(orig: str) -> str:
    return orig.replace('_',' ').title().replace(' ','')

def same_signature[**A,R](original: Callable[A,R]) -> Callable[[Callable[...,Any]],Callable[A,R]]:
    # https://stackoverflow.com/a/77954920
    def decorate(target: Callable[...,Any]) -> Callable[A,R]:
        return cast(Callable[A,R], target)
    return decorate
