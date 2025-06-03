"""Various small utility or helper stuff not TLS specific."""

from collections.abc import Callable, Iterable
from typing import Any
import functools
import base64

class SetOnce[T]:
    """Descriptor that allows setting but not getting an attribute value."""
    def __init__(self) -> None:
        self._values: dict[int, T] = {}

    def __set_name__(self, owner: Any, name: str) -> None:
        self._name = name

    def __set__(self, obj: Any, value: T) -> None:
        if id(obj) in self._values:
            raise ValueError(f"{self._name} is already set on {obj}")
        self._values[id(obj)] = value

    def __get__(self, obj: Any, objtype:Any = None) -> T:
        try:
            return self._values[id(obj)]
        except KeyError:
            raise ValueError(f"{self._name} is not yet set on {obj}") from None

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
