#!/usr/bin/env python3

from typing import Iterable
from io import BytesIO
from spec_static import Spec, FullSpec, Json
from spec6 import *

import spec_static

class PersonSelect(spec_static._Selectee[Months,Person]):
    _SELECTOR = Months.February
    _DATA_TYPE = Person

class AnimalSelect(spec_static._Selectee[Months,Animal]):
    _SELECTOR = Months.May
    _DATA_TYPE = Animal

type A = PersonSelect | AnimalSelect

class B(spec_static._Select[Months]):
    _SELECT_TYPE = Months
    _SELECTEES = {
        Months.February: PersonSelect,
        Months.May: AnimalSelect,
    }

    def __init__(self, value: A):
        super().__init__(value)
        self._value: A = value

    @property
    def value(self) -> A:
        return self._value

def check[T](a: T, b: T) -> None:
    if isinstance(a, bytes) and isinstance(b, bytes):
        check(a.hex(), b.hex())
    elif a != b:
        raise AssertionError(f'got {a} expected {b}')

def test_spec(orig: Spec, js: Json, rawhex: str,) -> None:
    raw = bytes.fromhex(rawhex)
    cls = type(orig)
    check(orig.jsonify(), js)
    check(cls.from_json(js).jsonify(), js)
    check(orig.pack(), raw)
    check(cls.unpack(raw).pack(), raw)
    check(orig.packed_size(), len(raw))
    if issubclass(cls, FullSpec):
        buf = BytesIO()
        orig.pack_to(buf)
        check(buf.getvalue(), raw)
        buf.seek(0)
        item, count = cls.unpack_from(buf)
        check(count, len(raw))
        check(item.jsonify(), js)

def test_error(cls: type[Spec], js: Json, rawhex: str) -> None:
    raw = bytes.fromhex(rawhex)
    try:
        cls.from_json(js)
    except ValueError:
        pass
    else:
        raise AssertionError(f'{cls}.from_json({js}) should be ValueError')
    try:
        cls.unpack(raw)
    except ValueError:
        pass
    else:
        raise AssertionError(f'{cls}.unpack({rawhex}) should be ValueError')

def positive_test_cases() -> Iterable[tuple[Spec, Json, str]]:
    yield Days.Tuesday, 'Tuesday', '02'
    yield Months.May, 'May', '0005'
    yield Uint24(258), 258, '000102'
    yield Uint8(17), 17, '11'
    yield String('abcd'), 'abcd', '61626364'
    yield Raw(b'bb'), '6262', '6262'
    yield String16('abcd'), 'abcd', '000461626364'
    yield Raw8(b''), '', '00'
    yield Raw16(b'cab'), '636162', '0003636162'
    yield Uint16(5), 5, '0005'
    yield Shorts([Uint16(20), Uint16(25)]), [20,25], '00140019'
    yield ShortShorts([Uint16(3),Uint16(4),Uint16(5)]), [3,4,5], '06000300040005'
    yield B16S8((Uint8(10), Uint8(20))), [10,20], '00020a14'
    yield Person(String16('ada'), Uint16(1)), {'name':'ada','phone':1}, '00036164610001'
    yield (Animal(String8('doggie'), legs=Uint8(4), nums=ShortShorts(())),
           {'name': 'doggie', 'legs': 4, 'nums': []},
           '06646f676769650400')
    yield (B(AnimalSelect(Animal(String8('cat'), legs=Uint8(4), nums=ShortShorts(())))),
           {'typ': 'May', 'data': {'name': 'cat', 'legs': 4, 'nums': []}},
           '0005036361740400')
    yield (Brass(Struct_5(valves=Uint8(5), weight=Uint16(40))),
           {'typ': 'Brass', 'data': {'valves': 5, 'weight': 40},},
           '01050028')
#    test_spec(Uint8, 33, 33, '21')
#    test_spec(Uint16, 50, 50, '0032')
#    test_spec(Raw8, b'abc', '616263', '03616263')
#    test_spec(Raw16, b'', '', '0000')
#    test_spec(String8, 'abcd', 'abcd', '0461626364')
#    test_spec(String16, 'bb', 'bb', '00026262')

def error_test_cases() -> Iterable[tuple[type[Spec], Json, str]]:
    yield Days, 10, ''
    yield Months, 1, '0100'
    yield Uint8, -3, 'ffff'

def all_tests() -> None:
    count = 0
    for (orig, js, rawhex) in positive_test_cases():
        try:
            test_spec(orig, js, rawhex)
        except:
            print("FAILURE on positive run", orig, js, rawhex)
            raise
        count += 1
    for (cls, js, rawhex) in error_test_cases():
        test_error(cls, js, rawhex)
        count += 1
    print(f'PASSED all {count} tests')

if __name__ == '__main__':
    all_tests()
