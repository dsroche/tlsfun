#!/usr/bin/env python3

from typing import Iterable
from io import BytesIO
import spec
from spec import Spec, Json
from tls13_spec import *
import util
import tls_common
import tls_crypto
import tls_keycalc
import tls_records
import tls_client


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
    buf = BytesIO()
    orig.pack_to(buf)
    check(buf.getvalue(), raw)
    buf.seek(0)
    rdr = LimitReader(buf)
    try:
        item = cls.unpack_from(rdr)
    except NotImplementedError:
        pass
    else:
        check(item.jsonify(), js)
        check(rdr.got, raw)

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
    yield ContentType.ALERT, {'name': 'ALERT', 'value': 21}, '15'
    yield (ExtensionType.create(100),
           {'name':'UNRECOGNIZED', 'value':100},
           '0064')
    yield (ExtensionType.create(0xdada),
           {'name':'GREASE', 'value': 0xdada},
           'dada')
    yield (PskKeyExchangeMode.GREASE,
           {'name':'GREASE', 'value':0x0b},
           '0b')
    yield Uint8(17), 17, '11'
    yield String('abcd'), 'abcd', '61626364'
    yield Raw(b'bb'), '6262', '6262'
    yield B16String('abcd'), 'abcd', '000461626364'
    yield B8Raw(b''), '', '00'
    yield B16Raw(b'cab'), '636162', '0003636162'
    yield Uint16(5), 5, '0005'
    yield (HkdfLabel.create(5,b'ab',b'cde'),
           {'length':5, 'label':'6162', 'context':'636465'},
           '000502616203636465')
    yield (PskBinders.create([b'aa', b'bbccdd']),
           ['6161', '626263636464'],
           '000a02616106626263636464')
    yield (KeyShareServerExtension.create(NamedGroup.X448,b'ace').parent(),
           {'selector': {'name':'KEY_SHARE', 'value':51},
            'data': {'group': {'name':'X448', 'value':0x001e},
                     'pubkey': '616365'}},
           '00330007001e0003616365')
    yield (PskKeyExchangeModesClientExtension.create([0x0b,1,0xe4]),
           {'selector': {'name': 'PSK_KEY_EXCHANGE_MODES', 'value': 45},
            'data': [{'name':'GREASE', 'value':0x0b},
                     {'name':'PSK_DHE_KE', 'value':1},
                     {'name':'GREASE', 'value':0xe4}]},
           '002d0004030b01e4')
    yield B8Raw.create(b''), '', '00'

def error_test_cases() -> Iterable[tuple[type[Spec], Json, str]]:
    yield Uint8, -3, 'ffff'
    yield B16Raw, [], '0001aabb'
    yield HandshakeType, {'name':'FINISHED', 'value':15}, '10'
    yield (ClientExtension,
           {'selector': {'name':'PRE_SHARED_KEY', 'value':41},
            'data': {'binders':[]}},
           '0029000600000000')

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
