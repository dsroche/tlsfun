#!/usr/bin/env python3

from spec5 import *

def write_to(fname: str) -> None:
    with open(fname, 'w') as fout:
        generate_specs(
            fout,
            Days = EnumSpec(
                8,
                Monday = 1,
                Tuesday = 2,
            ),
            Months = EnumSpec(
                16,
                February = 2,
                May = 5,
            ),
            Uint8 = Uint(8),
            Uint24 = Uint(24),
            Raw8 = Bounded(8, Raw),
            Raw16 = Bounded(16, Raw),
            String16 = Bounded(16, String),
            Shorts = Sequence(Uint(16)),
            ShortShorts = Bounded(8, Sequence(Uint(16))),
            B16S8 = Bounded(16, Sequence(Uint(8))),
            Person = Struct(
                name = 'String16',
                phone = Uint(16),
            ),
            Animal = Struct(
                name = Bounded(8, String),
                legs = Uint(8),
                nums = Bounded(8, Sequence(Uint(16))),
            ),
            InstrumentType = EnumSpec(
                8,
                Brass = 1,
                Woodwind = 2,
                Strings = 3,
            ),
            Instrument = Select(
                'InstrumentType',
                Brass = Struct(
                    valves = 'Uint8',
                    weight = 'Uint16',
                ),
                Woodwind = Bounded(8, String),
            ),
        )
    print('specs written to', fname)

if __name__ == '__main__':
    write_to('spec6.py')
