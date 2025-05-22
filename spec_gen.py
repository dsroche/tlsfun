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
        )
    print('specs written to', fname)

if __name__ == '__main__':
    write_to('spec6.py')
