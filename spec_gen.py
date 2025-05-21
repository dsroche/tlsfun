#!/usr/bin/env python3

from spec5 import *

with open('spec6.py', 'w') as fout:
    generate_specs(
        fout,
        Days = EnumSpec(8,
            Monday = 1,
            Tuesday = 2,
        ),
    )
