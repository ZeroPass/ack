#!/bin/python
# Test vector generator for bigint serialization test cases
# Author: Crt Vavros

import argparse
import random
import struct
import sys

max_rand_number = pow(2, 256)
min_rand_num    = 0

def to_hex(n: int):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big', signed=False).hex()

def to_le_int_array(n: int):
    blen = max(4, (n.bit_length() + 7) // 8)
    ilen = int((blen+3)/4)
    return struct.unpack(f"<{ilen}I", n.to_bytes(ilen*4, 'little', signed=False))

def str_to_int(s: str):
    if s.lower().startswith("0x"):
        return int(s, 16)
    else:
        return int(s)

parser = argparse.ArgumentParser()
parser.add_argument("num", type=str, nargs='?', default=None)
parser.add_argument("--max-rand", type=str, nargs='?', default=max_rand_number)

# check if positional argument is present and parse the number out
if len(sys.argv) > 1:
    args = parser.parse_args()
    num = args.num
    if num is not None:
        number = str_to_int(num)
    else:
        number = random.randint(min_rand_num, str_to_int(args.max_rand))
else:
    number = random.randint(min_rand_num, max_rand_number)

hexnum = to_hex(number)
le_int_array = to_le_int_array(number)
req_bit_len = max(number.bit_length(), 1)

tv = """struct tv {{
    using bigint_t = fixed_bigint<{}>;
    static constexpr char tvhex[] = "{}";
    static constexpr auto tv    = from_hex( tvhex );
    static constexpr auto tvis  = word_array({{ // internal state
        {}
    }});
}};""".format(req_bit_len, hexnum, ", ".join([str(i) for i in le_int_array]))

print(tv)





