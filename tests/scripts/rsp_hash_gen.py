#!/bin/python
# Test case generator for hash test vectors from NIST standards FIPS 180-4 and FIPS 202
# Author: Crt Vavros

import os, sys
from typing import List, Optional, TextIO, Tuple, Union

supported_algos = [
    "SHA-384",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512"
]

algo_to_func = {
    'SHA-384' : 'sha384'
}

class TestVectors:
    def __init__(self):
        self.algo: str = ''
        self.header    = ''

class MsgTestVector:
    def __init__(self):
        self.msg: str     = ''
        self.msg_len: int = 0
        self.md: str      =''

class MsgTestVectors(TestVectors):
    def __init__(self):
        self.entries: List[MsgTestVector] = []

class MonteCarloTestVector:
    def __init__(self):
        self.count: int = 0
        self.md: str    =''

class MonteCarloTestVectors(TestVectors):
    def __init__(self, seed: str):
        self.seed: str = seed
        self.entries: List[MonteCarloTestVector] = []

def get_hashfunc(algo: str) -> str:
    if algo in algo_to_func:
        return algo_to_func[algo]
    return algo.lower().replace('-', '_')

def parse_header(file: TextIO) -> Tuple[str, Optional[str], int]:
    file.seek(0)
    header = ''
    #hash_len = 0
    algo = None
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('#'):
            line = line[1:].strip()
            header += line + "\n"
            line = line.lower()
            for a in supported_algos:
                if a.lower() in line:
                    algo = a
                    break
        elif "[L = " in line: # we've parsed header return
            #hash_len = round(int(line.strip('[]= L').strip()))
            return (header, algo, num)
        elif len(line) != 0:
            print("warning: unexpected end of header or corrupted header at line: {}".format(num + 1))
            return (header.strip(), algo, num)
    return ('', algo, -1)

def parse_monte_carlo_entries(file: TextIO, current_line: int) -> Tuple[str, List[MonteCarloTestVector]]:
    seed: str = ''
    entries: List[MonteCarloTestVector] = []
    tv = MonteCarloTestVector()
    for _, line in enumerate(file):
        line = line.strip()
        if 'Seed' in line:
            seed = line.replace('Seed', '')
            seed = seed.strip('= ')
        elif 'COUNT' in line:
            tv.count = int(line.replace('COUNT', '').strip('= '))
        elif 'MD' in line:
            tv.md = line.replace('MD', '').strip('= ')

        if len(tv.md) != 0:
            entries.append(tv)
            tv = MonteCarloTestVector()
    return (seed, entries)

def parse_msg_test_vector_entries(file: TextIO, current_line: int) -> List[MsgTestVector]:
    entries: List[MsgTestVector] = []
    tv = MsgTestVector()
    for _, line in enumerate(file):
        line = line.strip()
        if 'Msg' in line:
            tv.msg = line.replace('Msg', '').strip('= ')
        elif 'Len' in line:
            tv.msg_len = int(line.replace('Len', '').strip('= '))
        elif 'MD' in line:
            tv.md = line.replace('MD', '').strip('= ')

        if len(tv.md) != 0:
            entries.append(tv)
            tv = MsgTestVector()
    return entries

def parse_rsp(file_path: str) -> Optional[Union[MonteCarloTestVectors, MsgTestVectors]]:
    header = ''
    with open(file_path) as f:
        header, algo, cur_linenum = parse_header(f)
        if not algo:
            return None

        if "Monte" in header:
            seed, entries = parse_monte_carlo_entries(f, cur_linenum)
            tests = MonteCarloTestVectors(seed)
            tests.algo     = algo
            tests.header   = header
            tests.entries  = entries
            return tests
        else:
            entries = parse_msg_test_vector_entries(f, cur_linenum)
            tests = MsgTestVectors()
            tests.algo     = algo
            tests.header   = header
            tests.entries  = entries
            return tests

def indent(text: str, width: int, ch: str = ' '):
    padding = width * ch
    return ''.join(padding+line for line in text.splitlines(True))

def format_var(var: str, decl: bool, indent_size: int = 0, var_type: str = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def main():
    if len(sys.argv) < 2:
        print("Usage:\n    rsp_hash_gen.py <path_to_rsp_file>")
        return 0
    elif os.path.splitext(sys.argv[1])[1].lower() != '.rsp':
        print("Invalid file!", file=sys.stderr)
        print("Usage:\n    rsp_hash_gen.py <path_to_rsp_file>")
        return 1

    tests = parse_rsp(sys.argv[1])
    if tests is None or len(tests.entries) == 0:
        print("Invalid file or unsupported hash RSP test vector file!", file=sys.stderr)
        print("Usage:\n    rsp_hash_gen.py <path_to_rsp_file>")
        return 1

    indent_size = 4
    hash_func = get_hashfunc(tests.algo)
    match tests:
        case MonteCarloTestVectors():
            print("/*NIST Monte Carlo tests")
            print(tests.header)
            print("*/\n{")
            print(format_var(f'hashes = {hash_func}_monte_carlo_prng( "{tests.seed}"_hex )', True, indent_size))
            for e in tests.entries:
                print(indent(f'REQUIRE_EQUAL( hashes[{e.count}], \"{e.md}\"_hex );', indent_size))
            print("}")
        case MsgTestVectors():
            out_file = os.path.splitext(sys.argv[1])[0] + '.hpp'
            with open(out_file, "w") as f:
                print("/* NIST tests", file=f)
                print(tests.header, file=f)
                print("*/\n{", file=f)
                declvar = True
                for tv in tests.entries:
                    print(indent(f"// Len = { tv.msg_len }", indent_size), file=f)
                    msg = f'"{ tv.msg }"_hex' if tv.msg_len > 0 else 'bytes()'
                    print(format_var(f'msg = { msg }', declvar, indent_size), file=f)
                    print(format_var(f'md = "{ tv.md }"_hex', declvar, indent_size), file=f)
                    print(indent(f'REQUIRE_EQUAL( {hash_func}( msg ), md );\n', indent_size), file=f)
                    declvar = False
                print("}\n", file=f)
            print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
