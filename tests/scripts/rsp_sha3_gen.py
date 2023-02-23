#!/bin/python
# Test case generator for SHA3 test vectors from NIST FIPS 202 standard
# Author: Crt Vavros

import os, sys

supported_lengths = [
    256, 384, 512
]

class TestVectors:
    def __init__(self):
        self.header   = ''
        self.hash_len = 0

class MsgTestVector:
    def __init__(self):
        self.msg = ''
        self.msg_len = 0
        self.md =''

class MsgTestVectors(TestVectors):
    def __init__(self):
        self.entries = [MsgTestVector]

class MonteCarloTestVector:
    def __init__(self):
        self.count = 0
        self.md =''

class MonteCarloTestVectors(TestVectors):
    def __init__(self, seed: str):
        self.seed    = seed
        self.entries = [MonteCarloTestVector]

def parse_header(file):
    file.seek(0)
    header = ''
    hash_len = 0
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('#'):
            header += line[1:].strip() + "\n"
        elif "[L = " in line:
            hash_len = round(int(line.strip('[]= L').strip()))
            return (header, hash_len, num)
        elif len(line) != 0:
            print("warning: unexpected end of header or corrupted header at line: {}".format(num + 1))
            return (header.strip(), hash_len, num)

def parse_monte_carlo_entries(file, current_line):
    seed = ''
    entries = []
    tv = MonteCarloTestVector()
    for num, line in enumerate(file):
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

def parse_msg_test_vector_entries(file, current_line):
    entries = []
    tv = MsgTestVector()
    for num, line in enumerate(file):
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


def parse_rsp(file_path):
    header = ''
    hash_len = 0
    with open(file_path) as f:
        header, hash_len, end_line_num = parse_header(f)
        if hash_len not in supported_lengths:
            return None

        # Try to make sure that this is a SHA3 RSP file
        if "SHA3" not in header and "Sha3" not in header and "sha3" not in header:
            return None

        if "Monte" in header:
            seed, entries = parse_monte_carlo_entries(f, end_line_num)
            tests = MonteCarloTestVectors(seed)
            tests.header   = header
            tests.hash_len = hash_len
            tests.entries  = entries
            return tests
        else:
            entries = parse_msg_test_vector_entries(f, end_line_num)
            tests = MsgTestVectors()
            tests.header   = header
            tests.hash_len = hash_len
            tests.entries  = entries
            return tests

def indent(text:str, width, ch=' '):
    padding = width * ch
    return ''.join(padding+line for line in text.splitlines(True))

def format_var(var: str, decl: bool, indent_size: int = 0, var_type = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def main():
    if len(sys.argv) < 2:
        print("Usage:\n    rsp_sha3_gen.py <path_to_rsp_fle>")
        return 0
    elif os.path.splitext(sys.argv[1])[1].lower() != '.rsp':
        print("Invalid file!", file=sys.stderr)
        print("Usage:\n    rsp_sha3_gen.py <path_to_rsp_fle>")
        return 1

    tests = parse_rsp(sys.argv[1])
    if tests is None or len(tests.entries) == 0:
        print("Invalid file or unsupported SHA3 RSP test vector file!", file=sys.stderr)
        print("Usage:\n    rsp_sha3_gen.py <path_to_rsp_fle>")
        return 1

    indent_size = 4
    if isinstance(tests, MonteCarloTestVectors):
        print("/*NIST Monte Carlo tests")
        print(tests.header)
        print("*/\n{")
        print(format_var(f'hashes = monte_carlo_sha3_{tests.hash_len}( "{tests.seed}"_hex )', True, indent_size))
        for e in tests.entries:
            print(indent(f'REQUIRE_EQUAL( hashes[{e.count}], \"{e.md}\"_hex );', indent_size))
        print("}")
    else:
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
                print(indent(f'REQUIRE_EQUAL( sha3_{tests.hash_len}( msg ), md );\n', indent_size), file=f)
                declvar = False
            print("}\n", file=f)
        print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
