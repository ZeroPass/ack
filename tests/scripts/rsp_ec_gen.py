#!/bin/python
# Test case generator for EC PKV and ECDSA signature verification test vectors from NIST FIPS 186-4 standard
# Author: Crt Vavros

import collections, enum, os, re, sys

curve_pattern = re.compile(r"^\[P-[0-9]+]$", re.IGNORECASE)
curve_hash_pattern = re.compile(r"^\[P-[0-9]+,[A-Za-z0-9-]+]$", re.IGNORECASE)

supported_curves = ['P-256']
supported_hashes = ['sha1', 'sha256', 'sha512']

curve_var = {
    'P-256' : 'secp256r1',
}

curve_sizes = {
    'P-256' : 256,
}

curve_primes = {
    'P-256' : 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
}

class TestType(enum.Enum):
    Unknown      = -1,
    ECPKV        = 1,
    SigVer_ECDSA = 2

class TestVectors:
    def __init__(self):
        self.header   = ''
        self.type     = TestType.Unknown

class EcTestVector:
    def __init__(self):
        self.curve_name = ''
        self.Qx = ''
        self.Qy = ''
        self.hash_algo = ''
        self.msg = ''
        self.r = ''
        self.s = ''
        self.result = ''

class EcTestVectors(TestVectors):
    def __init__(self):
        self.entries = None # dictionary {[curve,hash] or [curve] : [MsgTestVector]}

def parse_header(file):
    file.seek(0)
    header = ''
    type  = TestType.Unknown
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('#'):
            header += line[1:].strip() + "\n"
            if '"PKV" information' in line:
                type = TestType.ECPKV
            elif 'SigVer" information' in line:
                type = TestType.SigVer_ECDSA
        elif curve_pattern.match(line) or curve_hash_pattern.match(line):
            return (header, type, num)
        elif len(line) != 0:
            print(f'warning: unexpected end of header or corrupted header at line: {num + 1}')
            return (header.strip(), num)


def normalized_hex_str(str):
    if len(str) % 2 != 0:
        return '0' + str
    return str

def parse_rsa_test_vector_entries(file, current_line):
    file.seek(current_line)

    key = ''
    dictionary = {}
    entries = []
    tv = EcTestVector()
    curve_name = ''
    hash_algo = ''
    for num, line in enumerate(file):
        line = line.strip()
        if curve_pattern.match(line) or curve_hash_pattern.match(line):
            if len(key) != 0:
                dictionary[key] = entries
                entries = []
            key = line
            epos = key.find(',')
            if epos != -1: # hash
                hash_algo = key[epos + 1: key.find(']')].replace('-', '').strip().lower()
                tv.hash_algo = hash_algo
            else:
                epos = key.find(']')
            curve_name = key[1 : epos].strip()
            tv.curve_name = curve_name

        if line.startswith('Qx '):
            tv.Qx = normalized_hex_str(line.replace('Qx ', '').strip('= '))
        elif line.startswith('Qy '):
            tv.Qy = normalized_hex_str(line.replace('Qy ', '').strip('= '))
        elif line.startswith('R '):
            tv.r = normalized_hex_str(line.replace('R ', '').strip('= '))
        elif line.startswith('S '):
            tv.s = normalized_hex_str(line.replace('S ', '').strip('= '))
        elif line.startswith('Msg'):
            tv.msg = normalized_hex_str(line.replace('Msg', '').strip('= '))
        elif line.startswith('Result'):
            tv.result = line.replace('Result', '').strip('= ')
            if not tv.result.startswith('P') and not tv.result.startswith('F'):
                print(f"WARNING: Unknown result value '{tv.result}' on line:{num}, skipping test vector")
            else:
                entries.append(tv)
            tv = EcTestVector()
            tv.curve_name = curve_name
            tv.hash_algo = hash_algo

    if len(key) != 0:
        dictionary[key] = entries
    return dictionary

def parse_rsp(file_path):
    header = ''
    with open(file_path) as f:
        header, type, end_line_num = parse_header(f)
        entries = parse_rsa_test_vector_entries(f, end_line_num)
        tests   = EcTestVectors()
        tests.header   = header
        tests.type     = type
        tests.entries  = entries
        return tests

def format_var(var: str, decl: bool, indent_size: int = 0, var_type = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def tvecpkv2str(tv: EcTestVector, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += indent(f'// Result = { tv.result }\n', indent_size)
    if tv.result == 'P' or tv.result[0] == 'P':
        test_str += format_var(f'q = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ true )', decl_vars, indent_size) + '\n'
        test_str += indent('REQUIRE_EQUAL( q.is_valid(), true )', indent_size) + '\n'
        test_str += indent('REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )', indent_size) + '\n'
    else:
        if '1 - Q_x or Q_y out of range' in tv.result:
            p = curve_primes[tv.curve_name]
            error = "Invalid point x coordinate" if int(tv.Qx, 16) >= p else "Invalid point y coordinate"
            test_str += indent(f'REQUIRE_ASSERT( "{error}", [&]() {{\n', indent_size)
            test_str += format_var(f' qi = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ false )', True, indent_size * 2) + '\n'
            test_str += indent('})\n\n', indent_size)

            test_str += indent(f'REQUIRE_ASSERT( "{error}", [&]() {{\n', indent_size)
            test_str += format_var(f' qi = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ true )', True, indent_size * 2) + '\n'
            test_str += indent('})\n', indent_size)
        else:
            test_str += indent(f'REQUIRE_ASSERT( "Invalid point", [&]() {{\n', indent_size)
            test_str += format_var(f' qi = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ true )', True, indent_size * 2) + '\n'
            test_str += indent('})\n\n', indent_size)

            test_str += format_var(f'q = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ false )', decl_vars, indent_size) + '\n'
            test_str += indent('REQUIRE_EQUAL( q.is_valid(), false )', indent_size) + '\n'
            test_str += indent('REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), false )', indent_size) + '\n'
    return test_str

def tvecdsa2str(tv: EcTestVector, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += format_var(f'pubkey = curve.make_point( "{ tv.Qx }", "{ tv.Qy }" )', decl_vars, indent_size) + '\n'
    test_str += format_var(f'm      = "{ tv.msg }"_hex', decl_vars, indent_size) + '\n'
    test_str += format_var(f'sig_r  = "{ tv.r }"', decl_vars, indent_size, 'bn_t') + '\n'
    test_str += format_var(f'sig_s  = "{ tv.s }"', decl_vars, indent_size, 'bn_t') + '\n'
    test_str += format_var(f"r = {('true' if tv.result == 'P' or tv.result[0] == 'P' else 'false')}", decl_vars, indent_size) + f' // Result = { tv.result }\n'
    test_str += format_var(f'd = eosio::{ tv.hash_algo }( (const char*)m.data(), m.size() )', decl_vars, indent_size) + '\n'
    test_str += indent('test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );', indent_size) + '\n'
    return test_str

def indent(text:str, amount, ch=' '):
    padding = amount * ch
    return ''.join(padding+line for line in text.splitlines(True))

def main():
    if len(sys.argv) < 2:
        print("Usage:\n    rsp_ec_gen.py <path_to_rsp_file>")
        return 0
    elif os.path.splitext(sys.argv[1])[1].lower() != '.rsp':
        print("Invalid file!", file=sys.stderr)
        print("Usage:\n    rsp_ec_gen.py <path_to_rsp_file>")
        return 1

    tests = parse_rsp(sys.argv[1])
    if tests.type == TestType.Unknown:
        print("Couldn't determine test(s) type", file=sys.stderr)
        return 1

    out_file = os.path.splitext(sys.argv[1])[0]+'.hpp'
    with open(out_file, "w") as f:
        test_cases = collections.defaultdict(dict)
        for key, entries in tests.entries.items():
            for tv in entries:
                if tv.curve_name in supported_curves:
                    if tests.type == TestType.SigVer_ECDSA and tv.hash_algo not in supported_hashes:
                        continue

                    decl_vars = False
                    # if tv.curve_name not in test_cases:
                    #     decl_vars = True
                    if key not in test_cases[tv.curve_name]:
                        test_cases[tv.curve_name][key] = ''
                        decl_vars = True

                    tcase = ''
                    match tests.type:
                        case TestType.ECPKV:
                            tcase = tvecpkv2str(tv, decl_vars)
                        case TestType.SigVer_ECDSA:
                            tcase = tvecdsa2str(tv, decl_vars)
                    test_cases[tv.curve_name][key] += tcase + '\n'

        print(f"/*\nGenerated from: '{sys.argv[1]}'\n", file=f)
        print(tests.header, file=f)
        print("*/\n\n", file=f)

        indent_size = 4
        test_type = 'ecdsa' if tests.type == TestType.SigVer_ECDSA else 'ec_pkv'
        for curve_name, testsd in test_cases.items():
            tname = f'{test_type}_{curve_var[curve_name]}_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(indent('{', indent_size), file=f)
            print(indent(f'using bn_t = ack::ec_fixed_bigint<{ curve_sizes[curve_name] }>;', indent_size*2), file=f)
            print(indent(f'const auto& curve = ack::ec_curve::{ curve_var[curve_name] };', indent_size*2), file=f)
            for curve_hash, tests in testsd.items():
                # Each test vector set is wrapped in {}
                print(indent( f'// {curve_hash}', indent_size*2), file=f )
                print(indent( '{', indent_size*2), file=f )
                print(indent( f'{tests}', indent_size*2), file=f )
                print(indent( '}\n', indent_size*2), file=f )
            print(indent('}', indent_size), file=f )
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

    print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
