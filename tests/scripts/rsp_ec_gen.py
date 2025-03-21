#!/bin/python
# Test case generator for EC PKV and ECDSA signature verification test vectors from NIST FIPS 186-4 standard
# Author: Crt Vavros

import collections, enum, os, re, sys
from typing import Dict, List, TextIO, Tuple, Optional

curve_pattern      = re.compile(r"^\[[B,K,P]-[0-9]+]$", re.IGNORECASE)
curve_hash_pattern = re.compile(r"^\[[B,K,P]-[0-9]+,[A-Za-z0-9-]+]$", re.IGNORECASE)

supported_curves = ['P-256','P-384', 'P-521']
supported_hashes = ['sha1', 'sha256', 'sha384', 'sha512']

curve_var = {
    'P-256' : 'secp256r1',
    'P-384' : 'secp384r1',
    'P-521' : 'secp521r1',
}

curve_sizes = {
    'P-256' : 256,
    'P-384' : 384,
    'P-521' : 521,
}

curve_primes = {
    'P-256' : 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    'P-384' : 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    'P-521' : 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
}

class TestType(enum.Enum):
    Unknown      = -1,
    ECPKV        =  1,
    ECKeyPair    =  2
    SigVer_ECDSA =  3

class TestVectors:
    def __init__(self):
        self.header   = ''
        self.type     = TestType.Unknown

class EcTestVector:
    def __init__(self):
        self.curve_name: str = ''
        self.d: str  = '' # private key
        self.Qx: str = ''
        self.Qy: str = ''
        self.hash_algo: str = ''
        self.msg: str = ''
        self.r: str = ''
        self.s: str = ''
        self.result: str = ''

ECTestEntries = Dict[str, List[EcTestVector]]

class EcTestVectors(TestVectors):
    def __init__(self):
        self.entries: Optional[ECTestEntries] = None # dictionary {[curve,hash] or [curve] : [EcTestVector]}

def parse_header(file: TextIO)-> Tuple[str, TestType, int]:
    file.seek(0)
    header = ''
    type  = TestType.Unknown
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('#'):
            header += line[1:].strip() + "\n"
            if '"PKV" information' in line:
                type = TestType.ECPKV
            elif 'Key Pair" information' in line:
                type = TestType.ECKeyPair
            elif 'SigVer" information' in line:
                type = TestType.SigVer_ECDSA
        elif curve_pattern.match(line) or curve_hash_pattern.match(line):
            return (header, type, num)
        elif len(line) != 0:
            print(f'WARNING: Unexpected end of header or corrupted header at line: {num + 1}')
            return (header.strip(), type,  num)
    print(f'ERROR: Reached end of a file while parsing file header')
    return ("", type,  0)

def normalized_hex_str(str: str):
    if len(str) % 2 != 0:
        return '0' + str
    return str

def parse_ec_test_vector_entries(file: TextIO, offest: int, type: TestType) -> Optional[ECTestEntries]:
    if type == TestType.Unknown:
        return None

    key = ''
    dictionary: ECTestEntries = {}
    entries: List[EcTestVector] = []
    tv = EcTestVector()
    curve_name = ''
    hash_algo = ''
    b_parsed = False

    file.seek(offest)
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

        if line.startswith('d '):
            tv.d = normalized_hex_str(line.replace('d ', '').strip('= '))
            b_parsed = True
        elif line.startswith('Qx '):
            tv.Qx = normalized_hex_str(line.replace('Qx ', '').strip('= '))
            b_parsed = True
        elif line.startswith('Qy '):
            tv.Qy = normalized_hex_str(line.replace('Qy ', '').strip('= '))
            b_parsed = True
        elif line.startswith('R '):
            tv.r = normalized_hex_str(line.replace('R ', '').strip('= '))
            b_parsed = True
        elif line.startswith('S '):
            tv.s = normalized_hex_str(line.replace('S ', '').strip('= '))
            b_parsed = True
        elif line.startswith('Msg'):
            tv.msg = normalized_hex_str(line.replace('Msg', '').strip('= '))
            b_parsed = True
        elif line.startswith('Result'):
            tv.result = line.replace('Result', '').strip('= ')
            b_parsed = True
            if not tv.result.startswith('P') and not tv.result.startswith('F'):
                print(f"WARNING: Unknown result value '{tv.result}' on line:{num}, skipping test vector")
            else:
                entries.append(tv)
            tv = EcTestVector()
            tv.curve_name = curve_name
            tv.hash_algo = hash_algo
            b_parsed = False
        elif len(line) == 0 and type == TestType.ECKeyPair and b_parsed:
            entries.append(tv)
            tv = EcTestVector()
            tv.curve_name = curve_name
            tv.hash_algo = hash_algo
            b_parsed = False

    if len(key) != 0:
        dictionary[key] = entries
    return dictionary if len(dictionary) else None

def parse_rsp(file_path: str):
    header = ''
    with open(file_path) as f:
        header, type, end_line_num = parse_header(f)
        entries = parse_ec_test_vector_entries(f, end_line_num, type)
        tests          = EcTestVectors()
        tests.header   = header
        tests.type     = type
        tests.entries  = entries
        return tests

def format_var(var: str, decl: bool, indent_size: int = 0, var_type: str = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def get_hash_func_name(hash_algo: str) -> str:
    if 'sha3' in hash_algo or 'sha384' in hash_algo:
        return hash_algo
    return f'eosio::{ hash_algo }'

def format_hash_func_call(hash_algo: str, msg_var_name: str) -> str:
    if 'sha3' in hash_algo or 'sha384' in hash_algo:
        return f'{ hash_algo }( { msg_var_name } )'
    return f'eosio::{ hash_algo }( (const char*){ msg_var_name }.data(), { msg_var_name }.size() )'

def tvecpkv2str(tv: EcTestVector, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += indent(f'// Result = { tv.result }\n', indent_size)
    if tv.result == 'P' or tv.result[0] == 'P':
        test_str += format_var(f'q = curve.make_point( "{ tv.Qx }", "{ tv.Qy }", /*verify=*/ true )', decl_vars, indent_size) + '\n'
        test_str += indent('REQUIRE_EQUAL( q.is_valid(), true )', indent_size) + '\n'
        test_str += indent('REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )', indent_size) + '\n'
        test_str += indent('REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), true )', indent_size) + '\n'
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
            test_str += indent('REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), false )', indent_size) + '\n'
    return test_str

def tveckeypair2str(tv: EcTestVector, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += format_var(f'k  = bn_t( "{ tv.d }" )', decl_vars, indent_size) + '\n'
    test_str += format_var(f'q  = curve.make_point( "{ tv.Qx }", "{ tv.Qy }" )', decl_vars, indent_size) + '\n'
    test_str += format_var(f'qg = curve.generate_point( k )', decl_vars, indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( qg, q )', indent_size) + '\n\n'

    test_str += format_var(f'qg_proj = curve.generate_point<point_proj_type>( k )', decl_vars, indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( qg_proj.is_valid() , true )', indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( qg_proj.to_affine(), q    )', indent_size) + '\n\n'

    test_str += format_var(f'qg_jacobi = curve.generate_point<point_jacobi_type>( k )', decl_vars, indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( qg_jacobi.is_valid() , true )', indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )', indent_size) + '\n'
    return test_str

def tvecdsa2str(tv: EcTestVector, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += format_var(f'pubkey = curve.make_point( "{ tv.Qx }", "{ tv.Qy }" )', decl_vars, indent_size) + '\n'
    test_str += format_var(f'm      = "{ tv.msg }"_hex', decl_vars, indent_size) + '\n'
    test_str += format_var(f'sig_r  = "{ tv.r }"', decl_vars, indent_size, 'bn_t') + '\n'
    test_str += format_var(f'sig_s  = "{ tv.s }"', decl_vars, indent_size, 'bn_t') + '\n'
    test_str += format_var(f"r = {('true' if tv.result == 'P' or tv.result[0] == 'P' else 'false')}", decl_vars, indent_size) + f' // Result = { tv.result }\n'
    test_str += format_var(f'd = { format_hash_func_call(tv.hash_algo, "m") }', decl_vars, indent_size) + '\n'
    test_str += indent('test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );', indent_size) + '\n'
    return test_str

def indent(text:str, amount: int , ch: str = ' '):
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

    if tests.entries is None:
        print("File contains no test cases!")
        return 0

    out_file = os.path.splitext(sys.argv[1])[0] + '.hpp'
    with open(out_file, "w") as f:
        test_cases: Dict[str, Dict[str, str]] = collections.defaultdict(dict)
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
                        case TestType.ECKeyPair:
                            tcase = tveckeypair2str(tv, decl_vars)
                        case TestType.SigVer_ECDSA:
                            tcase = tvecdsa2str(tv, decl_vars)
                    test_cases[tv.curve_name][key] += tcase + '\n'

        print(f"/*\nGenerated from: '{sys.argv[1]}'\n", file=f)
        print(tests.header, file=f)
        print("*/\n\n", file=f)

        indent_size = 4
        test_type = 'unknown'
        match tests.type:
            case TestType.ECPKV:
                test_type = 'ec_pkv'
            case TestType.ECKeyPair:
                test_type = 'ec_keypair'
            case TestType.SigVer_ECDSA:
                test_type = 'ecdsa'

        for curve_name, testsd in test_cases.items():
            tname = f'{test_type}_{curve_var[curve_name]}_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(indent('{', indent_size), file=f)
            print(indent(f'using { curve_var[curve_name] }_t = std::remove_cv_t<decltype( ack::ec_curve::{ curve_var[curve_name] })>;', indent_size * 2), file=f)
            print(indent(f'using bn_t = typename { curve_var[curve_name] }_t::int_type;', indent_size * 2), file=f)
            print(indent(f'const auto& curve = ack::ec_curve::{ curve_var[curve_name] };', indent_size * 2), file=f)
            print(indent(f'using point_proj_type = ack::ec_point_fp_proj<{ curve_var[curve_name] }_t>;', indent_size * 2), file=f)
            print(indent(f'using point_jacobi_type = ack::ec_point_fp_jacobi<{ curve_var[curve_name] }_t>;', indent_size * 2), file=f)

            for curve_hash, tests in testsd.items():
                # Each test vector set is wrapped in {}
                print(indent( f'// {curve_hash}', indent_size * 2), file=f )
                print(indent( '{', indent_size * 2), file=f )
                print(indent( f'{tests}', indent_size * 2), file=f )
                print(indent( '}\n', indent_size * 2), file=f )
            print(indent('}', indent_size), file=f )
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

    print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
