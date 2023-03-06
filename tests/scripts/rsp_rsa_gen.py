#!/bin/python
# Test case generator for RSA PCKS#1 v1.5 and RSASSA-PSS signature verification test vectors from NIST FIPS 186-4 standard
# Author: Crt Vavros

import collections, enum, os, sys

class TestType(enum.Enum):
    Unknown    = -1,
    SigVer_RSAv15     = 1,
    SigVer_RSASSA_PSS = 2

class TestVectors:
    def __init__(self):
        self.header   = ''
        self.type     = TestType.Unknown

class RsaTestVector:
    def __init__(self):
        self.hash_algo = ''
        self.n = ''
        self.e = ''
        self.d = ''
        self.msg = ''
        self.sig = ''
        self.salt_len = 0
        self.result = ''

class RsaTestVectors(TestVectors):
    def __init__(self):
        self.entries = None # dictionary {[mod = <bit:size>] : [MsgTestVector]}

def parse_header(file):
    file.seek(0)
    header = ''
    type  = TestType.Unknown
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('#'):
            header += line[1:].strip() + "\n"
            if 'SigVer PKCS#1 Ver 1.5' in line:
                type = TestType.SigVer_RSAv15
            elif 'SigVer RSA PKCS#1 RSASSA-PSS' in line:
                type = TestType.SigVer_RSASSA_PSS
        elif "[mod = " in line:
            #mod_len = round(int(line.strip('[]= L').strip()) / 8)
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
    tv = RsaTestVector()
    for num, line in enumerate(file):
        line = line.strip()
        if line.startswith('[mod = '):
            if len(key) != 0:
                dictionary[key] = entries
                entries = []
            key = line
        if line.startswith('n '):
            tv.n = normalized_hex_str(line.replace('n ', '').strip('= '))
        elif line.startswith('SHAAlg'):
            tv.hash_algo = line.replace('SHAAlg', '').strip('= ').lower()
        elif line.startswith('e '):
            tv.e = normalized_hex_str(line.replace('e ', '').strip('= '))
        elif line.startswith('d '):
            tv.d = line.replace('d ', '').strip('= ')
            if tv.d == '0':
                tv.d = ''
            else:
                tv.d = normalized_hex_str(tv.d)
        elif line.startswith('Msg'):
            tv.msg = normalized_hex_str(line.replace('Msg', '').strip('= '))
        elif line.startswith('S '):
            tv.sig = normalized_hex_str(line.replace('S ', '').strip('= '))
        elif line.startswith('SaltVal'):
            salt = normalized_hex_str(line.replace('SaltVal', '').strip('= '))
            tv.salt_len = len(salt) / 2 if salt != '00' else 0
        elif line.startswith('Result'):
            tv.result = line.replace('Result', '').strip('= ')
            if not tv.result.startswith('P') and not tv.result.startswith('F'):
                print(f"WARNING: Unknown result value '{tv.result}' on line:{num}, skipping test vector")
            else:
                entries.append(tv)
            tv = RsaTestVector()

    if len(key) != 0:
        dictionary[key] = entries
    return dictionary

def parse_rsp(file_path):
    header = ''
    with open(file_path) as f:
        header, type, end_line_num = parse_header(f)
        entries = parse_rsa_test_vector_entries(f, end_line_num)
        tests   = RsaTestVectors()
        tests.header   = header
        tests.type     = type
        tests.entries  = entries
        return tests

def format_var(var: str, decl: bool) -> str:
    return f'{"auto " if decl else ""}{var};'

def tvrsa2str(tv: RsaTestVector, decl_vars: bool) -> str:
    test_str = ''
    if len(tv.n) > 0:
        test_str += format_var(f'n = "{tv.n }"_hex', decl_vars) + '\n'
    test_str += format_var(f'e = "{tv.e}"_hex', decl_vars) + '\n'
    test_str += format_var(f'm = "{tv.msg}"_hex', decl_vars) + '\n'
    test_str += format_var(f's = "{tv.sig}"_hex', decl_vars) + '\n'
    test_str += format_var(f"r = {('true' if tv.result == 'P' else 'false')}", decl_vars) + f'// Result = {tv.result}\n'
    test_str += format_var(f'd = eosio::{tv.hash_algo}( (const char*)m.data(), m.size() )', decl_vars) + '\n'
    test_str += f'REQUIRE_EQUAL( r, verify_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s ));\n'
    if tv.result == 'P':
        test_str += f'assert_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 {tv.hash_algo.upper()} signature" );\n'
    else:
        test_str += (f'REQUIRE_ASSERT( "RSA PKCS1.5 {tv.hash_algo.upper()} signature verification failed", [&]() {{\n' \
        f'    assert_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s,\n' \
        f'        "RSA PKCS1.5 {tv.hash_algo.upper()} signature verification failed"\n' \
        '    );\n' \
        '})\n')

    test_str += '\n'
    return test_str

def tvrsapss2str(tv: RsaTestVector, decl_vars: bool) -> str:
    test_str = ''
    if len(tv.n) > 0:
        test_str += format_var(f'n = "{tv.n}"_hex', decl_vars) + '\n'
    test_str += format_var(f'e = "{tv.e}"_hex', decl_vars) + '\n'
    test_str += format_var(f'm = "{tv.msg}"_hex', decl_vars) + '\n'
    test_str += format_var(f's = "{tv.sig}"_hex', decl_vars) + '\n'
    test_str += format_var(f"r = {('true' if tv.result == 'P' else 'false')}", decl_vars) + f'// Result = {tv.result}\n'
    test_str += format_var(f'd = eosio::{tv.hash_algo}( (const char*)m.data(), m.size() )', decl_vars) + '\n'
    test_str += format_var(f'l = {str(int(tv.salt_len))}', decl_vars) + '\n'
    test_str += f'REQUIRE_EQUAL( r, verify_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s ));\n'
    if tv.result == 'P':
        test_str += f'assert_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s, "Failed verifying RSA PSS MGF1 {tv.hash_algo.upper()} signature" );\n'
    else:
        test_str += (f'REQUIRE_ASSERT( "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed", [&]() {{\n' \
        f'    assert_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s,\n' \
        f'        "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed"\n' \
        f'    );\n' \
        '})\n')

        test_str += "\n// Test verification fails when salt len is not provided\n"
        test_str += f'REQUIRE_EQUAL( r, verify_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e), d, s ));\n'
        test_str += (f'REQUIRE_ASSERT( "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed", [&]() {{\n' \
        f'    assert_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e), d, s,\n' \
        f'        "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed"\n' \
        f'    );\n' \
        '})\n')

    test_str += '\n'
    return test_str

def indent(text:str, amount, ch=' '):
    padding = amount * ch
    return ''.join(padding+line for line in text.splitlines(True))

def main():
    if len(sys.argv) < 2:
        print("Usage:\n    rsp_rsa_gen.py <path_to_rsp_file>")
        return 0
    elif os.path.splitext(sys.argv[1])[1].lower() != '.rsp':
        print("Invalid file!", file=sys.stderr)
        print("Usage:\n    rsp_rsa_gen.py <path_to_rsp_file>")
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
                if tv.hash_algo == 'sha1' or tv.hash_algo == 'sha256' or tv.hash_algo == 'sha512':
                    decl_vars = False
                    if tv.hash_algo not in test_cases:
                        decl_vars = True
                    if key not in test_cases[tv.hash_algo]:
                        test_cases[tv.hash_algo][key] = ''
                    match tests.type:
                        case TestType.SigVer_RSAv15:
                            test_cases[tv.hash_algo][key] += tvrsa2str(tv, decl_vars)
                        case TestType.SigVer_RSASSA_PSS:
                            test_cases[tv.hash_algo][key] += tvrsapss2str(tv, decl_vars)

        print(f"/*\nGenerated from: '{sys.argv[1]}'\n", file=f)
        print(tests.header, file=f)
        print("*/\n\n", file=f)

        test_type = 'rsa_pkcs_1_5' if tests.type == TestType.SigVer_RSAv15 else 'rsa_pss_mgf1'
        for hash, testsd in test_cases.items():
            tname = f'{test_type}_{hash}_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(indent('{', 4), file=f)
            for mod_len, tests in testsd.items():
                print(indent(f'// {mod_len}', 8), file=f)
                print(indent(f'{tests}', 8), file=f)
            print(indent('}', 4), file=f)
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

    print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
