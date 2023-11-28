#!/bin/python
# Test case generator for RSA PCKS#1 v1.5, RSASSA-PSS and ECDSA signature verification test vectors from Google Wycheproof project
# Author: Crt Vavros

from asn1crypto.algos import DSASignature
import enum, json, urllib.parse, urllib.request, os, sys
from pathlib import Path
from typing import List, Optional

#supported_schemas  = ('rsassa_pkcs1_verify_schema.json', 'rsassa_pss_verify_schema.json', 'ecdsa_p1363_verify_schema.json', 'ecdsa_verify_schema.json')
supported_hashes    = ('SHA-1', 'SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512',)
supported_mgfs      = ('MGF1',)
unacceptable_flags  = ('MissingNull', )
rsa_skip_tv_flags   = () # Skipped test vectors with these flags
ecdsa_skip_tv_flags = ('BER',) # Skipped test vectors with these flags
supported_curves    = ('secp256k1', 'secp256r1',)

rsa_schemas         = ('rsassa_pkcs1_verify_schema.json', 'rsassa_pss_verify_schema.json',)
ecdsa_schemas       = ('ecdsa_p1363_verify_schema.json', 'ecdsa_verify_schema.json',)
rsa_group_types     = ('RsassaPkcs1Verify', 'RsassaPssVerify', )
ecdsa_group_types   = ('EcdsaP1363Verify', 'EcdsaVerify', )
supported_schemas   = tuple( rsa_schemas + ecdsa_schemas )

curve_sizes = {
    'secp256k1' : 256,
    'secp256r1' : 256,
}

ans1_error_tests_to_skip = (
    'indefinite length without termination',
    'incorrect length of sequence',
    'wrong length of sequence',
    'uint32 overflow in length of sequence',
    'uint64 overflow in length of sequence',
    'length of sequence = 2**31 - 1',
    'length of sequence = 2**32 - 1',
    'length of sequence = 2**40 - 1',
    'length of sequence = 2**64 - 1'

)

class TestType(enum.Enum):
    Unknown           = -1,
    SigVer_RSAv15     = 1,
    SigVer_RSASSA_PSS = 2,
    SigVer_ECDSA      = 3

class RsaTest:
    def __init__(self):
        self.msg = ''
        self.sig = ''
        self.result = ''
        self.comment = ''

class RsaTestVector:
    def __init__(self):
        self.hash_algo = ''
        self.n = ''
        self.e = ''
        self.salt_len: Optional[int] = None
        self.tests: List[RsaTest] = []

class RsaTestVectors:
    def __init__(self):
        self.header   = ''
        self.type     = TestType.Unknown
        self.entries: List[RsaTestVector] = []

class ECDSATest:
    def __init__(self):
        self.msg = ''
        self.r = ''
        self.s = ''
        self.result = ''
        self.comment = ''

class ECDSATestVector:
    def __init__(self):
        self.curve = ''
        self.Qx = '' # x coordinate of the public key
        self.Qy = '' # y coordinate of the public key
        self.hash_algo = ''
        self.tests: List[ECDSATest] = []

class ECDSATestVectors:
    def __init__(self):
        self.header   = ''
        self.type     = TestType.Unknown
        self.entries: List[ECDSATestVector] = []

def is_url(path: str) -> bool:
    return urllib.parse.urlparse(path).scheme in ('http', 'https',)

def normalize_hash_algo(hash_algo: str) -> str:
    s = '_' if 'sha3' in hash_algo.lower() else ''
    return hash_algo.replace('-', s).lower()

def normalized_hex_str(str, min_width=-1):
    str = str.replace('-', '')
    str = str.replace('0x', '').replace('0X', '')
    if len(str) % 2 != 0:
        str = '0' + str
    if min_width > 0:
        if len(str) < min_width:
            return '0' * (min_width - len(str)) + str
    return str

def normalize_hex_integer(hex_int, byte_len = -1):
    if len(hex_int) == 0:
        return hex_int
    hex_int = normalized_hex_str(hex_int)

    """
    Normalizes hex string to be 2^n and removes leading 0x00 for unsigned integers
    """
    if len(hex_int) > 2:
        bint = bytes.fromhex(hex_int)
        if bint[0] == 0x00 and bint[1] != 0x00:
           bint = bint[1::]
        hex_int = bint.hex()
    hex_int = normalized_hex_str(hex_int)
    if byte_len > -1:
        if (len(hex_int) /2 < byte_len):
            diff = int(byte_len - len(hex_int)/2)
            hex_int = '00' * diff + hex_int
    return hex_int

def skip_tv(flags: List[str], skip_flags: List[str]) -> bool:
    for flag in flags:
        if flag in skip_flags:
            return True
    return False

def parse_rsa_verify_tv(wptv_json: dict, type:TestType) -> Optional[RsaTestVector]:
    if wptv_json['type'] not in rsa_group_types:
        print(f"Info: Skipping test group with unsupported test group type: {wptv_json['type']}")
        return None
    if wptv_json['sha'] not in supported_hashes:
        return None
    if type == TestType.SigVer_RSASSA_PSS and \
        (wptv_json['sha'] != wptv_json['mgfSha'] or wptv_json['mgf'] not in supported_mgfs):
        return None
    if len(wptv_json['tests']) == 0:
        return None

    tv = RsaTestVector()
    tv.hash_algo = normalize_hash_algo(wptv_json['sha'])
    tv.n = normalize_hex_integer(wptv_json['n'])
    tv.e = normalize_hex_integer(wptv_json['e'])
    if type == TestType.SigVer_RSASSA_PSS and 'sLen' in wptv_json:
        slen = wptv_json['sLen']
        tv.salt_len = slen
    for t in wptv_json['tests']:
        if skip_tv(t['flags'], rsa_skip_tv_flags):
            continue

        rt = RsaTest()
        rt.msg = normalized_hex_str(t['msg'])
        rt.sig = normalize_hex_integer(t['sig'], len(tv.n)/2)
        rt.result = t['result'] + (f" - flags: {t['flags']}" if len(t['flags']) else '')
        if 'comment' in t:
            rt.comment = t['comment']
        tv.tests.append(rt)
    return tv

def parse_rsa_verify(wp_json: dict) -> RsaTestVectors:
    tests   = RsaTestVectors()
    if 'schema' not in wp_json or wp_json['schema'] not in rsa_schemas:
        return tests

    if 'algorithm' in wp_json:
        tests.header += f"Algorithm: {wp_json['algorithm']}\n"
    if 'generatorVersion' in wp_json:
        tests.header += f"GeneratorVersion: {wp_json['generatorVersion']}\n"
    if 'header' in wp_json:
        tests.header += f"Header: {' '.join(wp_json['header'])}"
    if 'notes' in wp_json and len(wp_json['notes']):
        notes = ''
        for k, v in wp_json['notes'].items():
            notes += f'  {k} - {v}\n'
        tests.header += f"\nNotes: {notes.rstrip()}"

    tests.type = TestType.SigVer_RSAv15 if wp_json['schema'] == 'rsassa_pkcs1_verify_schema.json' else TestType.SigVer_RSASSA_PSS
    for tg in wp_json['testGroups']:
        tv = parse_rsa_verify_tv(tg, tests.type)
        if tv:
            tests.entries.append(tv)
    return tests

def decode_ecdsa_sig(hex_sig, type):
    req_hex_len = -1
    if type == 'EcdsaVerify': # ASN1 DER encoded
        asn1_sig = DSASignature.load(bytes.fromhex(hex_sig), strict=True)
        if (len(asn1_sig) != 2):
            # The ration for this is that the ASN1 DER encoded signature test vectors
            # are strict and require only 2 integers, r and s, in the signature.
            raise ValueError('Invalid ASN1 DER encoded signature')
    else: # P1363 encoded
        asn1_sig = DSASignature.from_p1363(bytes.fromhex(hex_sig))
        if (len(hex_sig) % 2 == 0):
            req_hex_len = int(len(hex_sig) / 2)
    r = asn1_sig['r'].native
    s = asn1_sig['s'].native

    # Normalize r and s to be positive,
    # probably 'MissingZero' flag in ASN1 DER encoded test vector
    if r < 0:
        r = int.from_bytes(asn1_sig['r'].contents, 'big', signed=False)
    if s < 0:
        s = int.from_bytes(asn1_sig['s'].contents, 'big', signed=False)
    return normalized_hex_str(hex( r ), req_hex_len), normalized_hex_str(hex( s ), req_hex_len)

def parse_ecdsa_verify_tv(wptv_json: dict) -> Optional[ECDSATestVector]:
    if wptv_json['type'] not in ecdsa_group_types:
        print(f"Info: Skipping test group with unsupported test group type: {wptv_json['type']}")
        return None
    if wptv_json['sha'] not in supported_hashes:
        return None
    if len(wptv_json['tests']) == 0:
        return None
    if 'key' not in wptv_json:
        print("Info: Skipping test group without raw public key")
        return None

    key = wptv_json['key']
    if 'curve' not in key:
        print("Info: Skipping test group without curve")
        return None
    if key['curve'] not in supported_curves:
        print(f"Info: Skipping test group with unsupported curve: {key['curve']}")
        return None
    if 'wx' not in key or 'wy' not in key:
        print("Info: Skipping test group without raw public key")
        return None

    tv = ECDSATestVector()
    tv.curve     = key['curve']
    tv.Qx        = normalized_hex_str(key['wx'])
    tv.Qy        = normalized_hex_str(key['wy'])
    tv.hash_algo = normalize_hash_algo(wptv_json['sha'])

    for t in wptv_json['tests']:
        if skip_tv(ecdsa_skip_tv_flags, t['flags']):
            continue

        edt = ECDSATest()
        if 'comment' in t:
            edt.comment = t['comment']

        edt.msg = normalized_hex_str(t['msg'])
        try:
            r,s = decode_ecdsa_sig(t['sig'], wptv_json['type'])
            edt.r = r
            edt.s = s
        except Exception as e:
            if wptv_json['type'] == 'EcdsaVerify' and 'invalid' in t['result'].lower():
                # Assuming ASN.1 decoding error and since decoding is not part of the test suite we can skip such test
                continue
            print(edt.comment)
            print(t['sig'])
            raise e

        edt.result = t['result'] + (f" - flags: {t['flags']}" if len(t['flags']) else '')
        tv.tests.append(edt)
    return tv

def parse_ecdsa_verify(wp_json: dict) -> ECDSATestVectors:
    tests   = ECDSATestVectors()
    if 'schema' not in wp_json or wp_json['schema'] not in ecdsa_schemas:
        return tests

    if 'algorithm' in wp_json:
        tests.header += f"Algorithm: {wp_json['algorithm']}\n"
    if 'generatorVersion' in wp_json:
        tests.header += f"GeneratorVersion: {wp_json['generatorVersion']}\n"
    if 'header' in wp_json:
        tests.header += f"Header: {' '.join(wp_json['header'])}"
    if 'notes' in wp_json and len(wp_json['notes']):
        notes = ''
        for k, v in wp_json['notes'].items():
            notes += f'  {k} - {v}\n'
        tests.header += f"\nNotes: {notes.rstrip()}"

    tests.type = TestType.SigVer_ECDSA
    for tg in wp_json['testGroups']:
        tv = parse_ecdsa_verify_tv(tg)
        if tv:
            tests.entries.append(tv)
    return tests

def format_var(var: str, decl: bool, indent_size: int = 0, var_type = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def result_success(result: str) -> bool:
    def allowed_flags():
        for uaf in unacceptable_flags:
            if uaf in result:
                return False
        return True
    return result.startswith(('valid', 'acceptable')) and allowed_flags()

def indent(text:str, amount, ch=' '):
    padding = amount * ch
    return ''.join(padding + line for line in text.splitlines(True))

def comment(text:str, indent = 0, ch=' '):
    padding = indent * ch
    return ''.join(padding + '// ' + line for line in text.splitlines(True))

def get_hash_func_name(hash_algo: str) -> str:
    if 'sha3' in hash_algo:
        return hash_algo
    return f'eosio::{ hash_algo }'

def format_hash_func_call(hash_algo: str, msg_var_name) -> str:
    if 'sha3'  in hash_algo:
        return f'{ hash_algo }( { msg_var_name } )'
    return f'eosio::{ hash_algo }( (const char*){ msg_var_name }.data(), { msg_var_name }.size() )'

def rsa_tv2str(tv: RsaTestVector, decl_vars: bool) -> str:
    test_str = format_var(f'n = "{tv.n }"_hex', decl_vars) + '\n'
    test_str += format_var(f'e = "{tv.e}"_hex', decl_vars) + '\n'
    test_str += '{\n'

    decl_vars = True
    for t in tv.tests:
        valid_sig = result_success(t.result)
        test_sig = format_var(f'm = "{t.msg}"_hex', decl_vars) + '\n'
        test_sig += format_var(f's = "{t.sig}"_hex', decl_vars) + '\n'
        test_sig += format_var(f"r = {('true' if valid_sig else 'false')}", decl_vars) + f' // result = {t.result}\n'
        test_sig += format_var(f'd = { format_hash_func_call(tv.hash_algo, "m") }', decl_vars) + '\n'
        decl_vars = False

        test_sig += f'REQUIRE_EQUAL( r, verify_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s ));\n'
        if valid_sig:
            test_sig += f'assert_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s, "Failed verifying valid RSA PKCS1.5 {tv.hash_algo.upper()} signature" );\n'
        else:
            test_sig += (f'REQUIRE_ASSERT( "RSA PKCS1.5 {tv.hash_algo.upper()} signature verification failed", [&]() {{\n' \
            f'    assert_rsa_{tv.hash_algo}( rsa_public_key_view(n, e), d, s,\n' \
            f'        "RSA PKCS1.5 {tv.hash_algo.upper()} signature verification failed"\n' \
            '    );\n' \
            '})\n')
        test_sig += '\n'
        test_str += indent(test_sig, 4)
    test_str = test_str.rstrip()
    test_str += '\n}'
    return test_str

def rsapss_tv2str(tv: RsaTestVector, decl_vars: bool) -> str:
    test_str = format_var(f'n = "{tv.n }"_hex', decl_vars) + '\n'
    test_str += format_var(f'e = "{tv.e}"_hex', decl_vars) + '\n'
    slen_val = f'std::optional({str(tv.salt_len)})' if tv.salt_len is not None else 'std::nullopt'
    test_str += format_var(f'l = {slen_val}', decl_vars) + '\n'
    test_str += '{\n'

    decl_vars = True
    for t in tv.tests:
        valid_sig = result_success(t.result)
        test_sig = format_var(f'm = "{t.msg}"_hex', decl_vars) + '\n'
        test_sig += format_var(f's = "{t.sig}"_hex', decl_vars) + '\n'
        test_sig += format_var(f"r = {('true' if valid_sig else 'false')}", decl_vars) + f' // result = {t.result}\n'
        test_sig += format_var(f'd = { format_hash_func_call(tv.hash_algo, "m") }', decl_vars) + '\n'
        decl_vars = False

        test_sig += f'REQUIRE_EQUAL( r, verify_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s ));\n'
        if valid_sig:
            test_sig += f'assert_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s, "Failed verifying RSA PSS MGF1 {tv.hash_algo.upper()} signature" );\n'
        else:
            test_sig += (f'REQUIRE_ASSERT( "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed", [&]() {{\n' \
            f'    assert_rsa_pss_{tv.hash_algo}( rsa_public_key_view(n, e, l), d, s,\n' \
            f'        "RSA PSS MGF1 {tv.hash_algo.upper()} signature verification failed"\n' \
            '    );\n' \
            '})\n')
        test_sig += '\n'
        test_str += indent(test_sig, 4)
    test_str = test_str.rstrip()
    test_str += '\n}'
    return test_str

def ecdsa_tv2str(tv: ECDSATestVector, decl_vars: bool) -> str:
    indent_size = 4
    test_str  = format_var(f'pubkey = curve.make_point( "{ tv.Qx }", "{ tv.Qy }" )', decl_vars) + '\n'
    test_str += '{\n'

    decl_vars = True
    for t in tv.tests:
        if len(t.comment) > 0:
            test_str += indent(f'// { t.comment }', indent_size) + '\n'
        test_str += format_var(f'm = "{ t.msg }"_hex', decl_vars, indent_size) + '\n'
        test_str += format_var(f'sig_r = "{t.r}"', decl_vars, indent_size, 'bn_t') + '\n'
        test_str += format_var(f'sig_s = "{t.s}"', decl_vars, indent_size, 'bn_t') + '\n'

        valid_sig = result_success(t.result)
        test_str += format_var(f"r = {('true' if valid_sig else 'false')}", decl_vars, indent_size) + f' // result = {t.result}\n'
        test_str += format_var(f'd = { format_hash_func_call(tv.hash_algo, "m") }', decl_vars, indent_size) + '\n'
        test_str += indent('test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );', indent_size) + '\n'
        decl_vars = False
        test_str += '\n'
    test_str = test_str.rstrip()
    test_str += '\n}'
    return test_str

def get_out_file_path(path):
    if is_url(path):
        path = Path(urllib.parse.urlparse(path).path).stem
    return os.path.splitext(path)[0] +'.hpp'


schema_parsers = {
    **dict(zip(rsa_schemas, [parse_rsa_verify] * len(rsa_schemas))),
    **dict(zip(ecdsa_schemas, [parse_ecdsa_verify] * len(ecdsa_schemas)))
}

def main():
    if len(sys.argv) < 2:
        print(f"Usage:\n    {os.path.basename(__file__)} <file_path|URL>")
        return 0

    in_path = sys.argv[1]
    if not is_url(in_path) and os.path.splitext(in_path)[1].lower() != '.json':
        print("Invalid file or URL!", file=sys.stderr)
        print(f"Usage:\n    {os.path.basename(__file__)} <path_to_json_file>")
        return 1

    wp_json = None
    if is_url(in_path):
        with urllib.request.urlopen(in_path) as url:
            wp_json = json.loads(url.read().decode())
    else:
        wp_json = json.loads(in_path)

    if 'schema' not in wp_json or wp_json['schema'] not in supported_schemas:
        print("Invalid wycheproof json or invalid RSA/ECDSA verify schema!", file=sys.stderr)
        return 1

    #tests = parse_rsa_verify(wp_json)
    tests = schema_parsers[wp_json['schema']](wp_json)
    if tests.type == TestType.Unknown:
        print("Couldn't determine type of test(s)!", file=sys.stderr)
        return 1

    # Generate test cases
    test_cases = {}
    def has_key(tv):
        if tests.type == TestType.SigVer_ECDSA:
            return tv.curve in test_cases
        else:
            return tv.hash_algo in test_cases

    def get_key(tv):
        if tests.type == TestType.SigVer_ECDSA:
            return tv.curve
        else:
            return tv.hash_algo

    for tv in tests.entries:
        decl_vars = False
        if not has_key(tv):
            decl_vars = True
            test_cases[get_key(tv)] = ''
        match tests.type:
            case TestType.SigVer_RSAv15:
                test_cases[get_key(tv)] += rsa_tv2str(tv, decl_vars)
            case TestType.SigVer_RSASSA_PSS:
                test_cases[get_key(tv)] += rsapss_tv2str(tv, decl_vars)
            case TestType.SigVer_ECDSA:
                test_cases[get_key(tv)] += ecdsa_tv2str(tv, decl_vars)
        test_cases[get_key(tv)] += '\n\n'

    # Write test cases to file
    out_file = get_out_file_path(in_path)
    with open(out_file, "w") as f:
        indent_size = 4
        if tests.type == TestType.SigVer_ECDSA:
            print("#include <ack/ec.hpp>", file=f)
            print("#include <ack/ecdsa.hpp>", file=f)
            print("#include <ack/keccak.hpp>", file=f)
            print("#include <ack/types.hpp>", file=f)
            print("#include <ack/utils.hpp>", file=f)
            print("#include <ack/tests/utils.hpp>\n", file=f)
            print("#include <eosio/crypto.hpp>", file=f)
            print("#include <eosio/tester.hpp>\n", file=f)
        elif tests.type == TestType.SigVer_RSAv15 or tests.type == TestType.SigVer_RSASSA_PSS:
            print("#include <ack/rsa.hpp>", file=f)
            print("#include <ack/types.hpp>", file=f)
            print("#include <ack/utils.hpp>", file=f)
            print("#include <ack/tests/utils.hpp>\n", file=f)
            print("#include <eosio/crypto.hpp>", file=f)
            print("#include <eosio/tester.hpp>\n", file=f)
            print("#include <optional>\n", file=f)

        test_type = 'rsa_pkcs_1_5' if tests.type == TestType.SigVer_RSAv15 else 'rsa_pss_mgf1' if tests.type == TestType.SigVer_RSASSA_PSS else 'ecdsa'
        for key, t in test_cases.items():
            tname = f'{ test_type }_{ key }_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(comment("Test vectors from Google's Wycheproof RSA signature verification tests.", indent_size), file=f)
            print(comment(f"Generated from: '{Path(in_path).name}'", indent_size), file=f)
            if is_url(in_path):
               print(comment(f"URL: '{in_path}'", indent_size), file=f)
            if tests.type == TestType.SigVer_ECDSA:
                print(comment("Note:", indent_size), file=f)
                if len(ecdsa_skip_tv_flags) > 0:
                    lst = ', '.join(f'\'{w}\'' for w in ecdsa_skip_tv_flags)
                    print(comment(f"    Test vectors with flag(s) { lst } were not included.", indent_size), file=f)
                print(comment("    All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.", indent_size), file=f)
            print(indent('//', indent_size), file=f)
            print(comment(tests.header, indent_size), file=f)
            print(indent('{', indent_size), file=f)
            if tests.type == TestType.SigVer_ECDSA:
                print(indent(f'using bn_t = ec_fixed_bigint<{ curve_sizes[key] }>;', indent_size*2), file=f)
                print(indent(f'const auto& curve = { key };', indent_size*2), file=f)
            print(indent(f'{t.rstrip()}', indent_size*2), file=f)
            print(indent(f"}} // End of Google's Wycheproof tests {Path(in_path).stem}", indent_size), file=f)
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

    print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())
