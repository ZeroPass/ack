import enum, json, urllib.parse, urllib.request, os, sys
from pathlib import Path
from typing import List, Optional

valid_schemas      = ('rsassa_pkcs1_verify_schema.json', 'rsassa_pss_verify_schema.json',)
supported_hashes   = ('SHA-1', 'SHA-256', 'SHA-512',)
supported_mgfs     = ('MGF1',)
unacceptable_flags = ('MissingNull', )

class TestType(enum.Enum):
    Unknown           = -1,
    SigVer_RSAv15     = 1,
    SigVer_RSASSA_PSS = 2

class RsaTest:
    def __init__(self):
        self.msg = ''
        self.sig = ''
        self.result = ''

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

def is_url(path: str) -> bool:
    return urllib.parse.urlparse(path).scheme in ('http', 'https',)

def normalized_hex_str(str):
    if len(str) % 2 != 0:
        return '0' + str
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

def parse_rsa_veriy_wp_tv(wptv_json: dict, type:TestType) -> Optional[RsaTestVector]:
    if wptv_json['sha'] not in supported_hashes:
        return None
    if type == TestType.SigVer_RSASSA_PSS and \
        (wptv_json['sha'] != wptv_json['mgfSha'] or wptv_json['mgf'] not in supported_mgfs):
        return None
    if len(wptv_json['tests']) == 0:
        return None

    tv = RsaTestVector()
    tv.hash_algo = wptv_json['sha'].replace('-', '').lower()
    tv.n = normalize_hex_integer(wptv_json['n'])
    tv.e = normalize_hex_integer(wptv_json['e'])
    if type == TestType.SigVer_RSASSA_PSS and 'sLen' in wptv_json:
        slen = wptv_json['sLen']
        tv.salt_len = slen
    for t in wptv_json['tests']:
        rt = RsaTest()
        rt.msg = normalized_hex_str(t['msg'])
        rt.sig = normalize_hex_integer(t['sig'], len(tv.n)/2)
        rt.result = t['result'] + (f" - flags: {t['flags']}" if len(t['flags']) else '')
        tv.tests.append(rt)
    return tv

def parse_rsa_verify_wp_testvectors(wp_json: dict) -> RsaTestVectors:
    tests   = RsaTestVectors()
    if 'schema' not in wp_json or wp_json['schema'] not in valid_schemas:
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
        tv = parse_rsa_veriy_wp_tv(tg, tests.type)
        if tv:
            tests.entries.append(tv)
    return tests

def format_var(var: str, decl: bool) -> str:
    return f'{"auto " if decl else ""}{var};'

def result_success(result: str) -> bool:
    def allowed_fags():
        for uaf in unacceptable_flags:
            if uaf in result:
                return False
        return True
    return result.startswith(('valid', 'acceptable')) and allowed_fags()

def indent(text:str, amount, ch=' '):
    padding = amount * ch
    return ''.join(padding + line for line in text.splitlines(True))

def comment(text:str, indent = 0, ch=' '):
    padding = indent * ch
    return ''.join(padding + '// ' + line for line in text.splitlines(True))

def tvrsa2str(tv: RsaTestVector, decl_vars: bool) -> str:
    test_str = format_var(f'n = "{tv.n }"_hex', decl_vars) + '\n'
    test_str += format_var(f'e = "{tv.e}"_hex', decl_vars) + '\n'
    test_str += '{\n'

    decl_vars = True
    for t in tv.tests:
        valid_sig = result_success(t.result)
        test_sig = format_var(f'm = "{t.msg}"_hex', decl_vars) + '\n'
        test_sig += format_var(f's = "{t.sig}"_hex', decl_vars) + '\n'
        test_sig += format_var(f"r = {('true' if valid_sig else 'false')}", decl_vars) + f' // result = {t.result}\n'
        test_sig += format_var(f'd = eosio::{tv.hash_algo}( (const char*)m.data(), m.size() )', decl_vars) + '\n'
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
    test_str += '\n}\n\n'
    return test_str

def tvrsapss2str(tv: RsaTestVector, decl_vars: bool) -> str:
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
        test_sig += format_var(f'd = eosio::{tv.hash_algo}( (const char*)m.data(), m.size() )', decl_vars) + '\n'
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
    test_str += '\n}\n\n'
    return test_str

def get_out_file_path(path):
    if is_url(path):
        path = Path(urllib.parse.urlparse(path).path).stem
    return os.path.splitext(path)[0] +'.hpp'

def main():
    if len(sys.argv) < 2:
        print(f"Usage:\n    {os.path.basename(__file__)} <file_path|URL>")
        return 0

    in_path = sys.argv[1]
    if not is_url(in_path) and os.path.splitext(in_path)[1].lower() != '.json':
        print("Invalid file or URL!", file=sys.stderr)
        print(f"Usage:\n    {os.path.basename(__file__)} <path_to_rsp_fle>")
        return 1

    wp_json = None
    if is_url(in_path):
        with urllib.request.urlopen(in_path) as url:
            wp_json = json.loads(url.read().decode())
    else:
        wp_json = json.loads(in_path)

    if 'schema' not in wp_json or wp_json['schema'] not in valid_schemas:
        print("Invalid wycheproof json or invalid RSA verify schema!", file=sys.stderr)

    tests = parse_rsa_verify_wp_testvectors(wp_json)
    if tests.type == TestType.Unknown:
        print("Couldn't determine test(s) type", file=sys.stderr)
        return 1

    with open(get_out_file_path(in_path), "w") as f:
        test_cases = {}
        for tv in tests.entries:
            decl_vars = False
            if tv.hash_algo not in test_cases:
                decl_vars = True
                test_cases[tv.hash_algo] = ''
            match tests.type:
                case TestType.SigVer_RSAv15:
                    test_cases[tv.hash_algo] += tvrsa2str(tv, decl_vars)
                case TestType.SigVer_RSASSA_PSS:
                    test_cases[tv.hash_algo] += tvrsapss2str(tv, decl_vars)

        print("#include <optional>", file=f)

        test_type = 'rsa_pkcs_1_5' if tests.type == TestType.SigVer_RSAv15 else 'rsa_pss_mgf1'
        for hash, t in test_cases.items():
            tname = f'{test_type}_{hash}_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(comment("Test vectors from Google's Wycheproof RSA signature verification tests.", 4), file=f)
            print(comment(f"Generated from: '{Path(in_path).name}'", 4), file=f)
            if is_url(in_path):
               print(comment(f"URL: '{in_path}'", 4), file=f)
            print(indent('//', 4), file=f)
            print(comment(tests.header, 4), file=f)
            print(indent('{', 4), file=f)
            print(indent(f'{t.rstrip()}', 8), file=f)
            print(indent("} // End of Google's Wycheproof tests", 4), file=f)
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

if __name__ == "__main__":
    exit(main())
