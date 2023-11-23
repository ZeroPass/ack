#!/bin/python
# Author: Crt Vavros
#
# Generates test cases for EC base point multiplication from input file.
#
#
# Input file is in text format with list of test vectors for specific curve in format:
#
#     Curve: <curve_name>
#     -------------
#     k   = <scalar_value>
#     R.x = <result_x_coordinate>
#     R.y = <result_y_coordinate>
#
#     k   = <scalar_value>
#     R.x = <result_x_coordinate>
#     R.y = <result_y_coordinate>
#
#     Curve: <curve_name>
#     -------------
#     k   = <scalar_value>
#     R.x = <result_x_coordinate>
#     R.y = <result_y_coordinate>
#
#     k   = <scalar_value>
#     R.x = <result_x_coordinate>
#     R.y = <result_y_coordinate>
#

import  os, re, sys

curve_pattern = re.compile(r"^Curve:", re.IGNORECASE)

supported_curves = ['secp256k1', 'secp256r1', 'P256', 'P-256']
curve_var = {
    'secp256k1' : 'secp256k1',
    'secp256r1' : 'secp256r1',
    'P256'      : 'secp256r1',
    'P-256'     : 'secp256r1',
}

curve_sizes = {
    'secp256r1' : 256,
    'secp256k1' : 256,
    'P256'      : 256,
    'P-256'     : 256,
}

comment_chr = '#'

def parse_key_value(line: str):
    s = line.split('=')
    if len(s) != 2:
        return None

    # parse hex or base 10 value
    v = 0
    try:
        v = int(s[1].strip(), 10)
    except ValueError:
        v = int(s[1].strip(), 16)

    return (s[0].strip(), v)

def parse_file(file_path: str) -> dict:
    tv = {}
    with open(file_path) as f:
        state = 0
        curve_name = None
        k  = 0
        rx = 0
        ry = 0
        tvs = []
        for line in f:
            line = line.strip()
            if len(line) == 0:
                continue
            if line[0] == comment_chr:
                continue

            if curve_pattern.match(line):
                if curve_name is not None:
                    if curve_name not in tv:
                        tv[curve_name] = []
                    tv[curve_name] = tvs
                    tvs = []
                curve_name = line.split(':')[1].strip()
                state = 1
            elif 0 < state < 4:
                s = parse_key_value(line)
                if s is None:
                    continue
                if state == 1:
                    k = s[1]
                elif state == 2:
                    rx = s[1]
                elif state == 3:
                    ry = s[1]

                state += 1
                if state > 3:
                    tvs.append((k, rx, ry))
                    state = 1
    if curve_name not in tv:
        tv[curve_name] = tvs
    return tv

def int_hex(i: int):
    return hex(i).lstrip('0x').upper()

def indent(text: str, amount: int, ch: str = ' '):
    padding = amount * ch
    return ''.join(padding + line for line in text.splitlines(True))

def format_var(var: str, decl: bool, indent_size: int = 0, var_type: str = 'auto') -> str:
    str = f'{f"{var_type} " if decl else ""}{var};'
    if indent_size > 0:
        str = indent(str, indent_size)
    return str

def tv2str(tv: tuple, decl_vars: bool) -> str:
    test_str = ''
    indent_size = 4
    test_str += format_var(f'k = bn_t( "{ int_hex( tv[0] ) }" )', decl_vars, indent_size) + '\n'
    test_str += format_var(f'r = curve.make_point( "{ int_hex( tv[1] ) }", "{ int_hex( tv[2] ) }", /*verify=*/ true )', decl_vars, indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( curve.generate_point( k ), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point( "{ int_hex( tv[0] ) }" ), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point( "{ int_hex( tv[0] ) }"sv ), r )', indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "{ int_hex( tv[0] ) }" ).to_affine(), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "{ int_hex( tv[0] ) }"sv ).to_affine(), r )', indent_size) + '\n'
    test_str += indent('REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "{ int_hex( tv[0] ) }" ).to_affine(), r )', indent_size) + '\n'
    test_str += indent(f'REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "{ int_hex( tv[0] ) }"sv ).to_affine(), r )', indent_size) + '\n'
    return test_str

def main():
    if len(sys.argv) < 2:
        print("Usage:\n    ec_base_mul_gen.py <path_to_rsp_file>")
        return 0
    elif os.path.splitext(sys.argv[1])[1].lower() != '.txt':
        print("Invalid file!", file=sys.stderr)
        print("Usage:\n    ec_base_mul_gen.py <path_to_rsp_file>")
        return 1

    tests = parse_file(sys.argv[1])
    if len(tests) == 0:
        print("No test vectors found!", file=sys.stderr)
        return 1

    test_cases = {}
    for key, tvs in tests.items():
        if key not in supported_curves:
            continue
        for tv in tvs:
            decl_vars = False
            if key not in test_cases:
                    test_cases[key] = ''
                    decl_vars = True
            test_cases[key] += tv2str(tv, decl_vars) + '\n'

    out_file = os.path.splitext(sys.argv[1])[0]+'.hpp'
    with open(out_file, "w") as f:
        print(f"/*\nGenerated from: '{sys.argv[1]}'\n", file=f)
        print("*/\n\n", file=f)

        indent_size = 4
        for curve_name, tcs in test_cases.items():
            tname = f'ec_mul_{ curve_var[curve_name] }_test'
            print(f'EOSIO_TEST_BEGIN({tname})', file=f)
            print(indent('using namespace std::string_view_literals;', indent_size), file=f)
            print(indent(f'using { curve_var[curve_name] }_t = std::remove_cv_t<decltype( ack::ec_curve::{ curve_var[curve_name] })>;', indent_size), file=f)
            print(indent(f'using bn_t = typename { curve_var[curve_name] }_t::int_type;', indent_size), file=f)
            print(indent(f'const auto& curve = ack::ec_curve::{ curve_var[curve_name] };', indent_size), file=f)
            print(indent(f'using point_proj_type = ack::ec_point_fp_proj<{ curve_var[curve_name] }_t>;', indent_size), file=f)
            print(indent(f'using point_jacobi_type = ack::ec_point_fp_jacobi<{ curve_var[curve_name] }_t>;', indent_size), file=f)
            print(indent( '{', indent_size), file=f )
            print(indent( f'{ tcs.rstrip() }', indent_size), file=f )
            print(indent( '}', indent_size), file=f )
            print(f'EOSIO_TEST_END // {tname}\n', file=f)

    print(f"Generated test(s) written to file: '{out_file}'" )
    return 0

if __name__ == "__main__":
    exit(main())