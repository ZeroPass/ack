// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/bigint.hpp>
#include <type_traits>

namespace ack::detail {
    #if defined(__EMSCRIPTEN__) || defined(__wasm__) || defined(__wasm32__) || defined(__wasm64__)
    inline static constexpr bool __wasm_env = true;
    #else
    inline static constexpr bool __wasm_env = false;
    #endif
}

/**
 * Macro defines invariant object for elliptic curve over prime field of type ec_curve_fp.
 * The invariant is constructed at compile time.
 * The name of the invariant elliptic curve is the same as the name of the curve.
 * Defined curve uses ec_fixed_bigint as underlying big number type.
 *
 * @param name    - Name of the variable. Same name is used to create curve tag struct.
 * @param bitsize - Size of the prime field in bits
*/
#define ACK_EC_CURVE_FP( name, bitsize, p, a, b, gx, gy, n, h) \
    namespace detail { struct name##_tag {}; } \
    static constexpr auto name = ack::ec_curve_fp<\
        std::conditional_t< ( ack::detail::__wasm_env && bitsize >= 512 ), ack::bignum<bitsize>, ack::ec_fixed_bigint<bitsize>> \
        , detail::name##_tag> ( \
        /*p =*/ p, \
        /*a =*/ a, \
        /*b =*/ b, \
        /*g =*/ { gx, gy }, \
        /*n =*/ n, \
        /*h =*/ h \
    );

namespace ack::ec_curve {
    /**
     * Invariant object representing the brainpoolP256r1 elliptic curve.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation.
     * https://datatracker.ietf.org/doc/html/rfc5639#section-3.4
    */
    ACK_EC_CURVE_FP(
        brainpoolP256r1,
        /*size =*/ 256,
        /*p =*/    "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        /*a =*/    "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        /*b =*/    "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        /*G.x =*/  "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        /*G.y =*/  "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
        /*n =*/    "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
        /*h =*/    1
    )

    /**
     * Invariant object representing the brainpoolP320r1 elliptic curve.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation.
     * https://datatracker.ietf.org/doc/html/rfc5639#section-3.4
    */
    ACK_EC_CURVE_FP(
        brainpoolP320r1,
        /*size =*/ 320,
        /*p =*/    "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
        /*a =*/    "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
        /*b =*/    "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
        /*G.x =*/  "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
        /*G.y =*/  "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
        /*n =*/    "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
        /*h =*/    1
    )

    /**
     * Invariant object representing the brainpoolP384r1 elliptic curve.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation.
     * https://datatracker.ietf.org/doc/html/rfc5639#section-3.4
    */
    ACK_EC_CURVE_FP(
        brainpoolP384r1,
        /*size =*/ 384,
        /*p =*/    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
        /*a =*/    "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
        /*b =*/    "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
        /*G.x =*/  "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
        /*G.y =*/  "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
        /*n =*/    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
        /*h =*/    1
    )

    /**
     * Invariant object representing the brainpoolP521r1 elliptic curve.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation.
     * https://datatracker.ietf.org/doc/html/rfc5639#section-3.4
    */
    ACK_EC_CURVE_FP(
        brainpoolP512r1,
        /*size =*/ 512,
        /*p =*/    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        /*a =*/    "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
        /*b =*/    "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
        /*G.x =*/  "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        /*G.y =*/  "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        /*n =*/    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
        /*h =*/    1
    )

    /**
     * Invariant object representing the secp256k1 elliptic curve.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from SECG SEC 2: Recommended Elliptic Curve Domain Parameters.
     * https://www.secg.org/sec2-v2.pdf
    */
    ACK_EC_CURVE_FP(
        secp256k1,
        /*size =*/ 256,
        /*p =*/    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        /*a =*/    "0000000000000000000000000000000000000000000000000000000000000000",
        /*b =*/    "0000000000000000000000000000000000000000000000000000000000000007",
        /*G.x =*/  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        /*G.y =*/  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        /*n =*/    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        /*h =*/    1
    )

    /**
     * Invariant object representing the secp256r1 elliptic curve, also known as NIST P-256.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from SECG SEC 2: Recommended Elliptic Curve Domain Parameters.
     * https://www.secg.org/sec2-v2.pdf
     *
     * And cross-checked with NIST FIPS SP 800-186: Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
    */
    ACK_EC_CURVE_FP(
        secp256r1,
        /*size =*/ 256,
        /*p =*/    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        /*a =*/    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        /*b =*/    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        /*G.x =*/  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        /*G.y =*/  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        /*n =*/    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        /*h =*/    1
    )

    /**
     * Invariant object representing the secp384r1 elliptic curve, also known as NIST P-384.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from SECG SEC 2: Recommended Elliptic Curve Domain Parameters.
     * https://www.secg.org/sec2-v2.pdf
     *
     * And cross-checked with NIST FIPS SP 800-186: Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
    */
    ACK_EC_CURVE_FP(
        secp384r1,
        /*size =*/ 384,
        /*p =*/    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        /*a =*/    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
        /*b =*/    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        /*G.x =*/  "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        /*G.y =*/  "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        /*n =*/    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        /*h =*/    1
    )

    /**
     * Invariant object representing the secp521r1 elliptic curve, also known as NIST P-521.
     * The invariant is constructed at compile time.
     * The name of the invariant is the same as the name of the curve.
     *
     * Domain parameters were taken from SECG SEC 2: Recommended Elliptic Curve Domain Parameters.
     * https://www.secg.org/sec2-v2.pdf
     *
     * And cross-checked with NIST FIPS SP 800-186: Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
    */
    ACK_EC_CURVE_FP(
        secp521r1,
        /*size =*/ 521,
        /*p =*/    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        /*a =*/    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
        /*b =*/    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        /*G.x =*/  "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        /*G.y =*/  "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        /*n =*/    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        /*h =*/    1
    )
}