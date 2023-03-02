// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/bigint.hpp>

/**
 * Macro defines invariant object for elliptic curve over prime field of type ec_curve_fp.
 * The invariant is defined at compile time.
 * The name of the invariant is the same as the name of the curve.
 * Defined invariant uses ec_fixed_bigint as underlying big number type.
 *
 * @param name - Name of the variable. Same name is used to create curve tag struct.
 * @param bitsize - Size of the prime field in bits
*/
#define ACK_EC_CURVE_FP( name, bitsize, p, a, b, gx, gy, n, h) \
        namespace detail { struct name##_tag {}; } \
        static constexpr auto name =  ec_curve_fp<ack::ec_fixed_bigint<bitsize>, detail::name##_tag> ( \
            /*p =*/ p, \
            /*a =*/ a, \
            /*b =*/ b, \
            /*g =*/ { gx, gy }, \
            /*n =*/ n, \
            /*h =*/ h \
    );

namespace ack::ec_curve {

    /**
     * Invariant object representing the secp256k1 elliptic curve.
     * The invariant is defined at compile time.
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
     * The invariant is defined at compile time.
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
}