// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/ec_curve.hpp>
#include <ack/ecdsa.hpp>
#include <ack/keccak.hpp>
#include <ack/sha.hpp>
#include <ack/utils.hpp>
#include <ack/tests/ecdsa_test_utils.hpp>
#include <ack/tests/utils.hpp>

#include <eosio/crypto.hpp>
#include <eosio/tester.hpp>

namespace ack::tests {
    EOSIO_TEST_BEGIN(ecdsa_brainpoolP320r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<320>;
        constexpr auto& curve = brainpoolP320r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( brainpoolP320r1.p  , "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27" )
        REQUIRE_EQUAL( brainpoolP320r1.a  , "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4" )
        REQUIRE_EQUAL( brainpoolP320r1.b  , "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6" )
        REQUIRE_EQUAL( brainpoolP320r1.g.x, "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611" )
        REQUIRE_EQUAL( brainpoolP320r1.g.y, "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1" )
        REQUIRE_EQUAL( brainpoolP320r1.n  , "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311" )
        REQUIRE_EQUAL( brainpoolP320r1.h  , 1 )

        REQUIRE_EQUAL( brainpoolP320r1.a_is_minus_3, false )
        REQUIRE_EQUAL( brainpoolP320r1.a_is_zero   , false )
        REQUIRE_EQUAL( brainpoolP320r1.p_minus_n   , "14064fb4c224a8b248a0d933f7642bd56aced9b16" )
        REQUIRE_EQUAL( brainpoolP320r1.verify()    , true )

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP320r1_sha384_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP320r1_sha384_p1363_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of IEEE P1363 encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SignatureSize - {'bugType': 'LEGACY', 'description': 'This test vector contains valid values for r and s. But the values are encoded using a smaller number of bytes. The size of an IEEE P1363 encoded signature should always be twice the number of bytes of the size of the order. Some libraries accept signatures with less bytes. To our knowledge no standard (i.e., IEEE P1363 or RFC 7515) requires any explicit checks of the signature size during signature verification.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   Untruncatedhash - {'bugType': 'MISSING_STEP', 'description': 'If the size of the digest is longer than the size of the underlying order of the multiplicative subgroup then the hash digest must be truncated during signature generation and verification. This test vector contains a signature where this step has been omitted.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "0fcc8860cb26e262ca8b4ecb9c52f78d82a10a1d30dd0c8ecd7584ce80dbb75c488a062b64375500", "1f27e676c26cd3488c1ef4ec3edd88cf8af78daf9036724b57e66da02cf7c676a53664becdfedc3b" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "85b1bc586bf5407f9c8ec3765fe02bd19380998c45892ccd5081a1bd8872a26cdaf403e6dbf34a6e";
                bn_t sig_s = "833d6661b0576d61a80ffe4d3271c43b2a56c14b3bd90305923ccdcf7b3d988c07ebb1c4cc67381c";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "0159100378a2b190377dcb3bd531e20c378d106931fc183f707dc9d08576f8fb566185594220b8dd7f";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "d3e3f8dc8f2844f860d907224861c091cb23503f42d49bcffa98b069ac0ecb8bf36c495f2ba1865b6e";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "4dac8ac7cac70f3844adb4e87221b494660f36197105e5d5dcc68d0a6613b67cab9d517468d248a3";
                sig_s = "5020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**320
                m = "313233343030"_hex;
                sig_r = "0185b1bc586bf5407f9c8ec3765fe02bd19380998c45892ccd5081a1bd8872a26cdaf403e6dbf34a6e";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "01000000000000000085b1bc586bf5407f9c8ec3765fe02bd19380998c45892ccd5081a1bd8872a26cdaf403e6dbf34a6e";
                sig_s = "0000000000000000005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "01237f27debd21320e1a68f2707191fc90c8c8de0031452240c8538fc061cf19470536f8f1bd23ee06";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "d3ae6800f542b49a3775a4d8e3a17082245f08b41109c8b2cae33a28e6f9a1a9e40ffafedb3df16bf5";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**320
                m = "313233343030"_hex;
                sig_r = "015020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                sig_s = "005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "0100000000000000005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                sig_s = "0000000000000000005020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3730373135"_hex;
                sig_r = "25166f47ac99c6bec3b038849ab4ead3b251f18afb0da1da5caa604a92a909c8561817684abffb92";
                sig_s = "3107ffd1aadce5b58a2a1b9517ccedda090433ac6344b027f36fc6b358ef4a8e436df3fd05521668";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373530353531383135"_hex;
                sig_r = "103c3ef2b43a8f57d01e2da67edfa003a0d342d7fbde0541332b0b24deea76afff4e2cd0572d73bb";
                sig_s = "0a0a680ebe3644c46b58d67ed8ee94f3aaee2839bc270d6b939bcb7657eeebbb6cccf2bc54af9781";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333633303731"_hex;
                sig_r = "8c70216094feda4e721a72d8a91c51dd17392cf4c4481d7cd94be56da994e5baaa561085cecfe80d";
                sig_s = "1b19f7e89525601820bc17bd595a7dbdef76e5b352fcb16c3a8a1c332ff6a5308ff47a7e54e0b1cb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333632343231333231"_hex;
                sig_r = "b4a4a035dbeaee126d09c7b15816b04bc717cb71bb5fe7649ac026269b7fe6d593fe1ff8fc5278a1";
                sig_s = "635516de531104e72176e89a845032b3096e3269e41431c1854fbc4337ba6fb5ea91defd33729d83";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353838303134363536"_hex;
                sig_r = "2a3103cdaad1dd28ecf897491051dd0a9c9da9483753c93490b4a05f1c42e1642925a3a0154d4062";
                sig_s = "672903243b6858a5e09148e403461f31c1ff0e126c365942e0680d314c1a7a7c57e2f0528c8cabbf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313436363035363432"_hex;
                sig_r = "b880b6be2a1295af3840a5f374fe77cde1ffdd6df3bb86097d5ce14852f73a1925fa6d192a27b74c";
                sig_s = "c2cb211303aea030a5b92be98fc36770822f8195ad73eee5a9bb87c5717ba4345cb60b099e4d4deb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333335333030383230"_hex;
                sig_r = "677f84a0653725b94e4eeddbe0b70aefdf594f5ef9e484b4060567a8365c43a783d81548d1f27408";
                sig_s = "4cb24e15375bdae0b44b336fc7e6c11856d4c6f9dd7e83148dc387c4a8869b11538b7ee94f053f4f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333936363033363331"_hex;
                sig_r = "9d5d984c7544ef737a1001d67f9dbbed521b46f74bc468c03881c2ab5944635af5465c3fa01cf51e";
                sig_s = "0c706dcfe11a4e30d623870fb0f2b979d0fd9daa970d86f64bb48f49aa484d924e9b93bcaf406924";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333931363630373935"_hex;
                sig_r = "448464becc13522c90708aa5204930e676fedfbaefe8fe02509a4fe822cc88fd6d92a958438ded7c";
                sig_s = "5de659e080a61c50b5b7489f4677ec4c6931faaf171f2a69756e2f2d1214235bdb1ea3d2a4a75359";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343436393735393634"_hex;
                sig_r = "59c0c95941e1a52390e00c2d7796c685dcc4d73d6d6967590aa1767c972e199de3c6dbfca77dcac8";
                sig_s = "507f27ab5ac05ad23cb25fc48ffc766dcb6dc0cd25606505a2d270066c3a74842768b54af2c84751";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313539343738363431"_hex;
                sig_r = "59902d7763e7f1875a4252d133eb6114cfc1972b683adfd767a71ca80c3f78057cea759ea195d31e";
                sig_s = "397deaf96e2903a207f68e5330c9f2c6276a45d0fdba961a04c275fa203678176201ed370999a32d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323431373932333331"_hex;
                sig_r = "d142217584e852a499efa734a10a436a397ba7e068ad70f3eefc4d6731e76a481b260eac1d2147f0";
                sig_s = "17c8482639df8d20fcb835bfe0f3ecd27317eb8315c69b656ebf137dde6582f3409d7c44a8b6e085";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313437323930323034"_hex;
                sig_r = "8a55fa49224592f7e403a4b3e647bf382a26499b37ec2cff51a2be2a1357807fe875359ec8654f87";
                sig_s = "b9506e74af8f552d4abb2c472b8508ce24814e20b27d192e24d36d5ac751922b0c807bf97a7b1ad7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373235363435"_hex;
                sig_r = "68ad2da643d66fc5d27b63d7222f835d09fe0b328fc4da4684b86d9c12b3992626f610e3395e4ed0";
                sig_s = "9662f74d52712a2af54f601c4488934fe2826d50e1ee868022437c9b620c93d43fc750f03312897c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37333433333036353633"_hex;
                sig_r = "578bdd50de9986fad341a954e51126ff0cb540026abb3d42b3c208e4ad187f7ba2d99b3efe495c92";
                sig_s = "b95afd2d12cdee68c3572a5fe126334ed0ed7ba82d3097eaa6d9d737c09b830b6cd3e878f470e7e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393734343630393738"_hex;
                sig_r = "9d612663497c484084d3d15d8e799e1fe38b7b5922955fc5a7fea4ecfc41954ca707525c1e0dc010";
                sig_s = "59e80cf69be6876b95357ded13ca61a494fac7355ac2e80a89be0219552d916852632617c0946bc2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323237303836383339"_hex;
                sig_r = "b4c00f589dbb51ea68270f4b02eff48a4b123c0167bbd24daf2a837903e734339b8a2542041f87aa";
                sig_s = "94c32634baea4452c054295d7aebe23be7e80abbf53789651674182263ee5c2902fbfb3df7da7425";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323332393736343130"_hex;
                sig_r = "b9201e49950ce0d1df644356405f0a785a8b8470f83e78a6f35e6234daa92a7685877a59d8c91a97";
                sig_s = "8bee9077443eedde34a2fc2c266f188e844eab2904c84204c816ba3cb1c4b9b253d4a78ce4e81114";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3934303437333831"_hex;
                sig_r = "0d42a1899f73ac70c9192558b478db8803c68337d415faebab76858c32a37e399f1727fd599a1817";
                sig_s = "363f1346c0227ec54da1659165ee7b07e06610d36b1ce6226f608bf6cef2144248de37562be8537a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323230353639313233"_hex;
                sig_r = "c5d65effab2ec3e4435c258121c493e24ae92005ac80136f21f2f42946fc3745841dbc2a3eb99695";
                sig_s = "85fec2a9080a1ece18896970c9a2e1b32240eaf187d65f6f9e91d27111c4033d471eda67eb8986ed";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343134303533393934"_hex;
                sig_r = "a240adea61f748998df2cde95be9d7df30f454bde5b907ec7de6dcdb121bea41bd42c4392476c4f9";
                sig_s = "3ef991d642bd0265b4a7b521b20a42fb2c687ca2f0694b239a113a83575b5727dcb632482a572649";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531353638363439"_hex;
                sig_r = "cad52bdb35af7ee0e8f687c81f2edd8efc2d6ee317f3c6a82121048ef7a3ff3b69187aaea53f4926";
                sig_s = "58f84e186616544af494900241d2b802df2eae3e3f1410865e4cd16e221f277e7b5093ff186e4d76";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393539303731363335"_hex;
                sig_r = "93013ff84151a04ea146a36d2a3b9f497ba5d9323019b730be322bc519e2701e3f0ec1b6c8015e8f";
                sig_s = "872669f33b9b4b93384d9ac3f7c3092560b9af7e6738221e3b289421813601fe569b2c49afec8bb4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323135333436393533"_hex;
                sig_r = "26228cdd2c08fbf8dd4ad5d2f80ed15129868e892d33cd892503207e91114c868d0064c60f1bb612";
                sig_s = "afdedc05f0b27e9363c34d9bd1bc64ec0142fcd9f40f3584605bbccf12b0e279e4b3e3d0927a4852";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037313039383330"_hex;
                sig_r = "731d597c3694a4932f0f14fc3132d2ba9f5b7d833ae91cbe9a450352f4240d5bb712f65b0eea0412";
                sig_s = "1b8a6fc9bc1ecf8c09b1ba27c4c8dcebaf1e669a89036b34fa8ff57280e5741959e6c05e05880a37";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343932393339363930"_hex;
                sig_r = "d2ab69ae6110bb67ed99ffbdad8036dfabc46de8ae1fc7e799986b91ba7d454672ebe4896cf72011";
                sig_s = "d29d67bf2b882770d46dbd06a6fbaad583c2ceedcbd772200b7532e354f86eaf9a9418191eafc5b8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313132333535393630"_hex;
                sig_r = "81da10c5fef4bfb58b4a73b4cf3fd4f0f028b448b3463dabe0d6f1e101af570fa64116731ea5b9c2";
                sig_s = "ceac01ebad706ef43c80caa1d8962c655bfd810396b94d2bbea299bd5cbcced75562b0fab446ff85";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323339323735373034"_hex;
                sig_r = "38358ba2c46f61f39bef22873a5bf26464f2b05e4874bbb62a2323385f8e87a5b118a0079078b44d";
                sig_s = "93f84f06290f48161922552577482a973404f47c84c6e1a94643c3832fb2912fc4b38529e2f13e9a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303831313838373638"_hex;
                sig_r = "afd1fba700fc703fb772f701597adddcce4ff9f530c830dc8c8cbd4b3070f4a22b80516b0b820970";
                sig_s = "76c2e890860c36bbb5f6a1053401f1b51aa83cdfd96a3c15e1a183fdf8357e49d2984e4fcf19c25d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343534363038393633"_hex;
                sig_r = "8c90d4c8bf021906d3d577bd16b3e139bbc35d7692a828f0ef5cdf9d51a8442265f815849fe793b8";
                sig_s = "0bfe16492abb58a1d8064767546d29aaf6138c5842c7f7002fbac34b78b324b84426510c1b7b0d89";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837363837313131"_hex;
                sig_r = "6d07da92bd405912b22a993ed30e06149c78743fa195fcd3baf05803fddd5a6408201e68faee622a";
                sig_s = "5ad3c8b4c1c68080279f20ba15548343fca9ec52fe23bdf59619738dd1bd418414ac53ad7ce16c2b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303331333831383735"_hex;
                sig_r = "be43df617f79ef83404e7c7393ed3c38c815d06e3c0debf9ba37f36c419a6c3ea690822f88011ff1";
                sig_s = "2f0ad4ee5fe7ad128f58a520a4fbad3f0a502a4a4412639b3dbc206edfb2a03d564010d78d2228b9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323535333538333333"_hex;
                sig_r = "844ca29340112d0eb9dd15f62655a0cfa993415e570511a3f7273623b82d892d136c6e8bc57db84e";
                sig_s = "71114ae579d053b5cb3d77d2e9faf1c06cc263ab8fd845a0378f4a75da86ddc23ab4d07946832a77";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34363138383431343732"_hex;
                sig_r = "cda8531222502a62368fddc724798870038333b9fa77141d4bc5ef758f7e973e5ab8b4cfae90eaa1";
                sig_s = "9ead50a2533287abe5504efd8db57f8b96a7fe039cc95d1690ea0c1e2c9df5fc29cddd7b01edb99b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303039323435383534"_hex;
                sig_r = "5c2c6a661338df365af8ba1080b994e59989f002fa4fff42fc8994ca6395620152f3971300aff6f9";
                sig_s = "8681ea1793bd3e069426127a6b665725ddba4a8f1945851743477a1cbdc7356713ae70fc138531a3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373536343636353238"_hex;
                sig_r = "0e061b48b5f7836e0caf73c9770c3fee1f67ec18ded9e1d339ab56d05b9adde369504fedff1d6681";
                sig_s = "009dbc4ad8edc1896fa041ca60ac64b7fa148e3f02b0f697ae22d923f526fd4936e5f584b23ddbc3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313139363937313032"_hex;
                sig_r = "a8462605c79437c068523d93d2e1529ccae1b5248e8f9a90f2ef08d9d5e5025b3639f82b70f1e7ed";
                sig_s = "67aa5fe4e79e7c54a8ce389b90e1ce1556aa689b44814a6cb5c2f0fe4569c5cfcee34cbb4a086219";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323333313432313732"_hex;
                sig_r = "93b01029421ca30d8abbd06f134ee9dcbe81790d012722ae65214f0aaa34bba642f43949d5ec51a5";
                sig_s = "110e4fce36e0c2acd898122fba756e711ad082087c36b125084f67b22e37a02bd68628cdb164ece0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363733343831383938"_hex;
                sig_r = "6b6d893c3055da5d5a2ff6ce038a1bec59b04950bfd8012648d6063186ff861d7aa91a5185aa3c0c";
                sig_s = "a602ed34ee41e4811251a51bd67010f8eb3355b8691dad66035e723d971346f57c8a0f479fef666c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343630313539383237"_hex;
                sig_r = "6fc42cf23aa42c36675ff126412c757dde74ef73cadb0425e23cb76230a58b3d002370b4166bfd29";
                sig_s = "4e61b9b10a13fe0dd2758733f6b178af98e0079867837d55f8e5e90b577de90ce0d8dc345ed16b38";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393930383539393239"_hex;
                sig_r = "b529a563a2f4065d333c812b0b6134de9735bb269fea763f01cf7d1c6a0ec70d7223c7e6c1b040e8";
                sig_s = "347fcb8f3971b3d968ba709b1bd4d31b550cceed232268ca0df1e00502a56aa42dde7330bd919d5f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333236343430393831"_hex;
                sig_r = "b91b2a73449560522112fa4fd1b57b8c24754791af247a8c9de423e0bd536289a4fe850f7e3c43ae";
                sig_s = "2eb3f874f2e5ec56356bf6baf10b64b7c54b13447ccca1ffc66a1fc89dc8e977801748f8f0ce5a4b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333736343337353537"_hex;
                sig_r = "314338683f23b1110d1840732f672254f38079bf11eeafff1ec2e53a5373f74c98887b11ebb78c86";
                sig_s = "b7e3a6b459dd10cfb5df6d2ea7afb15efeb1e5e917e5aa44fa54743689d7daf163f998e05719127a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383630333937373230"_hex;
                sig_r = "22d1881a94e1e11cf10620f37d708ebed847f1459129a0d42cb457da8051f81a0f9da846281a68f7";
                sig_s = "404652ebd261f5f6b185de4a16980dc3662fc4573e245577e7ef6e3cbfdd47bc1e487ba206ccf760";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383037373733393837"_hex;
                sig_r = "863970caec6c6ff0a1c70f60859576e3583e6b529de3f928136e848c56b6c6715045fdfe52637747";
                sig_s = "667f525a88be891ec6b9f96d1a68c4f06b3b3d2ad1c15f063d110ec9fb60ae7463dd568a69ce452c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353731383636383537"_hex;
                sig_r = "69cf0600384ceb832e237b6b453dea81a3c19cb8fae48ba186d28e3b118464b27af9100f181b738a";
                sig_s = "2780269a8fa40790ed726372ee0956265e72896d9e84f713f883a3bc0548e8d3a2b357333dda4c0c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38363737333039333632"_hex;
                sig_r = "30f38139883f71c0c64d63adcb731f1c385df87db7ce7326bf50410acc50f0babf5017f92a1e1a6e";
                sig_s = "597734222482724643f60e48b3b589deaa37b86e1de1cf0b129b286ec67686574f16cfb5f2cc6f45";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343735353135303630"_hex;
                sig_r = "174ae98cc25dbed747cedf8697266d16e96bb4f8071c905990f4e72c728c94aaa32dce24a52166fb";
                sig_s = "578099835a3dcb3da2fd42750180079da407c7a142cbccb699fed7af89dd703ba0cad94cdf2c051c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393733313736383734"_hex;
                sig_r = "58cfb1511a223c06b3e974b660bed827bee38c59c4523068e9c9faa330c970e6271ea387db6b40b0";
                sig_s = "763594ced6e8413bfd90d5ceca18d6774a3da87473cc4dee726b0325e2df8b257d9e01318ae7e022";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363938303935313438"_hex;
                sig_r = "8ddba4f7aa8cc5e00a3ffd2a082710d42d3a88f9f947ba51f09466c2a9295caa131b8ae9ef51b35c";
                sig_s = "bc3410033a5798d9e4c6a817da1759c00c0d38e3c1ff22f0a41e5ad0d1e914e71c907da8c245ca2c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373530323638353736"_hex;
                sig_r = "2f7e50ee96706d597d8bf0103fa46786746a2c65c021fac7fa378d244c418a42b7908f0fab2dffca";
                sig_s = "b7b94f2a883ba1b49858329cc78fc2a992109809b470b878cc38e1bdd4df3ee00a0ae7e228e466bc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639313439353538"_hex;
                sig_r = "4591491eee04e10a40a1e8eb82148195123348ec1a7cba06044e8f226ed30910b693ebbbaee0685f";
                sig_s = "1b8b3733cc5ca15dad84809df8499788b4899cba307f93b49ea6a63b9e77487c3c98b803fce69cb9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313734363535343335"_hex;
                sig_r = "9d22b864e2706fa43a67ea62f39e4d3f402767d9d038c78e2844d699f41eaf1a641cfdd9d6a63fb5";
                sig_s = "1eaacdad8294ecc2ca0c55e6e73df03d832beafe048fc690895beca5cead9d01d37b3fed5741cb94";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363434353530373932"_hex;
                sig_r = "8f1502143eff372fb9bdd956ece35d232403fed7f77eb4f4552d4fc84e4a2e5d6c8ccf06f5a6ad61";
                sig_s = "4621c9fbc37466f7c757f66d171da8ee0a0dd5f24113e2f517a082b7ab5d4123c3eec9eeadf69952";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353332383138333338"_hex;
                sig_r = "8dcdcc74a25fcd92e4372e11364a361c7a2d7f3dd74c5d6bc3761c07fe78f084765de8ce70e448fa";
                sig_s = "b3cfdb35c20b1e30d3c216dcef3c73cd44ef1973c8695c8ab439f7e26628574e0f349d81c598d1e6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313932303736333832"_hex;
                sig_r = "bc2a5b098f724830a190480fff5fafa0f2fe85bf17176af8d4eb670e1d55533f820d690e76b3bccd";
                sig_s = "516c576444be0250e33823302adb708b6622f17e2438f01800c58edcf907e505b419f6c0dff11afc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353332383432323230"_hex;
                sig_r = "b3208e3c49a8ce5fb89effb2480e8ca6b9e11b16a049aecf0ce35450e1e53509909b02ab33e663e2";
                sig_s = "362affc091fa46d71ae84e27979ab575c60f115845fc521e0a81591ab233bd32e6ab0e8b08809801";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313536373137373339"_hex;
                sig_r = "91cd133d74c701c936758054753591d31f1d854213b4067e033880116d4653cf257015445c5563ea";
                sig_s = "43185b31dbee46dbb62d1cdaadf479aa4f4b0b32dbc49ef5ccad43c9f0fcd94f06bdf6315e67c785";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333033303931313230"_hex;
                sig_r = "c63ac9ada6e0a00dbdc171f4ced1c16294881cd7b8cc91e67d0f97f5a61909ac6a694ab0b0d37a6c";
                sig_s = "b33d6876f4464e7ad8e27a195f63b49fad3be8f4684f4c3d42f58913944abc60173e5113581d94b7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373335393135353831"_hex;
                sig_r = "489db46f6ab87624a332376735aaf8e6c4c43affdb9b93c78682d3f90c1e01caadbcac4c975a2213";
                sig_s = "8e10c64116c4042b71bd9872c0506a7b34b6fffa9c3e24f843ce18270e3f163659ddc4a2460a4382";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323433393636373430"_hex;
                sig_r = "09f7e103550337e36ea09f9ab3b83580ddc6259fb9daf38b424175d64134d14cae3112bddd7b21af";
                sig_s = "253719f8ce1161959841b06ae31dc9d84cf0df90dffc101f0442c8e98c040e4d53f8ecd709b62049";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333237363032383233"_hex;
                sig_r = "41310739de7f1e06169f375d73e06550a50850be6aef432ef2143d7addfaf218f68836375921006e";
                sig_s = "43c4594e625f7aaa757eea847451d0155bd6b820883306b921184ec8141ca2b8c23b1dd64b980f97";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32393332303032353932"_hex;
                sig_r = "cf0672d18f93bd9c8c1c5e17d90a918c5cc8fdb967f9d2ad727dd72ec992116741b175d35393885d";
                sig_s = "029e747ea2c1d66f1b4c5be492bd3b0ce01e8420a626a8a8e125c3b58c614cab12e6edbfc13f8a4f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343039383737323834"_hex;
                sig_r = "2a247a37c489974ed8946e5e8bd5a9d298d7afcc416b5efc3a9c69ba61d6538ad5294775d1c2a479";
                sig_s = "48f5716ab8b409f284351051dcd222cc5ec4f1b8c71708b1e85ed4db1ecec73888bd8f78c1e74d05";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303735363930343132"_hex;
                sig_r = "7a2d71ce074eaaa4dff6d104fb6e7b070cb09c235deb697f5334918e181ce9bbe547b79ab37969f1";
                sig_s = "6dc14d2bfa01e0cb36878d1aef216df992b5c3f058fab8ce922249b59cb72556364138389561af5a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333231363233313335"_hex;
                sig_r = "851f1d1483719cd183940cf4e9eb30eadde699d8ba8090e216123ff61e41d166505a591a75dac6ce";
                sig_s = "292a45f31ef34bf34c3ccfd4a22adc4cc19c416151f70e95ad19999f9c59685e5fd9079a27b86fce";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343130313532313731"_hex;
                sig_r = "061df326b43ad7aa7bc4af8f3a5830bb0e63297cf690ec60a7259a942dce631e6676742ad12830cf";
                sig_s = "0e88675228b7fa4743ab53d24865193742cd6c5db218dde0044b301654bbab639abc775aae69064d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383337323835373438"_hex;
                sig_r = "560e6e5414414dbbd6e9d40522c9f3fce665c4455eae07eafa3724d708689315f6c7515cfe1aedbf";
                sig_s = "a3e619bf5f9d776a591ff74a9252e43bd04ae1f1c34fe5b84f04c3d9c972a80e187888bade5aa9d4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333234373034353235"_hex;
                sig_r = "34f9def6f21f5328d1c5e349857f3a7008f0afa5bbcb896ff6247b21a4abac7aedada64fa23f956e";
                sig_s = "cb44dbc53b0b0b43d6b158d90247209c2c74152c4e19a1c703577cf407ada14b198bde1ba79a344b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343033393636383732"_hex;
                sig_r = "9721d7991f2968c23856a075e86b70a39f4aa30fd68777dbbf46c1d37cc3be4497cb4714b2f1656a";
                sig_s = "0aa34e858175fef3c0734c5c7c4ccd0459927b0f722e86af6c4045752b4ba154e725946319dc4274";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323237363035313238"_hex;
                sig_r = "aec92108751afc4a0c62a9da2163bb52bdabb9e7a8b566ca8d30fac389c68a3817d21a33df2f68da";
                sig_s = "befbacfb03957c9378903cf9b432093f78954e5224303611e9e96c92a76704e3a6432a24413bd277";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393531343838333632"_hex;
                sig_r = "6e852689b90451a1592fad585ea57c71eb5b446196c07dcf450972ad13fdcd8117319eec75d0781f";
                sig_s = "3608d11f0b8eb773b35878cc43ea95fb4d354ab0ffec9f785a41a17ebcf8f7d957f793479ae89999";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343532313237303139"_hex;
                sig_r = "a34ebb41336c252a056097983d56dedd1eda042c7378b8b56d905aa9be1d7f6afb605466c0026c44";
                sig_s = "414c12e2a97f8e427ee9bd95e15bd5c10c16c1eea6011f01f271fe75869a6000fbfbc25a6d1f8541";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373331353530373036"_hex;
                sig_r = "1cf27fa96f137e0fbce4da476bdb5c3b875b7fb455fcfe7efd863cb8ed61090f6cf6a2b927fabbdb";
                sig_s = "945bc7e4f319004b2ef4ce2fa2ef270c4abc360e21d8f8b21074080ee8a3422137c96f82e26cfa3c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363637303639383738"_hex;
                sig_r = "cdb4f0b7f7de92ec59a2e0a1900318bdd649155bcd3e0914136a7c46c5e4bfd84231c04d64cc5c53";
                sig_s = "7b0ee0d7b7773c3bcd5921239f36b093bd232859d685920eaff53a91ff7188344a3075fe7f342c7c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343431353437363137"_hex;
                sig_r = "aa8ef33f59508ea9617a41084a3532e1179d0f5755e08277a568192272cec63f910377a871021c7e";
                sig_s = "708751c6284f7c3cfc57a598c1199c1cfcb3d26e4546484de55228c292bca978ea7698d3f7d806c6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343233393434393938"_hex;
                sig_r = "7d57fe006a0563d5570acbcabdf94ed515029f52e02298c79c9891181bd8b4974dde5765433d89cb";
                sig_s = "3be83d7dc7a5dc1a151f2b0957f678b9efca3d0818ec359202d9a4cfe792e95924be9e36e20ef970";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037363230373132"_hex;
                sig_r = "998c251f0c1f9623980c1cff0e369c7b0a383fc74079113121f982bfe7b87f17b48e5cdd29b0e1c0";
                sig_s = "d0d33d8be8c37fb49c4f49ceee321186ff30b9950a706c6fddd1054772af3c3266fb286677592d69";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313634363636323839"_hex;
                sig_r = "2e2384e2621b0f248ad34922f721f434527d354a7ef876defb8e80f6864867ae60c76ce24896a40f";
                sig_s = "08ecea054800ec201f0d1ac893f3bd79ae48533529345e1d3310fdc747d765970fa55ee0a47bdcd1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393432383533383635"_hex;
                sig_r = "d290cf0f9fbd691743b9dcdc00c0816fb99b5ad3b89a23f1313e0bf00cb3e12c95648dce175e3447";
                sig_s = "587707db7e9ddf613ff7d979ba9ca411b4bb7826862a380ce7cebecd52f52ff885f8ad536fbf1123";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323139333833353231"_hex;
                sig_r = "34b252604ebd8675104266be4df84b51942687a212957dedd4ab6dff4355a0027b7122aeb1e9f449";
                sig_s = "15082c5764df742c40193a8bf1e38d43a5fa4c77416cd8753057521c765062c676f99be659fcd00e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393236393333343139"_hex;
                sig_r = "b45baf5ee188cef5413ef3e6f0d917a90cf263d2be0a7039a6064e6e4053b6c960f44de15932855a";
                sig_s = "47602defee00b2fdea095346deae00b46069c95c09e43594889b8d3aa3d75350377aa3431ef63c76";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373639333836333634"_hex;
                sig_r = "6d8267065d60dcd375ce041813d6085fa90246cddbbaba12643c736cc9b7e6d619178f12c6fd2d3a";
                sig_s = "9b72611a5b4f8763e30c11aa791eff6b74c34d05e65451736e2a2b728f2e5ef485dc4e2e5c3daa37";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373335393330353733"_hex;
                sig_r = "a1a302aa27a32cd25c336c9ed7adaf5caf33dc3485a813718fce395ec0c93eef4cb34a6518a61cc8";
                sig_s = "258acd1b450082fddc05433e2dd66b0321114395a33bd9827d4c44d486c82c2d229869f3762012fe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333030353634303635"_hex;
                sig_r = "63fad28570b4203502a1d105903244dfe2b09530a93d8ea429a197c7121337a99d4c73516ec66135";
                sig_s = "7b4a08b7cdeaf6eedeec6306a0c410b092718c25590190030c5255bf837393d8293890c84909f436";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333037363535373338"_hex;
                sig_r = "c1e6232f06a44de1d7213b20eaa1b89c31dd2f5bb033245e8171524cc9110876d778a04834ac88ee";
                sig_s = "cb4aa20d158c3b8d115ec62bb51545bd58b63f1f0176ada04869dfee84019737cb8072f7a8b940f6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39363537303138313735"_hex;
                sig_r = "47b6baa1a053eab8b38ed6c9862f2ffed3811449e49ff2e18a588512129d1dea0a6c4fb811dc5eb0";
                sig_s = "a6cceef5a1e12f9b049f72f53732d42903a733ca6f3fae9596e17d9c757ed4ef04fcc37302ad1f45";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature generated without truncating the hash
                m = "313233343030"_hex;
                sig_r = "67bea53478364ad2cc40eab42535a4bf8e41583c941cb04ef37f11f035654c331d3bb0ddfd74031d";
                sig_s = "76a9eba43713ed8892a627ed3bcbf7d87f7991d128580a057c1b6388b604954d340e92f41827674b";
                r = false; // result = invalid - flags: ['Untruncatedhash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b21ecd48cc46fb306ed54e88adb615208457bd257e7e9d81db5bd1f56100a7aebb1386465507bbf3", "0086224cb383815e1babe561dcb6f49af0073e1bfda366066ef62440fc81dec7eca021cb0c05091dfb" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000014064fb4c224a8b248a0d933f7642bd56aced9b12";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e23";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009c9701de2ffdb296e6d56a5f3c189ecbb0e4448e38ed65da46eeaa51a7b34e650a91da95faf17900", "1e0a98a598523a34c4918d4180f87d641e4626ce11fa3a244abfb2450736693d38652309240ebda9" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930f";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b6f0ddc834ef8a67903681ea02b788fcff82d12307c8c3f4a44b30d7c5f614dafcc9a839991f8ee4", "27538e30ae5102b2043957dd6124fba3a1b601c04bddaf6c929ffdf2f7796fd7098c387dbc0b26fb" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "8c0736554dbc446063e8e15f297fd4b66fa8879945bbb5c22714a9645f4fa4ef9d710eafa6b226d8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6df44321d4a5f6af63e01b79bb608ea04ac6f35f795044a04ff400f547fd34d9b78c12c45978f96f", "00b52901cece48aab432c3dbdcbc0e270b2cc9b9915cc1ffb69a365d84c39186c48177387aa9ee0a48" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "5407cdd593acb501fc2848351f9d2e6b5457d3de43c3130e3b74e6a9242b3cce1c24f094f118bcd6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4e496f056ab5d07f96562c683643440e31fea26d35e6c5b69eefaa4107d345c807bf279f2ea26b60", "288539766fc726cb9e841db5dcfbbb792cade3c1ef64b69dcbda7f5e497b455a911ce2f0ebcacaad" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "11e094f470948e4eaa6aa13fab4e063386e91a638fa226d988d0693dea719ca95f61e493e9835af4", "3f533e89aa2085a9f8121086a2597f1060f73c8d75d66940e50eead73dfd03c476ea1947cdd4dd3f" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "16517a7d7beab6472ea8f6bc20412a3cd96d242c246ce9f983b2ef08b284cfad1ac28563b56edafb", "009f56fe2df78c239aa16c3c318bc9191a16ec407a700354173f8b862d9a0aa10d67397f26e7c9c0be" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008c9ec3ec54f615dbdbd0b22d6ff579c778fba6bc95c8a14d9ba958eb5a479dda750f08db36f3e54d", "00b32c812940cfdf0d8ab89498d8d0cd07536e4e02c6d67e7747fbaed80bcc86993e7e53af1da215af" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "11defb02f29a9094d4f7acadba48b4280ee529586c961cda8bf8af50a0240075c1c70b36d614e7c0", "00b492beb9bc7381321ac6c13766ff7af9d7b2f85f92e5c804488247fd5183707f5b6be591402b0e82" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "231b9a53f5ea2b91259e96a9d7b34f10663721177f9adecc6a8d5bd8f55e9544be1648490d073295", "198b90ae723a749a7dee59bda317d3029c4d65dda8ad66a04f53ea889f8fdb53e2b70fd1e67925c3" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59313";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000003";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008f12bc4f493dea2d62eb988b47706169d2aaac64b32af001e09646a431419d5905ec6da9ed8bf552", "09a2af9ce875fb535b41fdbe5b7acb6679556b79575865a35d85e1adbea86a5ce2b232f3a00f2726" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44d86998";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cd1697c6e107f3d90b8df462eb368b75eba585635950177e0a64b1ad4be527c90957fbdf203d67c8", "4b003f20e81659099b7e466618f2610c6f1df315b2011db07b90f3662b51561fffdf3ebb5d443440" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "21494db879806d4f59e53d4963977a03f6ec51140c9f9a1dba8857ff3bbc76d2214947e60edc982b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b1e3619d9e35873e959bb7de7740e927e3cb7fcf4413bfdbbed72ecc9a86a50d7029cae08ec285ab", "486b5d2f7c9b9314420bc864cfe29b4064bf7b922bbb5bbcd16f3a81ea7d0a61b0a09a62959b7690" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cc";
                bn_t sig_s = "43becc876a63564b458280199e382cbad8ef68d406665bbf307ffea45845a9ac69345a84a5a72b87";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0097cfebab588a54242a4d962ef803376c3f43079aa50a8871d6e776f7a0b33aea46ab9a2da63a33d8", "00c81af34af2e9a0c571effb501c4a27fd2aedc13623447af2bc8b6d5e7208c23e87e2d797cc3cf57e" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4efc";
                bn_t sig_s = "3992353d916617b49303856488e39fbc26173b8bc426f8207de3d8f1b97f3d12c803b99d57768fa7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "296e0067947efc07a06ae218fb00164d1ebebcd3787f793481407e2796248e8b65eac57db0c14606", "729e8094b9a54eeac23d98d51d662eff2df33a8693008fd02a0429ef6851ecbdcd93aac67c2fbdb6" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "84380881b243236967227191398a3a4909000425576c79465bdaaa0a03267b9e48f68fa0a68b29e3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3783b01455d92080f520d171f92abeaf48c7238e168b2931f2b322f9c0faa69a24097836cb0a685", "1cbf1a22bac2437551244605682dabcdd4cf39ff9d08443921c99448cbcea5deb85ad952dbb2b967" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "84380881b243236967227191398a3a4909000425576c79465bdaaa0a03267b9e48f68fa0a68b29e3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70d5fd41c416d5b7cdbcb944205bd69ff00ed6354aa502757e089cb19af6f777beb0f6921c0fafac", "22ae7cc65e0e7b617423750b8493a58512e379c00de626c17f7c82bfc907f26610a3f1e4d132c575" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59294";
                bn_t sig_s = "8ce984c0247d8a7a9628503f36abeaeea65fdfc3cf0a0c6cc8dac9da9f043b4659b638e7832e620b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a878e3ad1f76c570331a3418765dfdb7316743a14778b859900bc5b2a6adb16217b1933e6878e121", "7bb7d9c606ac5e72f3c7d83d33eeb69ee3f8cfe8b4074ff530c97608c8aa2e3954798412ed47558c" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000009c44febf31c35950";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00caa94725e1292a67fd7f1afb248b60c17a5be2f4c6456ca6b34cd21086cd50db61a39f097947309b", "008b0ddcb72f2652f11b2700c030b687ba2cb42e0d8e05aab0e6cdf45ceb6b6c776df7493f7315a66b" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70a6580abdcc1db9f73635788ca9748fde403b5a85aaffca80ad06e543b8ff38fc9a2009a42bb25e", "0422cce30e0dd5f0fed0b9811d564411c53ff03e078e2cec7a68b109aa1d1e674b48c87a0bfe8505" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "00000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0d97429d93169b43aae72e5f7cfbc4b9f497ac4b1698551e6d5d3cf334fa9cd4a5007e0475ba5401", "79c2b1cc2d8271746eca7c19c6fde7855bfd521fe8c761c4cf47c4bf2e4de49f94476776e959af9e" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf";
                bn_t sig_s = "0000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "06828ce63f3b0d694ce2999d06947fa9e2d1c18ab8032652fa7a98c678cf6bb2c52e7369085e4ef7", "00c56df69128962fbefc2aef1b3f6c467b72fc305acf51b339643ca2ed6bde56317c4cf59895923ded" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a528dceb92a745c1bf3173bc8d1b51d9420b96a474428dbb043cba2b370458a9bb358414d9733e80", "622579790a9a9e38c6774462e77268f77285919be63f80729e8c3007b4e4b9349e917574ae5f8bdd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "336758275671b26064a2ee5ed995236c650c22045c98e6c1a63b03d2d353cd8d474006977dd0ff40";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4d6e7590224fd2a7726a9c9692485626d7436113c6b1f63b18c8219dce135f212530e2d6e2b5dc60", "00826c8eee3756db6ce23de1919c0302f090493cb5629bb1b2f6ee6a309023cd00d95811d2896773d4" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "52ca79c89313d4f18ad1515df6b2f32c0e95774739ad64391155257026ac1a48d008404e8068b4f9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "77fdf8489f8677e627e95117995d2e0eb139e52535116f9ab24af470267d828240ab7e303231d691", "00b94572cd603477f753dd52e74a6b3984fa2e9036124fbbf8a5322651400ae53247b1f67c1a614206" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "59bcfbcf6f28b79195bf98394b7ec6b4698ba4fdc6cb72389fabdb07fe29de4ebcc4906bcbbce67b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "755a598c9432ed6ef132dd5a96c710b86d01f53fe2fe58211fcc7c64c768d8afe00e6fa6978f83d9", "449c032f09fbb15d913937cd7db700ea56ba9516f383433b34b2bea7881e51b6009d1f0419a6e528" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "3e58def7758c644788a67c4ef9ee602236fa4d7466066fb6c1d83ad3e90d355489a6eb93baa0bc61";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d0dd2e3a42aa76e6513f8beee89d1d861bab426bd29069d6054610697069a0b3bc17c9c40672d69", "0358e44f935a6f9aaf1e3e948e8f63df5ffee132766f8e2ad2db31fa315994a1e0810df08f4e0130" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "68ae43de1cec917435cd3b4575c37b3b73b2aa300d9dfab2458b523ebea2d21667a9facc1559a723";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "45ae365e942fed73480077187683987a5263561c4da80d2330638c7f283be2d697f0e533e717cabe", "00b54be0c00cac148e52059af9e5380478c01631a4d68f0dbd0fd5a638bc9c26d06b7a231de2849a98" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "441ac1ef4c8c84c4c7d07c9b08b16822b5bfa5b5bc61f2874c15f9021944a0f6e34ed17f67c27cad";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1d052006191eb87fdddcdfdda6cfb1762073fc96b4c376d6a58e88a61f14dc62f53fa5a9e840488a", "7298debbce38b9afa2b9db3730468a9ac8858daca5968cae52c90a779cc41e426800993c3ed01e1f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "3f8d645a4bb4a71f78e85d0613cea2efcc80562b215117f8336c4a52b194275ed10fa194e68da54b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c0273f20d057b4e9df5689ee292209fb87878870060626d01cd6f131f07b9be9ce47d253912e9d53", "0091e0921bcdaabf599f82c7be7a36541194e75bcbdf824134d7bde917f6cac4022ae25c6e97be9c70" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "61e07b834a8be8ebf55cef4a7a9c14845eaea0ffe66fb98efb4472fa544c336ece34c991b4ab70b6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0e39031830ca7edce7972c358be82376e667b10a56367d3dc4c974ad50d802f6613930937bdc65e2", "5951f6f3d52ad94ac8a2ad2535c7d61d7f13cdc7946f715a9ebdeda626a724872867c08735b537ff" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "698ea749c25d9a934d50e1bb20d8246243cc650d16bdc4cb165553a01fdab3dc3bacbf053fe5697d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "40060af51065e69b454762703ada9e0dee1eb92941253400c125501c932d1d790197be29d8a4573a", "4709195e38285571a23d12086103698849785f1a5957efed861b51bfde70767e2fe00ef5190e1eea" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "586cebd6cc793cc71e949245c5d7044e47b786f3a0779271d3028cd5c9d0eee17c55ca55a82e4801";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "77e02441e9977a3c7d8cd16b1ef27a0de1a658787b82d7bbf70674a4ad31e4125e6282a29dfba202", "0089a75f0dda45602349d7901518df670bc679e3163b25f7f77af50add012bae0b381b564484202724" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "02ee7092471bcbd0194245d7662a7c8ee77414f0316e4401a17e25ffe1c8421e73c0debb46806de2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a7e3a5a77dcfe4d67b05afb3f51a575208623fcc53b051910efcb660eeb1cf2390846e55524ba564", "00c1c8a6a3fa6e808d44ac7dbe2cf13b4a4d4f46e6db28c6a4ad02f8d74c18cc45fe28be9ef29cd72e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "443c61e33c82a08bce3bb29d30e976cc97d5d7134f1be7402f841def418e78362133f07224919d88";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30087102951c74de9c10c6b07116decbba916f2a24debf027de887abec0451dda9e69e5497b180fa", "0354e5ff4cd580364f1fe598877ddbdfdfedc1a24411e9b96bc0d08d0b5ed55e7c10c99ad691ea5c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "47ae4a0ce41f8da4b35f63b1bd55a01e239571a23981cff63c5f845b314bf81208e374cb3fcd64ed";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009657b24f3a8e68f270ed824c0926d290a62b782fbaf5c9793174c80dc36b7c5678aab8981678c679", "2b9aaae5abe080b9467c5fc58ef8a835d38c9aa821751134c07880a72e1862c63f840f48cf253cc5" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "1de9e7aa69ae45a73f6b3a05cc19b7771277b81e16ad5c508539fe05a86cf112d1b764510b4357e6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5605f3a5152c30346c7eb48a3cdff5ade0d81e6987460ff68f9d412ec676e84fb9a3164e43eb9c9f", "40de2377f81398e9728569423a93dacd6f07ecd38354ca1f487c4bdd8900b9e6024ae47bd3f44efa" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "1f0eb2e2f039733cbab46abd9fbbe0c2bf8a73b76a12ff21d9c845dd707bf1b9e3d2d629ad4cb8c1";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "202516ad663775f12155521079037f3fca50c64faa4afd886add4daab927f3f62aa2dae684a635d6", "632aedd530e61dab35916962ee8f23ed688198afd5ad6b0705e2ef9d0ba3c5333b15bdab432ee342" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00823a830c58d9dd370f687ff819142b644ac9dc18a94681e2245eb22f27e333e62fece397231769da", "36a7e237ea2f3e2472de147e166ce4bd8248208df538ac00f5b2299e2d729b0dd80e3e106c060844" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "387a759284f65d2d93f541f2766f846abdec239190e8cddba9b7564a83d58162a489f25f0d43b4f8", "424625a6c1e1589474c30e6383c925b363239d1a87b9634fd8aac2eb0ce39e3763873de77358bd4b" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c989";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6b4327117e9c04d7a58259c5207a36e8d278e873b92b5b3a70a3c4742cc583b41408aaab23a12a9c", "009b0b26160c548abacd7f0e37276f917c09721b3844d0b26e9ed5c76c99787992259bf0f7b02445d3" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb700";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "277f487faf77a65dbb791536e863b8c70f904fcdcaf52740d4bd5c469731e58ea6bd53e8d7720228", "2d346f2b4ca7bacb882fef749c2713f1a75f00827e8b9b9f744a0e1e34bcf80799a120950de95d99" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "ad0b664f9559e29e46fd4fd390e75abebf14997d17a1a3304c80e451fc8f79bb7cff168e17de6f22";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "73bd62f3bb329d65092b5d13c5746d462401d2600994d8fe2ec5ef5b9f3399084b1ddc64cb334bae", "00c1d1ac4f9a0c2a79ef7ccc4ae9165ddfa76138235718cf24032c33f9db4a26b2b03692a56f5202eb" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "20a75551035db95d7a1a673d464d276da0861008e4644c582bc10a1beeaeb070823fd064a2625ebb", "5d47f0c77fc57e3bb0e153bbc7e9bbde8db98b0c46c58154af5b9786b10ba12ab3ba8533a3992883" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "8ce984c0247d8a7a9628503f36abeaeea65fdfc3cf0a0c6cc8dac9da9f043b4659b638e7832e620c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3f436d07cb0264b13f92fd696334a4e51b7d6619e2d043b2d0d278963f2516200ef905ebf6716663", "40e642b6c966072b79278003651128879f19dee01273b66bead8045194277c9284093348d90569b1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0cc64af035cb79b3336a62d915b381e268d3bcb834f9cfd0f597c37ca5fcf50f588614ef0ef7b6a5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c16fbe6d0d77327cf9a65f987c2fe7ee1807851c0e1c8bc4f0622807dcd4a88b3b912eb0475471e5", "75421c40540050507a163f23cc7cb90acc52822d01d245ab70dcaac06e2ea644327a85f595d026ef" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "8e765d0d1cf9539f682a4155b6d60eb6aa6862b2af9e9d3f94c9ad46d332f0e029775522815c0e5a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00be924007d6e22b944ac76da7fc2660d1aefab69471bd835bd78edd2c10621e76f718bfd0a5e2307e", "00c62583d5ba5cc1c547630476b399866e7ed953b538f76c86afe9cfd0854b57e33691c77e444ccab8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "7225a960d967cfe52ac126a50fd79fa85a586397c0b298c8adfaf138317b0f794b24f53bd920c1cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00acf240130d47d4a57d606595f989129fea7e9744b1e53f5ce679c244c85af35c618607e2ecce1a43", "1b696a7959fe30d049100dd54258181b08a2fe442e41ff29523c11a3e01028eb64b321c2b702579c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "874f311b6b9ac74fc34c60c0941873651b3c0ec1d097a7861e0c7fbec3226f23a5e2c929d856ecb3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "46243b39e77639ac19e9be53669317d9598e03ec30a0cf6930f800009833826a59ade5321933ff2f", "69d770b978ccc36c90b748e5010636e7004ddc19885da7bb90dbfad479fc52dce4b9281405f1c6bd" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "13753ac90fbc7edfdcb32e1697fdfd41b1fb59c5ad177e96feacc87522ef928de80a60bb0f32e7e2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b4b9b6ba3c0e7509c275894e84e818d71de14577bdb4bf0b8e5e1332d1087f3c333b73e8ab75f2c9", "4f33d0e2ab342d2e1968ce3e1c47be87e39ee88273ae4cf777869d3a1703b63a983d2d43c59303e5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "26ea75921f78fdbfb9665c2d2ffbfa8363f6b38b5a2efd2dfd5990ea45df251bd014c1761e65cfc4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "03015b3ca67683467c79446d4b93d10978330856eee40d6d58683ac73500ae315c5b582351c4226b", "18d89561d3ffa0f9311aa616547f7eb1d36e73a6cc4bd230df34a1f319be66bcb2fb0e1f68cc192e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "9fee192930d30502c05e56adf086ecd13a92cd43ce0c72ea65ead43667890ae19be835333c32c5f0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "187d93f84a0e6043f097d0a87f8dca07739cf44548a7d3403e039e49c4c51285482975af54ec056c", "0623c57538fefb7231d619bbefd4cab373a54b361354e586b1d9981a8835e9c6beab082cb93e13b6" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "963f97cb35a321df62fc219eb2f3703949c483165d06db13c403080a86c1e5d9b43d2e8dd9643cde";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0855cc20351126b38f934fbb56c302f62a360e62493c2d529fb87caea0d71bfdaf5fcc3368d495fd", "1ce7578610cbec465398b2c1238b3e23b9e29b476196106430d76316aaf29937ace658b69c8bfb99" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "13dbff9e667e7bcd44950226f93b09738e793517c02886ae9f2b3dededa756c9049ab9a46bc7c93e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0094c54919004079be0db4c92dc1fc947d79eb0f8e869d94813886ada4254f1dadb4d87a6112a58336", "0086d8b5beac00fafd647ef8b631e899a6a8b72a511d4f50ce156648ad9cb708fb2fb2c638fdb9f332" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "852466cef316992b3ca25cc54b7f4fda2e8a819e7c4b040543e94f9caca02937681c2019bb49ee43";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2bca76043728b5eeefde89d25acdf2e0b160c5ae0ccdab6bd3baa479f17753c3c000ccf8ba8623de", "0092f0c2d68a1bd405e449823fe63b21402aef3e9a017dcbc30af18bcc79a85264834398c72fa2bb16" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "634bfe1800786b0256e90ac2de272f41c85e0976c0caa1691bd835a5a444b1ed1705a0361ae6ee36";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1c013b3a3260ccfb53e3f6ce93e6984865dc8e1293e92301f4cb3a554bd5da8a53ee101b3e1a3009", "0097d2901e26729303e1cb93a8b72dc2afc90ff5b44fd5b6624455487974ed71c7833eff03cc128d0c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "c697fc3000f0d604add21585bc4e5e8390bc12ed819542d237b06b4b488963da2e0b406c35cddc6c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "624bec4520e6044abed1eee4964668775181464c5d6bf5a8b539f1156f3248c02271bf9425b966b5", "47f406bcc143226d814cdb988d76412ad186bdeeb869ad78a32fe87c76f2545447ddf8fbd0430811" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5685b327caacf14f237ea7e9c873ad5f5f8a4cbe8bd0d19826407228fe47bcddbe7f8b470bef3791";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b2b2738e3055d1596f64176cf0ac381b3a8178a2f021403350218fa18f9f860c1bba39fc524bc82", "09fbafca1afc5af7598b878d69cb875be0d39f41ff01b09388693eb310adc9d4836e226c23677e51" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "a2c1f84088120fce85fecf81f0ecc00729f4199ebba0d5b5eda190001000b43168db254b8ef32a70";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "40902bf6b239d2f3588260e9d7f512253fa44f308a0ab81dff05b8fa2e25814d65c2018d49390aae", "016f8ae5691938402adc0ffa29bb87ef0af0ecf3cd446d97c3e8d12b3b09eb78909c1b91b1b8785f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "711f6d0abce96fe7f5bed2ca4600a021fdda9a8c922fb0e10f180f97fa2cc84dd785c71e6c41dbaf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "726533e26773ac720a115b02de89ac15966677e239b7c577a1c15b81027b1feb73e673601e211aa9", "2accb585bc06cc274b61c9e614746edd248d1cccf8d8b1ab4bc15cc58cdf116065ce9767f2a3223d" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "02a6eb408443d24e96be4ca0278442a8a426087f9beb03ffe5526162bf1dc30434cf7ea79574b19b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "53c3da4de14f7d35775f9beca6d53ee78dac73cd3f18c6fbf709b4ffa7dd3e70b436409b9b285d1c", "2a5b60e457e58422c959142b5ecff236dfd76c99c3018cea904058099a13647db08898cfd0509e84" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "b6ba1aecd240debe77213a4228b125603671c9d5147b6c0b36dd23e42b7cb5078a1b8fdf1b98b93a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cd24ae7f7523adf859db92e51d48746b8b2f868620898a9c42f8bae8173e3646f586fd818712430e", "55b12d59f7344168f796fe59c026eaaa139745a8ace97df1d5c6bcc21f0cfa6860f9c8c75f391629" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "957b383ba1cebf5ca579ef6ed10027988f8424f42ffbea2e51b3340df9f8c3c60b558d6dc2df10f3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4db460209972c8e9c365119546ac457add157f0c4d2b3cd65c635dcaeca617029cabf75c06101bb6", "009ef8b7626e6b2f9845b0086d2a964018b9b25eb8db426bc90694cc614b7602b1fd6087a9a71cbf1f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "98ff1db1b9affa33a2e53c684d3f07611772405e8c200f2af2afa9e53c6e8ef30cc143b3f5ff7fb0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3e7ab850840d75987d33837ead46499ce433f3fce67383b2e325dd2fc7e0f500769cbb67b4550a28", "00c30314487a87094750334499dbfbeb2d5cb976ee2d47997321597a41124a038fe867be0ef668c4ce" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5e9ff4433ca3a4af648e0071c87c2e5c3554b11761b10bb2b81725028a56c4fc92f1320ca7396c4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7acc919934b0fd90011cd96f59ddba52e12094dac18a2cadcb03a0f31ac72d3fd5984a11e9220f8c", "0629bc5f3f0dabbd3fdd30f47a0a5bea3052892f8e50a4033be4795b32c6671d141b473080e57911" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "c76ce53560163f157b11e4d05c61540a5df6b8241cbd3ba7d911a7541eec55e986ebf811ae50a8b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "12c163fe25cb79ad59c76b5280dc6706a42c58596230bf7ba7206e6ce2b467e1b7a7063e59b0bed6", "00ccbeaf22accb1ac41ed43ac775b97aea3a688e2f096c3a5e59f868bc919da5ce252cf5d712e7de40" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "4218a45116ea65b283cc7d90a510f077b1b09eddbcfca3e7d2896b869dd3ba556c4f10590b0e08cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6960bfcddd0021fcb8a3d7aa85f96cf360a7113e3824508525021f83e3085989c35e0c5772650330", "5c1275b9d8b5199d461fcb9d34f8857b65a140462fd5cdc7a33e5cf7f4e2d08a5a34d9ae00b2939a" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5e5f32423bad3644be718d8195341362c9cba52b330f913b1521af6e5e3eb2069421b05dcac299f7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66ad2c26012388c8b9046a466b87bd71b64ab81b54cffc5a611f4b7581ad8365edd08e6afd4a52f6", "1a3066c0b3b703ddce746239a4d3dbf1938945f15ea9497bbfc45b389e130350b9945922b87ce374" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "ac07aaade5c5fb2fe5a18bbefd262e0e439fd68e0a317db06ff4ba623a2a03114ec5b6e084171058";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0cfa6e3838d8113a24d87db97417d68f00c426e9b8550d8a951fed531572e7cca66ffe0ae176ff0e", "312fa02e5cc77c21f4a6630e25bcb987dc1eef14aec80c15b9b292e3acfb30bc2c0438f0a9831c07" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "311f6d0abce96fe7f5bed2ca4600a021fdda9a8c922fb0e10f180f97fa2cc84dd785c71e6c41dbb1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3dabbc36a455ba07432da1aa7239aefdefb72ac09313c3a7f3439850f602543eb4affc5d8225b5ee", "00ce48e2f67e82d448b3d8b9b0fc200832a3d1ac88058872762fcbf027e9f5705d8f5812e507dae125" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "623eda1579d2dfcfeb7da5948c014043fbb53519245f61c21e301f2ff459909baf0b8e3cd883b762";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a9658dc5f91aa577706f1d91d2252cb0d09f2053e561129105c7f37ddb2f972b3224f12cf9e43fe", "08782ec6105f4c06587eb1ececb2f4f4a04e236304dc75eb2efff0be66b977fa804af73bfcbac78e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "935e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59313";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "06b43bb9587ee158ad5752d1ad11f6f0f5e316ad21937cdd9253f3844857f0a25e7b677bbf999444", "009705362334bdceb68ae6a584640c95cb10789b19953f5e119973eed735177aabfcb263fc8ef5ef97" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5b5d0d7669206f5f3b909d21145892b01b38e4ea8a3db6059b6e91f215be5a83c50dc7ef8dcc5c9d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "568803da071e6b9f4380e39954f2b0fc0f5bb58a0f68b5d1a42c7e9052ece2a0fc7acadc0f423999", "00c08367945495d933f206927a2b7f5b74b22f973a898355aa2f7e295e06ef3a4f561546db97f79afa" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "9563bd68545ccd185ae724d8efcd4cc23234934eef10f280792b2f930c97a6c1e00829a8b975b9ee";
                bn_t sig_s = "c5e79c49abb135129f0636e18e2e73bced30855deeba1477d9521b33a32865155177d946e1babcb4";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "568803da071e6b9f4380e39954f2b0fc0f5bb58a0f68b5d1a42c7e9052ece2a0fc7acadc0f423999", "12dadf8be2267683ef35e5e4a68284f14760386c6d70b8452014908e71a4b1d9a6becbd659bb932d" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "9563bd68545ccd185ae724d8efcd4cc23234934eef10f280792b2f930c97a6c1e00829a8b975b9ee";
                bn_t sig_s = "c5e79c49abb135129f0636e18e2e73bced30855deeba1477d9521b33a32865155177d946e1babcb4";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d1a100118bd3610f10e13b5adcc7a90a37f4f988cfa4e22cca77e88444b00216dcfe5f68418d342", "5d5b88c9b8c92b3dec7f7bcc688a6d18e6cdeb9176150d4b1062a832c8a3bc377f8d7e98b1db0b9d" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cca9ac38de5b36cf79d8e415cb729e685e0bbdafe161c5e7ecfa4177e826e815d66526aa5daf3227", "009b7799bcefc6b5d8d09ff1a0739fd423188126f80af703314da0d26ba6714aa197a6582c36b0f05d" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cceaa1203bdcbe15e20434d624f0ed9aca81d4c82f840bba3a86c6756262aa37efed62f5f1d097f7", "457057b98d2b9ea6bd28581d40ac20fcc9d536a117769203447bf41e10ce4da1ad794ca20f8ee146" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00cc9ed25f13e94a6ebd531f3b142fabc4ed522dc6127861528830c6787d6ecfd4b704e1774e9118ed", "68e4e172f93f1d5b8d7860fae2c115f4aa0daaf6df5ca3809d79acfdb9ed2be19995658d2f44d235" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6a3cae0edc8455ae16b5eeb6569603bdaeb5793699e85d372857f1319c70dd525b1ea30a0f5c7b44", "075537cd822d9ee2d0e7a49c4c3141445d01b789bbcad02ec4249c2e2355d61db5581dbdb342c993" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "a91838e692303fc64dc9f9e574ce4d1e613fd9515ed8dbb5bdd3589ff20513ee05411115d09e0f41";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4efb5161ca1a1eeb59a5fc39cd521d40bd3e034512fa2a1eaf3b7e92bb9e95c06a4c726ceccdf9bc", "6bfa801b067137f1b6b4506041130b4d402d90087ad005e3f652e1d91c9d344cd1eeffff61d3a306" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "b52c3cf70a58445477eab051464ac05768321fb29c7aa242b9194cab5ebc4c35e10edb72cd3ba2a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5f658687e6a542a91d893b48776a86d528fd399781bbb9305be0797e3a6f36118ae19e68dc1673f6", "676e536c7897a0002f9664929631f418c4537d23749220c50a32121c434dcad2a6cdc203cd035a32" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "53bf06e43fcc4236b2ec0d88471379053f1f3437207c5a75b09036b1c40fa8f3128277894a4c96cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0090537a6827a25060273d44d4846aea596682df0a59d0ffe79be2a1ebe918703cabfac64da5e59100", "3309180d9da5e78237b95403c52f3ceee503067b672715e97d8b6369342684a72f467698741b1a1f" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a81ccbf4fc4457033bd49ceac8fa52e459400730b877305be0418153d278d30b5973777a7dd1c2c1", "7544ff1b76208e841053ecaef7a5869e92da08c5c4c3d0a167d5685eb721d620339cc9b00149838e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ba160089327cf8ba163eefa476a4eafd0f6ce9d55292f6724d020f0efac54bf684f9d5f5695f89c2", "00b4de70dc4ab265761827323da3b2b055ac1187fc5341e4555ebc6f6993b4c3fdd89863fc55ea38b4" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4a5cf447550f0ff2efa193c3e185db604fcfd7de5c47a59a392da0c7572f061038c6af5afcfa9bd5", "30b7682b82010c39334ba2edecf0a23bca09e810d745bdf73e445e80ace0e5399fa26102cb3faee6" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "a91838e692303fc64dc9f9e574ce4d1e613fd9515ed8dbb5bdd3589ff20513ee05411115d09e0f41";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d3fef1b96dbc8ca9330508ad4ced491e627eb67cba8c6b1537937498ee3021b45ca6759117d89c4", "00ad2b699e3ef9516fff2ed2e134931c96d28d3e14dd51c5b87589a8fa88af2529b8caa0f785ce2033" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "b52c3cf70a58445477eab051464ac05768321fb29c7aa242b9194cab5ebc4c35e10edb72cd3ba2a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8336702c158dcae495f1c9cd720c39f15c123a67750dcd74520c34cf67907e49220bcd020cc3a60", "151a432ee3e23a74c8b8a98d8e7c672216df48d8a60d3f592f6673830ac9ecfbcd00550db7ad5c62" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "53bf06e43fcc4236b2ec0d88471379053f1f3437207c5a75b09036b1c40fa8f3128277894a4c96cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611", "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb700";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ad0b664f9559e29e46fd4fd390e75abebf14997d17a1a3304c80e451fc8f79bb7cff168e17de6f22";
                sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611", "00be6076caf0d032ef35fbe53a528ab907f24bcfb9e5828b04a5cb4174cde781612981cce088849f46" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb700";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ad0b664f9559e29e46fd4fd390e75abebf14997d17a1a3304c80e451fc8f79bb7cff168e17de6f22";
                sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "44ab2320c2297b66114428df33fe641956f82033893398af3b49b0023179201c27d26dd65121c06e", "0c59524c938f19daffc2a9a4679dba7cf1991ced4700592bb75e98cf77dbf6c584c2f72735152921" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "9cf7f0d60cc1fb2d4b3e78d5f83b374e17a4aebccc6e723f1ad35babb2acfb2b75530389189395f8";
                bn_t sig_s = "001110c5b8b8e5fa8dc7952a7bf6200bddae6c1d66639a07a4b6046e00bfa7a2bd9d5777b80c3a92";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "26fd695ee1cc50c2661c2434f8699577af181304bceb7690c538b03463df24334395e791f6750ff6";
                sig_s = "b322618cd50c6a7cffcb419ec05b67ec6a117088c78d57cecdd224902d391892ca03e4bc1bd0467b";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "7a31b7375f924369ec12bc33b834726c95444a4c263557344afa732cf48a155e71a6ee7de42e91ce";
                sig_s = "24d3d72861f4d2b551c10f0294d16a3bf1d4ee3e484439b804d097dea2d7cace76ade14af1663322";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "2417eb10a538921621066608243fd6574de84ef1281520f01ebe0444b46a607ab9eda8f3721779a6";
                sig_s = "8f1e2ea294028baeb738181e128c86ad55cb1945436cf69e090c2f6159f6f22011d731733b4433ba";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP320r1_sha384_p1363_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP320r1_sha3_384_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP320r1_sha3_384_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of ASN encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   BerEncodedSignature - {'bugType': 'BER_ENCODING', 'description': 'ECDSA signatures are usually DER encoded. This signature contains valid values for r and s, but it uses alternative BER encoding.', 'effect': 'Accepting alternative BER encodings may be benign in some cases, or be an issue if protocol requires signature malleability.', 'cves': ['CVE-2020-14966', 'CVE-2020-13822', 'CVE-2019-14859', 'CVE-2016-1000342']}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidEncoding - {'bugType': 'CAN_OF_WORMS', 'description': 'ECDSA signatures are encoded using ASN.1. This test vector contains an incorrectly encoded signature. The test vector itself was generated from a valid signature by modifying its encoding.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   InvalidTypesInSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains invalid types. Dynamic typed languages sometime coerce such values of different types into integers. If an implementation is careless and has additional bugs, such as not checking integer boundaries then it may be possible that such signatures are accepted.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModifiedSignature - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an invalid signature that was generated from a valid signature by modifying it.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   Untruncatedhash - {'bugType': 'MISSING_STEP', 'description': 'If the size of the digest is longer than the size of the underlying order of the multiplicative subgroup then the hash digest must be truncated during signature generation and verification. This test vector contains a signature where this step has been omitted.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "44ab2320c2297b66114428df33fe641956f82033893398af3b49b0023179201c27d26dd65121c06e", "0c59524c938f19daffc2a9a4679dba7cf1991ced4700592bb75e98cf77dbf6c584c2f72735152921" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "1df0b7216839cbb0053b366f923c33026fc24098f018447d0cc6876c1676e07e499d948316cd3a48";
                bn_t sig_s = "826976dc125cf3e56ec88a6f8f0869fec2170d5ddf322057d7b3408860862d8f30752a46c131cc25";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "990dc69bca3e68f79f0e59a60f0008c70daa5031f09255a5cc7b850d4787339b9a2a35455137b896";
                sig_s = "576c1476d74a36ca1a426b5ad68499eab0a3d1096ddf6783c88718303d11b3646d1b419e16fd7378";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "26134e31915b884eb75efcc379b720c3e9016efb11d4005f9568d66bf7f160c1f4a67617dce6bdd8";
                sig_s = "47b3bea3826468b7e252bf458fee8992b2ef6957ba41df53f94223a123c9e83db0521fb2be86dbb3";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "cd231c280096b5cb236a53f5edde23c7f25f00bbe1b5ebb19852f6586de77ebd9de1a2cc93b95e5f";
                sig_s = "1c8353a32cbc8bd23d58517da603c4ba83caf1655e82cd91692b8f03c7ca10934836284fec067d5c";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fcc8860cb26e262ca8b4ecb9c52f78d82a10a1d30dd0c8ecd7584ce80dbb75c488a062b64375500", "1f27e676c26cd3488c1ef4ec3edd88cf8af78daf9036724b57e66da02cf7c676a53664becdfedc3b" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                bn_t sig_s = "8f55283e35bba5abb958fe66060bfb1d9f264b8201bfdce10d60c7bad8c50ff6eb8d2170d662cee0";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d70000";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d70500";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "7a59faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a457";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "59faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c4310000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c4310500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "46091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c4b1";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c4";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "ff44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "7859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "014bb841c7873d9a2e43e2c374755afb4805bb5f433e660ca8be5929e51025c65e9bcc441393b737e8";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "a4fbb38719c4fabe8169d2b6d1573a7c129bbff7d147e76263c8cc553319148b8ea9995d0a2c11c6";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "d3d6a11ade0cd102579f1ea9e7a53980db9bfb355416e99d32d93fc30ba7f856fba69049fd1484b5d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "87a60558af7eb5899d59b4ea5ca6e51df3d47062782905fa6eef04e2de60928aeac51147b10e5b29";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "5b044c78e63b05417e962d492ea8c583ed6440082eb8189d9c3733aacce6eb74715666a2f5d3ee3a";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "feb447be3878c265d1bc1d3c8b8aa504b7fa44a0bcc199f35741a6d61aefda39a16433bbec6c48c818";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**320
                m = "313233343030"_hex;
                sig_r = "017859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "0100000000000000007859faa750814a7662a64b15a3591ae20c2b8f9d87d6fa059110fb1d219f6d75153aeeb84ef1a4d7";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "011767660237bcf9c4091ff2579df7c5ae53f953c96b5e48654d2f95d50447a1dc21958945b3285742";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "ff70aad7c1ca445a5446a70199f9f404e260d9b47dfe40231ef29f3845273af0091472de8f299d3120";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "d3a2503f18bd5061ed645bd8cacdd64b41ea3929da43e1d8ef68162efb9c1a32792c598f2f33f5d531";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "bbf6e11dfeff55f3d81c8607340a1ab7a5967bdc4b30ca3de01898f2ea3eb70d64fbcc15919d3bcf";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "fee89899fdc843063bf6e00da862083a51ac06ac3694a1b79ab2d06a2afbb85e23de6a76ba4cd7a8be";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**320
                m = "313233343030"_hex;
                sig_r = "0144091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**320
                m = "313233343030"_hex;
                sig_r = "ff44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "01000000000000000044091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                sig_s = "44091ee20100aa0c27e379f8cbf5e5485a698423b4cf35c21fe7670d15c148f29b0433ea6e62c431";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59310";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59312";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e28";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3337313538"_hex;
                sig_r = "25166f47ac99c6bec3b038849ab4ead3b251f18afb0da1da5caa604a92a909c8561817684abffb92";
                sig_s = "22430ab3e14b6cf4a56c4c24a05ce4758467232629eb8101a995edb8f81660d4037ba7f057a8b5b7";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131353534393035383139"_hex;
                sig_r = "96b56e4f5ca6a77e08fdd100798c4e295c991c23e0bb0862b0a448f26523ba6e621522f0fcb6f4dc";
                sig_s = "681f9bea5bb26e77003cc8e5057d20501e03a08cdf9df4a6b1f92555fbad5142503712e868f4fffb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363831393031303832"_hex;
                sig_r = "c17eadea9492bb860e86519072d1008bdf396231b99734805a311db0c51957d32356720d62b3aac3";
                sig_s = "11bbbed00ec6402bd51885db44e1cf8accd05bb9b6847952234cbd45aa9f1fd0a04623e929342ba7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333336353438363931"_hex;
                sig_r = "4f72a949a03227dc057a4c83d5089f076fd0d174fa6387d5907019a876e4b1fd237855e8966276c0";
                sig_s = "575c86b2ca89d6cb2245780898bae6f52e212b14be8ad96c86980a07c274f7a457b9de15490962d1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363235303538313232"_hex;
                sig_r = "68532fdf732db9de308a1bbe79b281567eda1ff0f7c6179ea61f678a6d4457319aee89bca52005bd";
                sig_s = "7884b4f1e9917fd179f3ea4126d7eac61a33b9516e889e060cb3a2f2744820b2a9d8a57da2497dbb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323739333237313834"_hex;
                sig_r = "b5b90052ac94ea20b5a1d07ab6f319bc0361661979bff0986ef0c806867ccf06a741c7b6368bfc18";
                sig_s = "30efe58b33ebdac9b7ba0cdbc9d85d9702ea3a8b4cca2d4e3de53f33b44836d268392003bf09a267";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383836363432313439"_hex;
                sig_r = "73938d137dc151d1339335c27b51f451781f289abb61d75fb6226e83f6b22d70ee017dbd30d0c731";
                sig_s = "c01c5102209e434dc5bd86f1d4103f29ccdcd79d18cc52039aeda36267a0e3f611d4b683a9681eea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333737393036313539"_hex;
                sig_r = "80f092dacdc272080ab183c5c898aa4aa3169de0785a41c1eb7d3d1b2e193ab76001b6d3be8107ce";
                sig_s = "58a1b05dfdb3ec33cfada6ddec72a24bcaf1a664008a61b702fcfab98a9e320cbda541ea3bc5b8d0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303833323436363234"_hex;
                sig_r = "99e78d55a807be57b8f8b8c514dd56ceff2dcc6e92cc5e78670336ae2021cae4b2099e7185f1f808";
                sig_s = "0faf3c7b95812a4131c68ce5e9e1c0b5348867e368cf041f0d3ab5d6721a057aa8b8ec3a99e91ff8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343832353634393539"_hex;
                sig_r = "a9036c8644e3be5d80efbd934a9d4478fcf0acc6d5fdde16cb05e88b29639ff9a697ea0db176f986";
                sig_s = "850f0897b85d8268a6976a8f82a8a660021aa2555a4237a7a1bf26a37ec76eb025d309f9452c7d3e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303635303732353033"_hex;
                sig_r = "5564073e989dd7255883b2913657bbeb2abeea525e71905315602d65501d26566b6bae20def57f97";
                sig_s = "bbe1f83cfd14b40de0e4ce620cb6263c5d577296dcf2c6dc4ff1c8062110152e8c00bb6a741c84f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343932313138323033"_hex;
                sig_r = "5513b6a74d7c93e00365d983745d454ff9468139589de293900de216da3dbf08f1fc07c6b4191101";
                sig_s = "a6659a5fb301d6c135e3cbf9cb7db1ad3240820b64574e7e01bb9d15f4dceaef3cc8dd2a636aab26";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353535333230313336"_hex;
                sig_r = "2f40a2dee6fbffc556b1d9d27e83db210cfc225d1999814de81ed18b2365388dcabddcf3c498feab";
                sig_s = "7f360df60e70aba2d97f48f1cbba06e16dc5c78e8e0ddc938626feef70ce6c3a0b6b95e119a43201";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333331373032303036"_hex;
                sig_r = "5bbff492841621fac5e68205ec994437f0de9aa9d0554faa48502a22a44a97096b5fdf049728d7e1";
                sig_s = "c00d4788caf9aafa244e8f9b51bf6c11d355811bc09ab249812b42fc1d2e7b31c3c1e62d0489942c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373531313832333938"_hex;
                sig_r = "862a7df9460a05d6fb199626efae385dc12b9269160d84c90f6b94a9548eca8a3e0c61efc80f1bba";
                sig_s = "a86af4f643715d87fc9da42a5c8a9b64cca36ec8400bf48c3cbd9dca10648b8b9668636162513c4c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737303439353436343831"_hex;
                sig_r = "b2ee1b485f497a633e7d9e81a809bbc0d8a632386655cdbe4cfbbd2eb93bb270ece51f878fae9b53";
                sig_s = "2b73fc1c1e7637fe58b3886e1506278e38adcec92f239ec33171e8cb04f5def355a4bea265ac5c73";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323539303733303333"_hex;
                sig_r = "8273b4dc20862646cd931bb1fad28710153c6955a5262bc0b8a8ffaf24742e0461feb02d65a175c2";
                sig_s = "1b6b8151707f999494569122472e4b3dd160b2f423dcb74ea4a5071cc7a69b8dde5bb86f6d7be2c4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343139373133353036"_hex;
                sig_r = "6659e0d0fbd6cdb0136f6b5e5e3c4ca0cec67463d588096c9b2e2cbcbbe185d455a3f22ed429edfe";
                sig_s = "31993a1d231566076c3eaa2fc24dafd59a56f591e8b9a8308ca6abc227e1f1f9e19b388ec5b69bde";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3231393238333534363838"_hex;
                sig_r = "2b2ce180dc031b96802053c860624e8a4b5f76ec232dc72465db042b97f7bd37afb501b819bdad2a";
                sig_s = "cfbd71dabe99badf9989e096bedb64bd120c7be892d9a6ba696eaf293e1221e8b9f51149a130d159";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363235393934383739"_hex;
                sig_r = "c07fa346e5826db30403f45bc4d706b03a54cb9bc66f4f451aa6fc1bcb4da15a68ca0199ba5f1bf7";
                sig_s = "732405f51c4aad33be2c27c5b161f4d9da234976b13dd910801ec89a17390a1ce8bd01dcbb571105";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393538343937303836"_hex;
                sig_r = "a65db0e7c71925071821e73d4dfa4bd2fb8f5644c4de51847c160493df013ef4a4599592e06e3b7a";
                sig_s = "94ba7bea8b5687c0ae8419110e1def2c220d5f1a8e8e07751c10f56afdc4c3384ee9c1d07e834ae3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353939333434393638"_hex;
                sig_r = "1421e07e71b0154b989d6459491adc5c1f7d4ce16be2b0890834dd1e47d90d6abb5367ad7629ab3f";
                sig_s = "432157414e26650f0f14daf1b2a94b92b1f956da9b31acd8dc2d3fb80cd5fcd99eb016b8348d7a0f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323332343733393531"_hex;
                sig_r = "3f0fef46b6751f3dd965fe8e2b2a72b197ab85c1493577e9d7f8f1c400d54f5abc7647ff139b7719";
                sig_s = "73b1b6acebdd946c5232a4256a2319be2ca0cbb1d971b01b1aa0ba7b567dc310baabc48d345c98ef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737363033313033323137"_hex;
                sig_r = "0413f313eb68b68720bdc351866d4fa6fc877edc91eae7e51c092dec0a253cec7cb6020478c2e40e";
                sig_s = "c7416b3576936e0e9f22e8292d859d6ed16ed1a90dc73c62e6f229c369e3ac1be5f7d7d1f9fb665e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393534383338363735"_hex;
                sig_r = "1361b05e30d1e71cfa8a56cfcc2d54c310cc4c1c23ab7db676f3e2320ed5bb6e9ec0496a30db3dd9";
                sig_s = "6cc089b8072ce69da8a521379464e0ef2a95b2d9a75a4d3377196093dd48fecbbbd9e2d2f082fb49";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343533383530303035"_hex;
                sig_r = "6eac926459f7ac5cd4ca3a9bb062e81f332405ad684a97873c12f63edd9d3197a3097d4589e32f82";
                sig_s = "41cc9b217abae590d1e6a9b5bfc70a295da32e330dd8e2c02ed9bb59f5329b95b90434ed6b881892";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363934383137303236"_hex;
                sig_r = "88ad1a9603e2d5d002e7a4255ddafd98711338804c9e97c70023f6f9582c20282cde8675e2a79d3d";
                sig_s = "a3655f2f43eac97b15799a6c7007ecf5bf1bf6811c9735028eac55955bd46945c1c89209c91e20c8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343331323036323937"_hex;
                sig_r = "d175a4cd6ae366384d8fdd8025096ff8ee6b4f1f5ad7e41ce1a2b766a94994386a0ded9f280d0def";
                sig_s = "6a3ec3ba0aa4fff1e9ed2ab4a6de6c26cb039f12934db1d9e794ebbfe8d2d164f1c269788b729c12";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323031313936373336"_hex;
                sig_r = "59132b6452aa8f8d6a5c68fa027aaa6da9119cbf7f25392041359d50e9b3cd7d1f5942d6bbfad0f9";
                sig_s = "cb27d24a6943dc887eda359cef6351bbd85dc3b7ed18d7c4b5465baa017e09c1d1ff49faf13a7dc2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383330303038353932"_hex;
                sig_r = "4d559032c70a97e0700c88af92166c0d2035993d9685e2c22c543af04a82d95914cde11bbfda1bcc";
                sig_s = "c3822076b28d0c86119229b4fa9c66cac3ec9069150e3c9bb5e1c7ba53a5a41125282688f9e5dd57";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383834323632353236"_hex;
                sig_r = "437b77c4a2a69fba1b29c5f5a52c211cb7eea38370774d9a7e529cfb451593edd71cf9347a4f001f";
                sig_s = "8ba45c700a5ba46e46283abc06853706b78d6a9e9a16cccca50c0daaffe120e1bb3b35c8ae5b1ac5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132333434393638393037"_hex;
                sig_r = "2347c452dd6f7c039294604c79676e747f80a1f650b51ff64c46de737b3aef99828df713ada316f4";
                sig_s = "54170218466b53a3e2ce373a42f012f548a7f911695799357cc21cd62ebba1bb276e68d4177470ee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353439323433353935"_hex;
                sig_r = "8bc6d8a3bfd7a4d2ca8af70bd9b0e9fe2b51d4c8c641bc8b8d22c805d7390dadecf6550eaae311df";
                sig_s = "7a1aac6c927b3d12c805c7fdd780cd545e4d5e802ad6b4ec4f120151e95e493521342924e11ddc23";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303832383235333337"_hex;
                sig_r = "4c6c2d69a94bbf0485d54ac20d2de1c90501b9324ee914c7b79531d013807e09d943764fbd90842a";
                sig_s = "3118a437ac08090aeab38d4ad8a0954e7b5bf9a0ced7c08394579c26ff0a8ea0485c1e567f8d85ec";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303337353732353536"_hex;
                sig_r = "3996c88e0007daebd98b1cf5e58d6c7c76b7fa72b9ab80c49af31a8366d47f0f725aadb48467cec3";
                sig_s = "650a0c483aa3e3aa7bd9c9ca6b8efdda9a79f765a650dfe09608fa3489232b612c03f9a7a496f85d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373734343739383034"_hex;
                sig_r = "cdfe1e9bb4381080f346c92d52e355f168f065c5ae22c59eb9f32ea23b96cf343c14450a880beafa";
                sig_s = "ce5bb7b26da07a63014dda6f83b7ab52f3d60fb1a2b9915e001bc8d27bfbb77f5f5fa9f5755e56bd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133333732303536333833"_hex;
                sig_r = "89cbc746335c9fc7fe243787ca3ba9963194465ebf0a98715aa35568252665f0a3a5cac6744b3e9b";
                sig_s = "b7f228315eb38cf42509ff1063184557ceb885e3a396ec51956143b4bcfe1092aed78459a64a2889";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313832373036353336"_hex;
                sig_r = "3b5c3f811c46ef775ee2030a19d8259b9ded0474195b18e28d6cc9359e8197b62557963e3ee0c33d";
                sig_s = "1ce2c88e8e23eabc1cfe1d44e9ea20463784f9d8a9377111792bb25894e1acf68b4c1b49a7896de9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303337363939303936"_hex;
                sig_r = "48c248f40db16605ac19f44c70f2e4068d67af2fcea6933ab624aaf60dd63bd0b66a8679dd508b3e";
                sig_s = "8d849dfdf0f7b897c151981152bcc85c8687dfc720f6710d85fd658684f316d2fd753287eebf2a9b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343230303039363832"_hex;
                sig_r = "64b8453fa3274cdce937809eef3a6e9ed284358dc52dcc458c64c4b12cd7cf31a2a207d0ac2f4c27";
                sig_s = "7f1c5f1010c32e0bb16823b2316125f884247a7932fe551365a8ac161f7297d2fab0e27885ecc216";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323037353534303132"_hex;
                sig_r = "bda9bd9743ac8dcbc89df2c5e7ce9815fd108bc8f9e9f9912f0087dd7016dce4baef8e3139964343";
                sig_s = "ae4aff57910d9e53a21d785207e9007214a822b8bc9589243d95e0f3ed0fd2827828e0ba419a7a27";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383536323335373531"_hex;
                sig_r = "591fc6b75d45d666f2fe61e1117232ff889f175fc3c33dc99367f8134a0ac9c78d94a56ee2493ffc";
                sig_s = "113c0f28eff38485ae23e5e5981605c8ccf4b9f5d83399bb97d0adfb4ddc122e87dfc646ab171817";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363736343535323539"_hex;
                sig_r = "6e846dd1cf589a4d6fc382b2ed5a32381bfff953e6ee34489b54752b32f79d03acfe5a341cbfbfaa";
                sig_s = "0e921da250b2e01a66ae85064483500d012846c1ce49d5a25111f978124a3dc9a1d5b824bb9be94e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313832323433303137"_hex;
                sig_r = "07fd1557becb507a6786e3b74eca5c7b31d1a2f2fc39bf8da20f8b62dfac5481701acb5e32a4f092";
                sig_s = "03755c221d4b9c22b808473f2f4c14190be09eabdbf72c8ca5e8db5b54333d464e35f2d96c05b7c4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353232393434373333"_hex;
                sig_r = "6639a49c8ba65145603b05a9d6d9c3bbba374347ebb3d001490934978f737182a689270347901202";
                sig_s = "830f19724f13f19c290f1b144c37eeefe5afc49781f04077c7699340dd7dde997ad31c2c8a329ea6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343535383431313936"_hex;
                sig_r = "6697940e763aac597144fbf18b3f2ce16dd49fc17cfa3e7fef17cf5d526afb6208cc48234e78e5f6";
                sig_s = "82737609f57af96d915a812658a39988f1e54c7b0860e828d126505b482a0bc12bd7a34f0163462a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393134353430363938"_hex;
                sig_r = "6d97807955a91a231040e46a55161308321469de3d06be91d4f45e4ed0dbebeb375a687e5afc80eb";
                sig_s = "2f4c74da228fb1b1e92ed00de9bc6effc792797355d0f5569b947028ce95f37a8545de3aadc59ae5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323730323132343635"_hex;
                sig_r = "454f9537d0d3291e7f6eb4f32526d023546697b539afe9a600e6b6e444d0196a9239c09a8af63d80";
                sig_s = "c60987c5ec0728ed04333daa1006dfc7b0689b71d1c2745f698cfbe827ee38a2466a0d0faae87835";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313732353737303635"_hex;
                sig_r = "d2c2d244730c2fd2571e0bd3ee98e87192f324b5f7d66c5ab27be2cac0ce256dc2113367edffa4fb";
                sig_s = "a263d765df16129caae5e2c322176efd9f881102f7aaf6261359664c4c632cc403adcf6d9f7d49b2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333835393530373037"_hex;
                sig_r = "b3d1298278b8cb86d23ff6737c8e8e1bed37027813cb995b8a5890cc4778cc12842aed0cd513b028";
                sig_s = "3b5dadf71ba7d5e1616013ddbc042aee7b4fe07126e7995d0ff6e0e93fd470eba219bc7276f4651d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3634333837383033373037"_hex;
                sig_r = "07f24f651b71499aad48cf17192d6971e9c04834a69c8d96222bc21c524fdb697d2f88ba10cbf06e";
                sig_s = "87741939ad3fd3fa3e28bb746fab3e58f8cd501837c0929fbedc40ccb50c0503832fc988d93c97d0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383637313133303632"_hex;
                sig_r = "2c32f640a1086587f862b5a1b93115903b28de765b42afe8ffa040f7c6fdd13d1c867c443c025283";
                sig_s = "85db57ea2b83124dc8e2b6c6a7a116448f8ad123c686b92572f1feef5104ef0734e51ff77dbd68a9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133343239363139303533"_hex;
                sig_r = "47ae60028bc17d58699db3f8329bbc01b1f7370724479df9cae5004d14537abf053df50c9bea7852";
                sig_s = "101efe9ddab6f9626066f8143a55ed46058df3d5c9936814d7f352765fee43ba79ce60505021ec97";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303634343932363338"_hex;
                sig_r = "28f87a101a9197118b0dd17eb02ba4639b35da684b9101513fba12817d0fab28e3f3e77ff30a9c35";
                sig_s = "1b82df365249c14a136912f638942a296a90f0a326f0cbd0198bc4c80320d362f501877ec25ece07";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232373339393133"_hex;
                sig_r = "b96920442a51ceec642e642743328481f38a523dd80fd73a74286d7309356ce84808d4dd70d70c64";
                sig_s = "0aa2f21f342417c4d940e160337332cc8b39ded7a4453331141ec18e8cd3907883efed5b6dcffb42";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333932353736393433"_hex;
                sig_r = "49e5f9dcae3e30f3627863d7c02fb0c23f5385b121bb7ddd498aedbe711dd929c12d52d171e25b92";
                sig_s = "b0c3b09b42219b868f848e8cd582afcff5ee8aba775c42bc291d98abaa4c2eb4b630660bc0e56e28";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343435323032373632"_hex;
                sig_r = "d21e8e1d320b887867ad4e933c53621fec702753d389c3c4a06fdb3d4251aedb770287fbcab54409";
                sig_s = "1587e48b0c1bc16b8c1643913f098840b6ca02a62091a482f67627ad0c3f34c3f4163e0c1026d687";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353934393639363532"_hex;
                sig_r = "825f8a63b079ff2d0334b32c70873b98a05f6dc43888a37d7ad19abd7f6421b1a40fb7f5df203be0";
                sig_s = "d19a30a76db86b44eb25f79fa9c4b4196f865fbb91560e5d4f506fc0632e17c9b698a90ced3af443";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303134363536343631"_hex;
                sig_r = "17731f34231761953eacb2c7e40fdd03ac0c5c4372614ba27678ede7950f1a865268178438acd41d";
                sig_s = "6d40eecb97c22807186535c1e3e5cddf077e9251bdee9fe55dfcbc3ce7a2740bc661037452531e51";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39373034363738313139"_hex;
                sig_r = "1086186335ccb6d20b199293c34f205c0077bced548b0ec9d436427c1f9e32e438faa54987654718";
                sig_s = "99fd6a5341f439a7fd04afbaabbb6fb45f4436528190a89f70421949e79f1329880101860fbf2664";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343131303338333134"_hex;
                sig_r = "692693694c5b1967eb7102f503608e2589a5e8cb3e5e60d01699df3bfbc7a46fa3c9c9a8026d06ac";
                sig_s = "a550e0c412c6b216f6c8cd443c72c3c97a836c886c5fb17928225f24caca2636a451cbe31a6732e2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353437383438353336"_hex;
                sig_r = "02beaef34d8a1c157819c4fc0cb11526b4fcb6693032916261375ae1ece815a64de9f1d369c0b37f";
                sig_s = "b3d7fc2946c369559978528fd17f953ff55b075dbe361bb7b0ba71c13478ae571fb01ba795e49199";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333738363732383631"_hex;
                sig_r = "9a90782a8c1674137bbd9616b20aa8cc5514b09c90b2e47b2edb613df6a12b2e27166cfdfab5f815";
                sig_s = "17329fa8d84d4d115f966b920ea5bb2770844c6cd5d67fcc342c9b7ec75c7d8c5ebc4e8efdc7faea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313636353734353639"_hex;
                sig_r = "66991e433630636d5b8aaa65d625594fa645236166d83a57f8bad9dad03e8c8115ddc7788461c3f6";
                sig_s = "23c6deb58c8c94aed5235be1660e46f3cb65a85f0e0364dd9fdf701a69a56a87fac1eccf6e07f88f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363431343037363435"_hex;
                sig_r = "8e6909763f6321a7da4d7503291b1ffa8dd1c120086466453455fb61cc2db06ad7f82015a74f74a2";
                sig_s = "9aebc9c0940dead8879d5af426d03ad101dc602fa0948b91938b5af419b31d354d3c3c10f597a4bb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303833363036303631"_hex;
                sig_r = "9184b0e82ecb7b4e20bccffd21a2edf7f04a31e86a644866316a94785240f3f62abd80351c3ad78d";
                sig_s = "4faec72e67ee9809d7b8fcd117f0779181dc1b26f2d443d39e5a313d98fc7fcfef0cbce7fd596953";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383235303436303231"_hex;
                sig_r = "398eb3dfa49eff3ad448c1ec7cdd2544b58094cad0dc2a5b6ffdcfe21d646e6e2ae2235994d8db22";
                sig_s = "3bfed4e73b6864f669fb37e3c00b1f3c4303f921d10e7bbcfb0141e939086e754b8203746e3bf24d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313432323938323834"_hex;
                sig_r = "882d392e0f7d740f062b0e2fb325aed5d77c30220e0313c32b15b582cef5333c89eeb11ec8483e93";
                sig_s = "220e2f6574a1fc0c4e1e7276ca4b85e3c0c7360cffd5902aba3da42991041963ad976daaebdf1192";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313636343232303939"_hex;
                sig_r = "8535cf9d81fc5984d9a527aab0834b4e24156a1a02f6b991c03df63d9a4ce13b2b3e26b61b051c3f";
                sig_s = "45ce184b9750779d39e5b2ae468025b3da56a991881ec3294c13c9f807cbf9b55563b120bcd39c01";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343830313930313632"_hex;
                sig_r = "40f1f557a440d31f76ed2b0f5c280cb883254b09cd431b2019ebae2cbf06c66bda569e2bf055827a";
                sig_s = "7fc49f3bd6be82c5467de84cc15f3c14e09e7968d6f4eb02727c01a4eff02900c0a50f7efd19f85f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323138393734303738"_hex;
                sig_r = "53cf9b4877aee7c12434c9f08b3199f79c2928b858d27b0fdc1de52b5480a15b59103e39531d17aa";
                sig_s = "a2dc4e94329fd4e5f0dd13925c06d89b35c99dbddf38544c2da45ed97c5b02074cac7d7e335902ac";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343538383435393733"_hex;
                sig_r = "c367b70d77382e5d9bba9f9bb7a22c5cc9829edb30f47231dbde3f12852e01a546db1c06d3b6a2fc";
                sig_s = "2cf154898ea9dcbc30a43139f1d277615b3488cc1fdf5fd43d68f4467b3c5f9aadb3e0d4590d72cc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343839323235333334"_hex;
                sig_r = "bb9605f9cb4bd352761b8747614aab799ff63cd3b7cbb5458937705b0c1dfcbf6521874b982f9007";
                sig_s = "8aba696ec959e4fa3c05a6cf3c8005bdfbb8862d7f91faab9dedc40662ea7d5ac3c278bc21a23301";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303433393832313335"_hex;
                sig_r = "9ba2a1ff04a0cc0345ebe72c51f28bfa9908acf244de6b371ec6b0b4140f8245b24c6c2a563d354f";
                sig_s = "a40bf3d0feff59df18a74f5b8d5a148ce5fecf5038d50345295b74d821c76aa040ba25b26b07e41e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393833353030363939"_hex;
                sig_r = "b56f0e81ebe659a58c852f81db037a9a49cb5cdcc594557856d1a46bacecaea2e65bcfb4b7e3505c";
                sig_s = "6f73be444aba3f1984238515c866a0dfdf7b16248d76db1f38ea0d56c24b55ba1c7e5fbcc5317f33";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131333236373331343032"_hex;
                sig_r = "365d3f9b8a9f69bd9f97ee1f3b6ac708a3b534ac8f16fa971c802713e43368cee096b4148dffa49f";
                sig_s = "0edf30d0cff68f0773cf0456d0d6c49336efee434f6c3fd8fa6eeba027d9e7db5b5fc3be3fb6c525";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353733323839303232"_hex;
                sig_r = "2c6e9bc19dff48ab30442cbaba1eff6dcc58e804f61657142f2b875f57bb6111abdfafa7b33b366e";
                sig_s = "a3ea444ebb8bba9fcabb081ea5b38a90b46282d70678699b26bf9489d32951bcaa533e76eb7609a2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131373339353634333738"_hex;
                sig_r = "bdb9ad0594250628b6dad1f39d068a616b5e4ecb7f596f90b40dd4fbcffdc78ef09e91c176dece24";
                sig_s = "6f59a48bd38b19eeeff74824dcf64fa779fba066ddb653b88a23ef10fdc6fcf7746db29b4f458e05";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3733383230373935303035"_hex;
                sig_r = "31614f1861d72a8a4432409b5d8d3befc487a220e36800d2f964c58c5fc778c92e903c0fe7827dae";
                sig_s = "b4ef673f6976db18ee4c75b3dea0102f1af1ddefb8415a286504b8c19857151df75102d80c39baf9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353233333738383430"_hex;
                sig_r = "0e823a4f5fcd2c951f34a8e0aace9fb253b9a12f9e7b157c4214fd2be3907f61964c233c17bf24b9";
                sig_s = "5880f89553cdded44a40c5e609b1dd9272ff352cd69d66f632654fd0b8b682be60c5db75bebd159f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39303239363535323738"_hex;
                sig_r = "636fa3af3848045164fa010bff1231dd5892d22b9840e7316969e684d9c1c3feca0a43c1bd6728b3";
                sig_s = "a9228d626b202bb08fe467f122fe390190b438a88837eb7ef72702ba945ee15b52536007f84befbd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363030353238363330"_hex;
                sig_r = "483836a3b810de697ecc6e7ac0b014ef208b9f042f83763ec4c886670d22ec602bc9e857ed7d16bc";
                sig_s = "114f99d0c64bbded3e11642a4452d556c711b655524861b4e5df22403d8342a64750cfea58e1502e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333639343536343136"_hex;
                sig_r = "ad0453e59927b80cd5fe3442958892dcb35140b1498de85f59e41f79b39e77be5df7c16b892b6867";
                sig_s = "397dc4fbaee39262a67f80c0aa3b03f1f6d700237f4907adfd24b57b9644797e7c07a4b384e61b65";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303139393230373030"_hex;
                sig_r = "023791e6c75773e72a515c9ac640e617edea0e10fa1b2847694ab66d05f76c2fa482bdc39eb5724e";
                sig_s = "02fdf6813b26951a89f96ebdff19e026a93981ac9aaa8ad8ca6af742fd07a7750e2070e9e1182ddf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373032333133323830"_hex;
                sig_r = "678b6b227627ff27553bb2ad262c8c4413f83d7e6e5452f244859603418a10dc986cb8bc7e4821b2";
                sig_s = "2f517ce94b9596dcf4e1ba0076fe5976c95f843fa11f0522f2139137baa8607731c9e859a447ac43";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383038393439383431"_hex;
                sig_r = "63d9e445230d924fe7098088e536dd077e2c5581e6c00f13c256ef6cbbc3b613cb8030b98312affb";
                sig_s = "1b7608d2176d9d8af5b216c2f26929b0e16df39f3ea5bc404e1bca1660accc5a5992fefb05a2498c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373438323839333135"_hex;
                sig_r = "2da811e51328a2e7ede4c0ad7e631d84f8d4a851f7689cb4e4a4b6f689be54c960f591aa255748fe";
                sig_s = "5c9753acb54cd733348eab389304ee804d4a36f9a9407e7e70f5f139fb7c0437380ddef2a90663a3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363232313031303338"_hex;
                sig_r = "b9e4648ee237d55f732bc49d437dc64d227d751a23d38c902f11bf3b4a8c555dfa8e2fb6718703ca";
                sig_s = "3f361945fcf7232a6da85359ae09b5b60df35e3ce11126d0ab113ac1730e1b70fe96c2306cb11364";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132313833363339"_hex;
                sig_r = "a7fd5b24425eaa638e3f987aa31527e058eb4a7c7dc569d4e41f3404db1cb4680065b299fc694e41";
                sig_s = "9f39841891709711a72fc7201d006a13118dffe9de7a5132aa015ffc362a578124870e96f78fb45e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393535323437333036"_hex;
                sig_r = "3b672dfc8ff417da0f0cd972d2146145be021e25716d685cf6f64faa9fda420b0b9dca384ce5b17a";
                sig_s = "30fdf5f1f21cf6b64ceb32af8ac4753f0010d02d9de5d3d1ac2d2177bd80dd741c1640cd7046f5a7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531393636303731"_hex;
                sig_r = "a0028fa7b0c6c6e6a2103c67cb4d13c9f189f0dbb4c2d1231d708e1bcaa7921769aaeedafad51715";
                sig_s = "46d0dd8023d8a8f09a7585d5309860b4324323a296ce4d7f06b0a02f99128fd97c4be9a59d5ce70d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383830303734303635"_hex;
                sig_r = "a5ebb739b713021fc9505a2c40189deeb652bae9df3c5c128f7039bb87cf491fd30c2af186dfe446";
                sig_s = "722e8faf72304d8e9f4556b8b5c794064915b60a7e9f4461b3bc1a84e5db90ff257f1cdea994536a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136373937333631323130"_hex;
                sig_r = "ca1ff9a2ec2dc5ed447c8a9340744bcb99c90ed6681b6580600f4b89b26f1ac0dcfa516b09f89d64";
                sig_s = "3f28326e96ae8b13a3c7050551a28182493bacc9266f88205b70ef03a91f01a91a39cd3d771939f2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323235353833343239"_hex;
                sig_r = "660f0892ba13bdc08164b8e620b579f2f441a50e08644bd24b720f241a96175e447014ec5dd4d26d";
                sig_s = "22a56a4d6d0ca59558768a705c70d435890b940e838cf603c4f02964306080b45f3210c959a3effe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3236393238343433343334"_hex;
                sig_r = "4bffc5a27ba7a7e429cb3034ec3a5ce305877743bee295fc80e39af8e28f45a21c45bec295353b38";
                sig_s = "cfe62f1c089113c46ed5c38b09f684e48709927e6b9a51b6dc57d161e1277f098bffea9ecb4fac73";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323734383032323238"_hex;
                sig_r = "ceaf34dceea01a551d04cafcbfd6cf301d0f8009a37e9f6ae3066856b14bb2c20ece0c6a3ee66744";
                sig_s = "4dbb0ea7fd22c19fa73b64f6a538d52b5511693c22a9c08b55577ebbc38ac9aae815a20c93c2cc04";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313439323431363433"_hex;
                sig_r = "42ba359e3ed7b2aad71f3a60a31d3d27004f52bbf0fee1ac0d5d77447a109f4c9e1ec8ec4589720e";
                sig_s = "0a958cb86e5f87f623b8d353074042f2f2e5caff213f9f6d913f57e227e0666068564349c28bd68a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature generated without truncating the hash
                m = "313233343030"_hex;
                sig_r = "264aa6b015b2a3b783411c19dbce512a6f4f19841514e7727123219453e7675ff6608ba8c843a461";
                sig_s = "4d9f473fa9914ba12c6d582ed5300fd75521bb432866e28a23d8ddebab4a82e0a4e3bf8b919797dc";
                r = false; // result = invalid - flags: ['Untruncatedhash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3473b57c2dd3714890b885b973767e5ca16670a1cd10209732159c213b6b03eafc734fa5414eb4ed", "0082a27608d88fecb99d6b51ccca2bc337691f8d08b1e8cfc5244addffa08cf6c5ae59fc4b33cde10c" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "014064fb4c224a8b248a0d933f7642bd56aced9b12";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e23";
                sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "04d989de87d41e4122f7974d9120b0d25b731c42c525d46af973b91760c32bd649c9e5025fb47620", "00d1ec28ca053abeb202de57960c2b17458286756280e1268aca90bbd08ff3dd97fa6eb735691eaba5" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930f";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5930e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7019d437744f43e9b0d1bcd3c782cc3a69a22f8d13c183ca0b72f29862d09ce93fb9a90c8de3c79b", "5ad221bc30ac27a9b78df3dc0327f4ed2737469c5812f9eac5a48f17f631fbbcdede4e58477a6ad5" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "8c0736554dbc446063e8e15f297fd4b66fa8879945bbb5c22714a9645f4fa4ef9d710eafa6b226d8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bc2ea56205d5e358c90ecc2c6384157f2c895fefff81b8304abdaa112eda79fe49b9623979cb0003", "00be5f9cf7f8506e1ca368e948da61e2d76b839789d388e31be0e567adae5b63c2ec8659d9916f3a36" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "5407cdd593acb501fc2848351f9d2e6b5457d3de43c3130e3b74e6a9242b3cce1c24f094f118bcd6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0092fb2ffc2803bd3461d678e6709a9ca117faca0d9ae578b46a7f7b235210d3811dfee4b369372bd8", "67146fd16a7c6cdcaf4469877c427f2e3d138b4820f82e44a5c40efc1b4dfbb817dc2ea53041a0cf" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "23ffcd1db5eedcd71cc7432a59be0019af33fa173ddfc85ccb7d2b56be75a2ca04aa8c6d27bd3a33", "00a3649a9160cc08f43c928611e69e5e96bb0f58557eda7bff6fa3de95ea9beb08a297c589191ba75c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b9d7d5a21f4e7669a212258c985a848a95986a95c5783ed0985a6eab06d76d646510534b6dc82413", "17f152a54a4e1a70df5cfea245389aa9cf31ec51ccd2658552b29db8815bef1f48b789b5e3146289" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bf9f9c252df13a64ad30c47659c030e4472eff78399971380cb70d6771863880cb7ccfce1bb29b70", "06f411a18864e90045fa8f208a4cc8114ed0b892f3ab012af34bb6d5c4998ce68e565f8a3c3f1525" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "59e216e270c82aadc02854b0a3eac7fcc5a6ef893c934d3d873aaf20b6a278663a1d4052079707f8", "008b9752df581b1ac4b238eb8d1ca113952bdf7810be9e64bc2fb4c09c7c8c1e0fdcd20642c0ae675d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3d835e6fd17d80d8a3368256595a492625eafbd4d2a74bf77c102afd21b3a63ea557e60c0297af7a", "02e2f90a7512e723cfe36da5229c31988f167abd74b8e85530d803be004eb555888127a84203d244" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59313";
                sig_s = "03";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "71d3ca359409cc4aa2425f4de5f6d37f62ad91b95ccf7b84fef6f199400c3aefaca2b3cb6b97af1b", "0251dc5e673cdb61172303f5ee34ff54ae8257811e1c7c9dc7855d14a6d295ef00602408badb216a" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44d86998";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008d9c650d233064d5988eef185969f33123848425a888f96c10089c40cf85ab7458d95b3a4630c5cb", "22e81937f36e84c44c05745ec99d790ae7d99a1099f698f8a92b29989117e993ba62f9bfce787e8c" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "21494db879806d4f59e53d4963977a03f6ec51140c9f9a1dba8857ff3bbc76d2214947e60edc982b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00981947e782f19a1dccca005a51b7c80d74a1ee0e83d3951e33edc2fffd11045bc6d6d1e78844ab57", "478229682bd1b0ce55e8767dde57590da97d1bf8f9eaf7e6a038348b9be80797c7099fa8c537d5ca" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cc";
                bn_t sig_s = "43becc876a63564b458280199e382cbad8ef68d406665bbf307ffea45845a9ac69345a84a5a72b87";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00baca0292ebb424311a1bc3496bd3b030947b67d5798386bda48fd65e5b36c6d36246c4332590a521", "00d26e9fb941de245c14b909c96b0e721c7f2f6c0b34c9b83692e8e512932a60558e6012d4c1c61c56" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efc";
                bn_t sig_s = "3992353d916617b49303856488e39fbc26173b8bc426f8207de3d8f1b97f3d12c803b99d57768fa7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008fcbe543efe4d7aa1465c89e39b289d09fc899ead8f7af549fefa27ea2c51cfdbfbd5a0e89ccdc6c", "00c89f784bd461ea23c7d534f7f918293d405916507bc6e73ae866dbafa9fc045a31b250415eafae7a" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "84380881b243236967227191398a3a4909000425576c79465bdaaa0a03267b9e48f68fa0a68b29e3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3b4e1af7da9c4eabaf884bc20dcd6e8dc87df89e4c6d6a1848e3f8d7be853870e13638761ab55f7d", "712d8bbcad25a3ccd8fb007b9b37b345aa3e465a8015e83700ae1adfa471feb2b1a9f36282b9be62" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "84380881b243236967227191398a3a4909000425576c79465bdaaa0a03267b9e48f68fa0a68b29e3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "28a10973947ab71ee74628e1e29ca288940f98816742ce9ee8d97e1843b9a9f22803b572897ef1e6", "5502bb036cbcbc6a93acc92febfcf903a64963e4ff0bc025e9f6fc1a7268cc86c50be3de0f323b98" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59294";
                bn_t sig_s = "8ce984c0247d8a7a9628503f36abeaeea65fdfc3cf0a0c6cc8dac9da9f043b4659b638e7832e620b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "12481628451051caa5c143efcb5eafcb66ce7e43e3b4d0528be2dd6b5a0f0d3810af2f18362ca310", "1f092ef06707ce75fb4424fa8abf7c774a8426a2f0dacc6a34364f19afe709dde60bd805da3a37d6" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c35950";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29282bc0b3285ac987f9109308d7e16670dd344258696dba4e445e47050a1dda9203ed4ea6fda654", "0bad0af52528264dc4d448260308b87534f4ac446ff8a51c0e3b143e8a328367a6cc4a911f8a2587" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "60ee958cc008387d4ed824d39ff72ff0f4263f196daebd42e586905eca0ca7fa897e5cdeff6a7382", "53e2a576c0740475e56c3893e397d84cf3c3c0463ccafa3c62b190a3e6b23401bb44192195c8b882" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "06f7388b968952dca535bd7e7d064722df2f4b0e8f613dbdd5eec3f17cfc4afb0bdaddd486233034", "2417a356fdb027ae6796bd5134a131af5dcf706fd8592ca89f7e4ce8465880364f37e3a7036a5b05" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0bdf";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c7208c48441de500050d174d47906460e4717e6d6ecb2fe3045be1f78eba9204b2fb27440249b246", "353ffff4482bdf0a89d29d7821288051fc1989353b50897cd5ab488f7b03318b68a196b7a63977e8" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a18cf3dbd9549015b0381632cef8ec2953bba8a471d759303749c76716947cfb4372fad1462f21d4", "6967f478cd224b8c4d523b9f2e151866943cdae89fc50d4bfdac8432400727f0f9888c40902f61ae" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "336758275671b26064a2ee5ed995236c650c22045c98e6c1a63b03d2d353cd8d474006977dd0ff40";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "22fb1674b631c22263b24a5361da94e9ae2f2efc83aab5ac320635bce4a03242481ff0ceec26ad4e", "008b44a399c0b801cc9c0ceb8e02c940ad5ec423967c4ed78df8cda0160c6d6809b2f4c7d45f7b0bcc" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "52ca79c89313d4f18ad1515df6b2f32c0e95774739ad64391155257026ac1a48d008404e8068b4f9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ae22530c046c4abd73a038434361949d617547ed280491f4d675d6cd37e61cc7a6669aed7183eecf", "00c82e560bd177236a15f83062dd8bf1f26b7c883e405c48bace4f9ac3e98d3a84a00b3e75d1782ad8" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "59bcfbcf6f28b79195bf98394b7ec6b4698ba4fdc6cb72389fabdb07fe29de4ebcc4906bcbbce67b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "041dc297218a44334057cb19ecf2019d8d458cea4dead8d2718c643ee0dd6947940c90e99fba1b24", "361605d89822855f5d2d727f679135b22ef94d7e1c6f86a3a77715c7403bbe116a95c8c459a4d603" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "3e58def7758c644788a67c4ef9ee602236fa4d7466066fb6c1d83ad3e90d355489a6eb93baa0bc61";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "443a5dde335086ad42d23eb687bfed15e3b44214b1b481aa4dcc0891a2987038a8f71f20fbe3dcc2", "01e06a4dc05af56fd58120ba831e5f7c853b68186804e5922c63e5dbfafdff405d0d455ccb93f8a2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "68ae43de1cec917435cd3b4575c37b3b73b2aa300d9dfab2458b523ebea2d21667a9facc1559a723";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "62ed3b72b0c6b662571dbfa84d851486738a0e78926cf0510e9e2f6485dd2f094dfd9fefc5f8bd21", "7764bcc281726d3dedf04f3f40029fd6f6b3405a706a2613006c553b7d3abdc4de3b08f1fbc2d1a9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "441ac1ef4c8c84c4c7d07c9b08b16822b5bfa5b5bc61f2874c15f9021944a0f6e34ed17f67c27cad";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f734f03b8a7614b210834380e137269f49baecb50f0f47447945cc70e05f382031a3d17865101c1", "00a6519c1c48e75fce16d9437b8ef7b9b444bd40b5203c475af2ac03d39cdc0d5e8067a5d1553daa90" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "3f8d645a4bb4a71f78e85d0613cea2efcc80562b215117f8336c4a52b194275ed10fa194e68da54b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0096bcf5a53f983f7964591a0675d8a71cb1aa7c5ecd961a583c01437d22ab11a2a015b7b37d37e5b2", "3d1c1b2373c94965eee446aeb3024a9d61b7e1561ddfc6089945a1f303cf46de8ab731284a456d90" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "61e07b834a8be8ebf55cef4a7a9c14845eaea0ffe66fb98efb4472fa544c336ece34c991b4ab70b6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b9f0eb70ca441aa7e62ec72cf72b0767968a54b5a58aede225dfd02df84e03c6ebc7714952b0fc5d", "462d5c3e85d8bd4fb417561bf26d618d0babdf444d2f48b80e65d4e1d060e53fa928bf7945548c0c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "698ea749c25d9a934d50e1bb20d8246243cc650d16bdc4cb165553a01fdab3dc3bacbf053fe5697d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2640fbd0c09c0279402b94d87e4cc166de905b75e457ea76d0a17a31841e6a583e3ae5e567cbd797", "00a63a61d12f287d1c57cd13f83a19d276379f9af240e52bf02824fc15ad51859632de17a90a63090a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "586cebd6cc793cc71e949245c5d7044e47b786f3a0779271d3028cd5c9d0eee17c55ca55a82e4801";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "02a61b260d48e45a851c0d65ae2190f412c3d0ce25ff1d18a52ab049f92862a2234191215417a348", "0088ba6c540bc51f253f0b4acd65e5476720d321a76fbd23d7bf5feeef9ac699d5986a85cc091642ed" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "02ee7092471bcbd0194245d7662a7c8ee77414f0316e4401a17e25ffe1c8421e73c0debb46806de2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "254d59675918fd3629870d621b445524866759ca61f2c82a4756de42c0cb86ff164ea06dce3e311c", "35c979bc1a27dcb584e5cf1981e1681dca7e7315f19dae33d6d0a0563e1a57e2a8f5f358e7428f27" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "443c61e33c82a08bce3bb29d30e976cc97d5d7134f1be7402f841def418e78362133f07224919d88";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "02934d4873a0ae6c8de89f441cecb5b0e9c5caee0fb9ee25d3a187e4733b107ebdbe96daa620d8eb", "2164f87eb9fa6c52d44dc6029527255c5b3abde269b3f3c0ebe9a0088d35b314c95679686dfe7c4d" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "47ae4a0ce41f8da4b35f63b1bd55a01e239571a23981cff63c5f845b314bf81208e374cb3fcd64ed";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00be580a9490b3ee9bbead5f12dbfd4fb80afd5b58245fcdffa77e25b5f37605812a7aaebcc871e11c", "30e301cd48b41e3bb7e19a3b21cd4e22a7ebba07b937e359938daa0bf65e458b8f2329452c3f8e41" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "1de9e7aa69ae45a73f6b3a05cc19b7771277b81e16ad5c508539fe05a86cf112d1b764510b4357e6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1800dcd69c7bbfcfed510f9a3dc15ce0ac0df50f2ba1217b63b51e5b43d40bba6d661d9ee00f56d5", "00890f1b7b89b814d7f42e473e4d84311cfcd87c4c82d684faaf5f30dbd4c1319701a092b293ec3cea" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "1f0eb2e2f039733cbab46abd9fbbe0c2bf8a73b76a12ff21d9c845dd707bf1b9e3d2d629ad4cb8c1";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "400d9364b5efe3c2eddccfdca24f73ebfefdcc8fe6a74adae942a4b3e8fb79d79829cca9de1e6bec", "1a51775d5174fbac7424e52300798252c7051357b82cc0193fdfc9f171830dae7d3152c1e5363926" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7c44139ecc37288e5ae9e0e4d3db1a3667a9c471734ea35b0cd079f4bdd285c8779127dfcc7e4cfc", "00947cd9c8baa6b9838a7dbb5ffa1ff999c7106351b4632a81eb4e68f29deb52be8e0f51452dcf0f0a" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0264f2e74b929c6b81ad7b7743b24feb05220bde604c289e15d5bdd21b15b3b5c9b77b43a079f6a", "384333fdcdc0ece729e37af1befa45168e010965899d0bf625a2dc866d1ec985c3738ea44cbd85e0" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c988";
                bn_t sig_s = "69af23901b5e27dbf09e3c2f6900f032fcc7e7d2db47895196a41763f7432c74c348aaada262c989";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0088d7aad940b94c2170a002d7e909dde1157e2d0af942572702f2b0dbdbb9f928e50fac3a5d9ac0a2", "00bd33cfa670bb12994c56157f6b238e741514eb8aacbaeb1023b4abb7e5a7acac4b7b6b5963202035" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b74a6be5900bbf62ce66850b7ca898774970d368acb87565a14078364f93746b7ec5da3d979cc559", "00b9499473230e3e333ea7536bb2583bfad8f426b8ef1ea968c63c80685b44836a5b96ac3f6f55e660" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "ae4a5dbcaf940fc15449b517cbccfde29e70de386a15ee4ac30454e4c1b273d4b8787b0b6567b1a4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "332c3ed3e34de227761144aac7625775a90fa1b47fed57e04236b9bd402806c640041e3de8bc7f1d", "7f96e31f99355c6775c13bfe00dda8de949f998b9b68d34ca51ce7b351f66804e93fdeffb63a5a22" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1bb77718efe5a68f77ba50854ce1e779d95f739368bcf1a7793705a129d6ca334979bb932980da4e", "00aad388cfe4b2e3ab7edf790d052a93991f30fd13287c11c1cf936c158d63fdc000c54a0ddbed9e29" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "8ce984c0247d8a7a9628503f36abeaeea65fdfc3cf0a0c6cc8dac9da9f043b4659b638e7832e620c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009a9faf8d4aabbd7b231b7891d0dc361fefd214dc0569367c8c155212705300ea5d820112a3386c6b", "7eeb846392288d06b570185734c0cfa56df71a888f9a8fbb41af3b278e287433dafefb2136e7091b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "0c5bf8768262bffcd9a64117acbc4b811e5fa5cf197db6c8236bf34bb99bf706ef5d9e1a9fc9f5cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ad831f444fdce2ad84db6fdaa4769e405c6f8c11b541378d51aa9f59b600ee3dca673310e224f473", "5f68561380a66953bac16b71f2dbf40ddda850609465ff303bd0eb7afb031a5636726a759ec17d52" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "703ed1db7cbe8938377b5683b745ee348c3422533ed1ef1eaba30037403751b3744b9ddd2f981e8d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00913e2ad9490d96b3abf2dac8b68c177dff16304b83e3de65b28d99c43af75fa13676377faa816d78", "0097613c3ad7a71da296a20dfd99848440f93c31837013bb9c15adb8fe80b5f75c3321ab21c4e7dbc8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "a188a03f44459e91cf77371a377bb28af208da01db60034d52f158231904d9412f1d36d1ade9ce3e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "54aed183ca575dcac58572d2e5bfc5868988c2254932f0db9ec1c278c6b9bdafe69a5628be619542", "7b6810b87c308e5c2b48ec76d258d3dd2d43019d48435cff0513ac5c6fb9b38b45e5133c704858ef" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "783b488dbfe35fa347638901c737cdd8bd04abfca4320f5e3e0b47a1f6dd89446cb5a2187005dfb0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "63e52576b88d9296e7533541efaf2244103cbe11f72fa2819ade7b8ba8492e291c5aa57949f679bf", "35eccdbdf826fc6ff3126eb18d86f255bb71cc56cc889e7cd6b2bba1bf8fe4c2b796c85a7d3dfad0" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "bfd3c7ec3ec8f496196d05cee9cb0c14dd67afa945555559bec88684d455624219effbabb4840a57";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5f2668100d2843ce961d687062a20491f193313b8be563697881b746e3565ef067ed94dcb4441149", "72d77b6a35b269bcacd717f1bbd289a43c4093db841bfa926a3812e635275f6422005665634d8c48" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "ac4948b846d59974519d933f019437c3c13f8facd41b98105048de41ba246b9aad4ea1fc2442819d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30c1fa8c28f242144ebcb5a86a53ab0dd5bee5043d919d24ba65b9ce0bac7e747c5fe86042302a3a", "342ef78a3cca855163db4836ef7371359eb8aee7ad1ac6f18621926134d9d15220be93445688bacd" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "187c226158dae4df569ad6bd6b8974e5ff02eeefcb9da127aaa9303f259c1c6ced466e20a90b7c7d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8d756150d86d8490d633e80b06ba06e3978ca98edc8931d3fd5fe4ccc25b1d59683eb0c04ad9a1c", "00a739481edadbad6a85448f4b37d90d4810f4ebd0d1349a67b6960d21994bfb7d594211a28e7a7e60" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "01daa9d927feda0a3a1692445697f7ceaa895ef5b4df8d6dbb4421957f5652ef32fbd5bc093fbdce";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00989d5b7b14c27c72f4c8bd8fa7a9fa1e16a1e2d790adb009ed65b3b2bd93c2139bfb78a1193720b6", "6787bc24b4b22ba7946caccb17f1f190d4baac79380eabcd1a7cf5389b424f24b4a11b807f2ac47f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "6872bdeaa7ede175dada68e03e214f0c79be573e2587c3d72cb2e575fe4d2d5a7825b477c59b6427";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0092769a986f96d19b08cef2052de18d80831b1c79fbe9832c1099fe168fa999952f3c7b16bf93dc05", "00a2450334fd62051d1b149c5e16e0472358d51af449f663cc7be7e1e487c53c26afe1812252b08e59" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "a36d397fea7ecc5a4b7999c56db48dd906b7ed55d31e9e5552d8709f25ecb57f242745c201823ee1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0c45be8925ade79c653e8748c2dea9b6f379c2c92f7c1070678d81c7cbc3ce1ab7b166297a40578e", "00b7f7097191a38493be0cd10bd750b0ff34ba2e91051e52a58007b11da33a17b8d32931f9b1a649cb" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "63812754da2cc7dd83cb1ba392a2ca726d9814eb4e88aded84ee1dbe1a7530f14b99dba0527dcea1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00899b7ab40ab1d0cfb2c13cb5ed523339e818b1a9caaaa421748197533cdc76ed8f249e9fb73eec18", "0098bdb312b40b6df9bd8d684276498859190f1c8ec9a0981d25d1c6df1e9c30e44f847363d210dab4" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "c7024ea9b4598fbb07963747254594e4db3029d69d115bdb09dc3b7c34ea61e29733b740a4fb9d42";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d7b0fb562a6997bdc76bd4fbd248fd42634bb37cd6817bea472a278a94fd2d077bb2a38c23bb594", "47478aff38b28dced95bfeaac7054170a3fd691cc6571a6ea56f0ab336c8061742b7b20bf9a4975b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "57252ede57ca07e0aa24da8be5e67ef14f386f1c350af72561822a7260d939ea5c3c3d85b2b3d8d2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00ca806a035517b677e221a91fdce5ecc8405a299ee3dcc9392c6c9f21b52e50fa6cde36fe5d8979de", "695122aa069159683d1b3822814fa1ed964a20d4380b484f29af91771862d68a7d80e2be96ed0650" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "50c4501fa222cf48e7bb9b8d1bbdd94579046d00edb001a6a978ac118c826ca0978e9b68d6f4e71f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a204cbe49f7aec5bfd78f0940c84f7199813051cdee0740712b2bb4ac3c307f424417817ccd5aa7", "7c262daef83997044d9f8de5194a570167d4b19e068e963412f546512cff5c4559592a763bd23061" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "711f6d0abce96fe7f5bed2ca4600a021fdda9a8c922fb0e10f180f97fa2cc84dd785c71e6c41dbaf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56c56160e80f003224fc3af0e6eb5ebaa76571a86d82924cb4e6268cc1088503c79ab123b767beb5", "008ea1864e81c98875aa72d64cd7dd1b989e131f5e0522982f6e7f73cf702e6e15d35587026dcfecac" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "02a6eb408443d24e96be4ca0278442a8a426087f9beb03ffe5526162bf1dc30434cf7ea79574b19b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3b26481a3a38226619cd43d0c3400ec98af68f1cdc53bdddbe31703621b5c5b341902b0e4e691a17", "388f2e30a0eb720e44fb95ef341c9184f852eca6dd1761d4025fc48fb7d25109011846f62cee682e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "b6ba1aecd240debe77213a4228b125603671c9d5147b6c0b36dd23e42b7cb5078a1b8fdf1b98b93a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00d06666a6d693c9a5a963c303852689705fde5b221fd93192b53e43c1808c20f12d9a6da344f74808", "038f8a5fc61ebb0da89f5795bf062457e0f504f5d512c19ebc7ae0ffbfb080facdcd091556811948" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "957b383ba1cebf5ca579ef6ed10027988f8424f42ffbea2e51b3340df9f8c3c60b558d6dc2df10f3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c769eed15fe7c5d8ba82958d34bd4f2594230a1dc331faba491a5f933aebdb4bda2073c06710f9e4", "164efea0ebe407450b25f0362de80407f6cd373deb373012d22c35d02766d0fc3604df2b351f75a7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "98ff1db1b9affa33a2e53c684d3f07611772405e8c200f2af2afa9e53c6e8ef30cc143b3f5ff7fb0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c5d2f44a5dc61c0ae41adddbe258349008a5f37879e59058d26e1000c4b03c066788532318b78233", "00c78dd8481332d6868ddcabc0a278b6e2f22e0ae1786a4af08d50cbd1e3b521bda933eea6fc6e84a4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5e9ff4433ca3a4af648e0071c87c2e5c3554b11761b10bb2b81725028a56c4fc92f1320ca7396c4f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0096b69df13be64fcbef7ca8a8ed38ded52ecc98b74ce723ffeed5f830c8904c3640532623763b48f3", "00b7f351fe8aeba0489cd52e3cc0280c22f30aeaab0ebc57710522f5ac8d48c69d369a14ed06369201" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "c76ce53560163f157b11e4d05c61540a5df6b8241cbd3ba7d911a7541eec55e986ebf811ae50a8b9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "15eb2caeca2200c2e57bbe0e57a2c836596a9742422ee3dc71fc8b296f8b0e721e73615f49cf5001", "4d93a7626ab6e148e9c10a85e60ead47e092bd713845ae4324d3200720fbc22d9ac1770670e90a29" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "4218a45116ea65b283cc7d90a510f077b1b09eddbcfca3e7d2896b869dd3ba556c4f10590b0e08cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2bd1ec0a492c0e4aaa8c17b1e70e37e79c8f68314dd1541a44d316a58f42205f4e8d057f0450ec98", "492c358a93adf5aa93c186dd690ddd60132f38aa4dcbc714c4a7a8550ffb02667d85fb78bcb3c838" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5e5f32423bad3644be718d8195341362c9cba52b330f913b1521af6e5e3eb2069421b05dcac299f7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "39a33006d490275f09bd36cb7acc5021e63871d47fd8966d9e4d513adf6db56ffb67ef34d6add366", "00c24bccc7d66fa8c7ffa532474666387ebd354d8920fa98bf5a39ceadc5e655ec4ee5c2fcbe05d1f8" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "ac07aaade5c5fb2fe5a18bbefd262e0e439fd68e0a317db06ff4ba623a2a03114ec5b6e084171058";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a1f8a2eaaa09febd3c4689e541173ed8a0fdd59ae4288df96e790224b3795098451ec55db40b54d4", "2f84af7511e8b9123f61829bdfd90a9f577f8c78520e4d85dbb4c900d131b3d72a0cfa0d9cada0a6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "311f6d0abce96fe7f5bed2ca4600a021fdda9a8c922fb0e10f180f97fa2cc84dd785c71e6c41dbb1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009998152be343ded303960ff65045dd9b8ff54ae9d4366a94d3543141d12347d731c88dcfe1b107ab", "7667f2b7ba92148552473892dc770636de6dd27a39c05a98fd3b71bbc29aa983c120ab3b7296cb92" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "623eda1579d2dfcfeb7da5948c014043fbb53519245f61c21e301f2ff459909baf0b8e3cd883b762";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00c3dfc19f1df3523fb884d7716246f1c25f7b031209cd15e6746e2ea797aa0cd5afd7e5d0f7b31f86", "730c46e4db23a10e9a269388bace71ab84ec3ffaa28ef9b0a2d4bc77770c7c7f4b975d1ebc1f3752" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "935e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59313";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70ef60b28eb0a5f1fa990a842f4732c8874f76b6d3eac5dd3320784d52c93809b74a166f9bb9b84b", "2e277755a4e266119505b1ff35fe37487b47fca5ac8223811fe260d7c95d7ad6ec28b6ccc4f1e5a6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5b5d0d7669206f5f3b909d21145892b01b38e4ea8a3db6059b6e91f215be5a83c50dc7ef8dcc5c9d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0098bac10c8bbff34b38f1df0cd51d7eada1ff2d26c405b30e3a7110f802eb47126ac48303280b3ce1", "0e8ded10664774f20b72b364d1a27d359b4086df9fd327128c4b17cceca45036e8491236a1aba277" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "9563bd68545ccd185ae724d8efcd4cc23234934eef10f280792b2f930c97a6c1e00829a8b975b9ee";
                bn_t sig_s = "360fe79f7d37f49c103553733438a2334f690bebe9643b8d1e32a4bd7daa2aa764306ef240a40ea0";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0098bac10c8bbff34b38f1df0cd51d7eada1ff2d26c405b30e3a7110f802eb47126ac48303280b3ce1", "00c4d05a0fd074dac5d5c9c4fa005f63305e4f48c75720e6dcc347a21f8bef9bf2148b007b50078bb0" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "9563bd68545ccd185ae724d8efcd4cc23234934eef10f280792b2f930c97a6c1e00829a8b975b9ee";
                bn_t sig_s = "360fe79f7d37f49c103553733438a2334f690bebe9643b8d1e32a4bd7daa2aa764306ef240a40ea0";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00bb8cfdc1f2361bcdc96729951668dee7e495a9f756cac1a387574b0af1d369bafeec4b47c42c2475", "062a170b2654e92c21799ca0fc8b24d7143a45695ef42ca1b0b5291d1719e3e36d5749d4cb7506a5" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00b2a76d25e1dbf660a6cad955bea08417be5796a8cce6387a85a3aa3c9d029e43c63521b0f139d8ae", "58ac60e914ba44fa030234e786e182cd433c073f605b59aeefbdc54e72a61ca3aec91edba900a0e5" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e0bbc0ac4c5ed2b0b6fa291e1170d8da5cdd275253daa0a18e12eb432445d3db917b22102bacd8d", "7ec333565bbb2797b920612bbecfb566724763c204c6bbb1a6f65a09f0ffb19a2c040e9d4b1818bf" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a11b3f9d0070b554d009b08391d915aaf41e1c9375049119bab40721938f605d400b8cf7a9aca57b", "6b7b137f08f28cd5cf6ba0cadce3c3077f10dcad55e7694ad4c62000806f911137b4bb795ea14127" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e9f7515ba68f12580afc3f39e7cebb9cc10284ddb256780c863d18939c7b0c39a50183eaefd28df", "3a9cfda5eb4f0ba24095e7b86fe2f359ce4b5ab95f834360acd8ac5c8baf935faaf8e9f945bbe54a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "a91838e692303fc64dc9f9e574ce4d1e613fd9515ed8dbb5bdd3589ff20513ee05411115d09e0f41";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "355cdfa9507a6540db1820c2e0f96eeedaaf95829e5b6f9914d9a00f1396d9b0422973634f4afd60", "2a0476aaa8724129241d086ec0bd5b0d811fc07be632989611769983245adc15d81f9c331e5cda9f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "b52c3cf70a58445477eab051464ac05768321fb29c7aa242b9194cab5ebc4c35e10edb72cd3ba2a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2e3bca2cd9b527a42cc2dc98d71480118336a99f6292b08132ab6b786e4e9069b695d21b05b72629", "7fe24daab6d40fce101ec559f3778e50c9968692e64bdaebc2409bb3665b9591cd0f702ebd388bd4" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "2fb412f03e6debdfbfa3a3092f21c4619e04279be0931694ab99c6503e5a894def8377ed059a6de8";
                bn_t sig_s = "53bf06e43fcc4236b2ec0d88471379053f1f3437207c5a75b09036b1c40fa8f3128277894a4c96cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "06c77c49220712d4e5d25b6dc29c8808f77c77aa64cbed09c62646cd85b2f719cd563c371b5a6f3e", "00a61472da2cce3dc200a88da45e1b75adb7f794595fe632709679544daef719efb8ba3744c59bc513" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "4674c260123ec53d4b14281f9b55f577532fefe1e7850636646d64ed4f821da32cdb1c73c1973105";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081d7a07368b3f6a8027bc428208c847931786913ba8bc9317592e84789b9457aa01e01bc8252a44d", "332fad05f9e1d2448a0916f3c5e2d1a357d7abfedb227726a855f5027be8032da95454632fa89567" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008ec14f657dee3bc9e34eaf274e02d619602563530f60a4b6ee79a1cf7c8119e09b33efb35a3d1c4a", "3f4f464d05634cbba22fd067387b34c88fef98dd63ca5e1bc6b29cc27afdf0335dbcc190733163b2" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "2a460e39a48c0ff193727e795d339347984ff65457b636ed6f74d627fc8144fb81504445742783d0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1c1f096bc926e45775a30475032ee246883d1e57f9fa4d7afd521ad102952b42919679748703c850", "009e448e9c8613278a98bf0d53b6b9eef8c79d6f3fb0bb0771163a3b19504cdd8a69d80e4aaf3b3acf" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "a91838e692303fc64dc9f9e574ce4d1e613fd9515ed8dbb5bdd3589ff20513ee05411115d09e0f41";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0705d356eac8acfbcfbb361809868fb95569e2921142d9596ec385e92cbc02d595d4958dce284e95", "5608889e26ec9d70b5fd1f388c80aea7fb777ff46596fc9d18c64f6b026c8c8cda6e49c261a5e5e5" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "b52c3cf70a58445477eab051464ac05768321fb29c7aa242b9194cab5ebc4c35e10edb72cd3ba2a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5a3f50bb9624aa2de0d1c4eee53702a1882da39b4c26874c3aa49109971c5cb1cbe7d2fcf9dd1441", "10f5ca2a6799bab7d719553ccd25a9eaded90658a94f73b0bccfd50aee9acd1d85a3cfe9761a2153" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611";
                bn_t sig_s = "53bf06e43fcc4236b2ec0d88471379053f1f3437207c5a75b09036b1c40fa8f3128277894a4c96cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611", "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ae4a5dbcaf940fc15449b517cbccfde29e70de386a15ee4ac30454e4c1b273d4b8787b0b6567b1a4";
                sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611", "00be6076caf0d032ef35fbe53a528ab907f24bcfb9e5828b04a5cb4174cde781612981cce088849f46" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e";
                bn_t sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "ae4a5dbcaf940fc15449b517cbccfde29e70de386a15ee4ac30454e4c1b273d4b8787b0b6567b1a4";
                sig_s = "1e320a292c640b636951c80d8bb7200e915daff31a147060742ee21c8fca0cb3a58279e87789f070";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP320r1_sha3_384_test
    }
    EOSIO_TEST_END // ecdsa_brainpoolP320r1_test
}
