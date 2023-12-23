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
    EOSIO_TEST_BEGIN(ecdsa_brainpoolP256r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<256>;
        constexpr auto& curve = brainpoolP256r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( brainpoolP256r1.p  , "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377" )
        REQUIRE_EQUAL( brainpoolP256r1.a  , "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9" )
        REQUIRE_EQUAL( brainpoolP256r1.b  , "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6" )
        REQUIRE_EQUAL( brainpoolP256r1.g.x, "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262" )
        REQUIRE_EQUAL( brainpoolP256r1.g.y, "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997" )
        REQUIRE_EQUAL( brainpoolP256r1.n  , "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7" )
        REQUIRE_EQUAL( brainpoolP256r1.h  , 1 )
        REQUIRE_EQUAL( brainpoolP256r1.verify(), true )

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP256r1_sha3_256_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP256r1_sha3_256_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of ASN encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   BerEncodedSignature - {'bugType': 'BER_ENCODING', 'description': 'ECDSA signatures are usually DER encoded. This signature contains valid values for r and s, but it uses alternative BER encoding.', 'effect': 'Accepting alternative BER encodings may be benign in some cases, or be an issue if protocol requires signature malleability.', 'cves': ['CVE-2020-14966', 'CVE-2020-13822', 'CVE-2019-14859', 'CVE-2016-1000342']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   GroupIsomorphism - {'bugType': 'EDGE_CASE', 'description': 'Some EC groups have isomorphic groups that allow an efficient implementation. This is a test vector that contains values that are edge cases on an isomorphic group.'}
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
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            using bn_t = ec_fixed_bigint<256>;
            const auto& curve = brainpoolP256r1;
            auto pubkey = curve.make_point( "2676bd1e3fd83f3328d1af941442c036760f09587729419053083eb61d1ed22c", "2cf769688a5ffd67da1899d243e66bcabe21f9e78335263bf5308b8e41a71b39" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "8cb8886a70de6ff2080cd46dca0d7fd99586d561199dc22b49eef2725b3e2c60";
                bn_t sig_s = "137f519df89193db550373a9a5e70ec0a5db85933e3bddae77cb58bb87fe68";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "35fe352bf714f35c1ecec780565ded86a8e61fbe4a1fbd798c23e94ea8e8b91d";
                sig_s = "4f01535a365c95e62f8a099d113957f0d12cd12fb587e6a657f94a877a0e8f2d";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "8439f87848d99d467fb465be0732f894f302d6f95a020b554101f8dc817e125b";
                sig_s = "0dd36a690a1b814084052a018a4ddf720b1e9acaa233d96a6a6f51a5c5b83705";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "0c18936d0779760d671e5a674396c3dfe5ced2b26662baa146923c74a4066caf";
                sig_s = "5e5c3ab4ba34d39c0b1639a5fbe6c94be94434da1bf07b8176e88d8858d89233";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "019a2d9637743a63ddaefdbca0ee229a163b809b9b145e5313bbeb8defeab9d6", "548caf89bf5ba49499404145651234336401b9b2843a579ed152e090f11b9e59" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                bn_t sig_s = "a97e2bed0c91e92e4b78be61e94a6773183ed36fc945354de1ea9f2822566a9b";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe030000";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe030500";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "3bbcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe83";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c0000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c0500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7f2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec8c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "ff7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "39bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "e3b845f1fff848dca1a19d8e96e30b294d53c48cd26e237d59089d3c034954aa";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "8fc1963abc1af56424d5886d5bdbf04634e0cf4567aad58e38cc8036d4b8a75c";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "aa3514c9b84cb35b5ec946239b7cecef43fa94ed9e7eb37415e6f91150b457a503";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "c64311e9a1f660df9cc46d0206a082483ee5b616e2f3837a3715714693ff01fd";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "703e69c543e50a9bdb2a7792a4240fb9cb1f30ba98552a71c7337fc92b4758a4";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "ff1c47ba0e0007b7235e5e6271691cf4d6b2ac3b732d91dc82a6f762c3fcb6ab56";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**256
                m = "313233343030"_hex;
                sig_r = "0139bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**320
                m = "313233343030"_hex;
                sig_r = "01000000000000000039bcee165e099f20633b92fdf95f7db7c11a49e91d0c7c85c8ea8eb96c00fe03";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "aa7883ca374b6a4a315356bf51bcb370003421d7a17e18a13e517ddd0c3a42b3";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "ff5681d412f36e16d1b487419e16b5988ce7c12c9036bacab21e1560d7dda99565";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "a9fbd5079084067ccc58f7dccc37c6978aad754ae94dc36939cc41f1f1bd48930c";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "82d4116aa33f720d12b3d14bc6da018c0558cc13e38e5651cc90a58b0e13f4";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "ff55877c35c8b495b5ceaca940ae434c8fffcbde285e81e75ec1ae8222f3c5bd4d";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**256
                m = "313233343030"_hex;
                sig_r = "01007d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**256
                m = "313233343030"_hex;
                sig_r = "ff007d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**320
                m = "313233343030"_hex;
                sig_r = "010000000000000000007d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                sig_s = "7d2bee955cc08df2ed4c2eb43925fe73faa733ec1c71a9ae336f5a74f1ec0c";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3237393033"_hex;
                sig_r = "0c939a92486c6d0d619510b4a94162b9221be2eb15faf878bff75e6cdf4e3707";
                sig_s = "222866d875d1b31e23f70e3e8292e5eeef5b7f9442837a3ab8c6e7b0c950911c";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313930393433323838"_hex;
                sig_r = "998d34761948f0cbfd45e36feb0e2408375ec9f89be3b4d224d50e281be9516f";
                sig_s = "441683b18b537c9a7e8a14f104716a04e6ffdf5fd222de9b062dd294c625d06f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383433343734313535"_hex;
                sig_r = "33364d51306c4f2bac4d4a4f6ee628ea5a9ea7ee4509e356d7a4f8abe2b34b84";
                sig_s = "319d54e83607370d9d375c4726099c10b4f8417dd1f8c1bb1c4f67e0d6b93d4c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353732363936383239"_hex;
                sig_r = "9355f6c4f55b9a5db82a6935292dcf03f1a6a4d0cd3f930e0d8c8e2c4e441280";
                sig_s = "54b19315a954be2ac97a68b5762979c931a35e66b646073bfa77d2cdff253a88";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353931383333343239"_hex;
                sig_r = "51e642a8692cf36e1aa3ec8bb766b54727105233539b1eaee15383b00ca18cff";
                sig_s = "67b1b6514253179a82003aee5696a78d93ec8326f9de13245c4011714f017e06";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3832353330383232353839"_hex;
                sig_r = "938fd46c5289179c69954c61505bbc3d6c6df7997ae72218495ca2098b75cde5";
                sig_s = "5bacd87347d752af443e1d748c978894b38aaa35f2c1462abd71dd7eada5460f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133373334383238313432"_hex;
                sig_r = "54b0cd8c19a299662a44729c498d59f07e9dc2c4ff66fa694fb75855c0403165";
                sig_s = "11ca7520f65ca47f7dbfe647b26aea2dcb797257f9955c28ad989394d2b27ba8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313733383135363430"_hex;
                sig_r = "88112a8284a1d7520824aa6c092e3f5e1462d79c53b75d7bbd31c307decde865";
                sig_s = "4e81338689b868fde75c395b064777596484189120aea758ffb5596ff3e49c31";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353533343636353034"_hex;
                sig_r = "8fa2d9c34260e60ab42e58fe6f436e660119d56a0d69a54f9b31f1ab7a7d733f";
                sig_s = "730af8362394b6628a34717327bc0e3ad95bccf5c5886c851ce0881d9d574a0e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313833303339313937"_hex;
                sig_r = "673f4c6ea7bebbd6fff00a5ee3c36c1ee582c1afcc044a7f709efd8e801ac9ce";
                sig_s = "71e6559d7c6e375b13dc1f1124d562a1a483d2a1423a8a83e5c6b02713d63812";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130353236313736353435"_hex;
                sig_r = "9f29cfc476b94fd879457c392e3d8be6226a53072a7517b1da1295dac19cb89f";
                sig_s = "2de81f06ef9fd0feeed4dbbcdeba3cc4140f873935ea210418cbabae97ecb478";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353031353339393836"_hex;
                sig_r = "28c4da9a3de47f0a4fdea62266c0319c2a4316627f98fe4f0acf53895d2bc442";
                sig_s = "63e0407f262dd5072514fca9d2f686fe8670b39af2d9294c7284851e66af1b86";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134393533313634363139"_hex;
                sig_r = "3bec5d12a3ac4e8a887ea481958102779a6ab8bd8ced06ceeb4d0ad815529846";
                sig_s = "730a695c12b5eb574012b71ccdf86a7da0f3ca81e1e87c36dff23ab65345960f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303633383532393036"_hex;
                sig_r = "60e6d17a829095d3c2492ef3742df6da92899a6caa1b577db8a20badb124e9c3";
                sig_s = "8297a2480909a2d4ae622f21add36f2828425301baab4f188cd63ba07429db7d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37383339373634393932"_hex;
                sig_r = "162dc425af52ef38f169594651591ba45d787c22be374bef136f189a1c5ba785";
                sig_s = "1b7deb7057601c8dfe286478ef39f36d86e73b55f147f7be2740a2e9813674";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313239323634343639"_hex;
                sig_r = "9f6085345082d095a5475599bdee7e89ef4875cb3de4e216c5df5a0e9e157a36";
                sig_s = "1fc7007dbfce1ca268e9b6a26f228e26c01d07085f3407402e8396139fb35d9b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383332303432363833"_hex;
                sig_r = "7b86c329a99a59f085c236c38bf90daa9b0a7076bd31f746c6fea9dcd445732d";
                sig_s = "90c9d5bfe10bed534576399886521e6723b5f0ca452362848aa49eefb95c4592";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333635323231383136"_hex;
                sig_r = "425130dab339a89ff4130937288ec20e78b977a13379adf979b3ca5425bd65fa";
                sig_s = "4bf62d3a998e2e80781de830f3807ecda4f5a0708f388448efdb77d1e6516c24";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3234393137313236393635"_hex;
                sig_r = "5db185253364aee145374027a386eb62f36b6d978f94e23972e03846dc131048";
                sig_s = "a56573f77b516d2fb6f884d155289f7f3d6eaa38d8e60bb14eab8ade6e8cd7e9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363232373930373738"_hex;
                sig_r = "130dd721f7fa3e3c26767522aa7e6404d0ae09988e2de1e7396722439e6b7ced";
                sig_s = "843f12ed77d542bc7118d9f2a04f4de0bcbbbaa0a1efe1fce1b5bf41e32eaaaf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313031323537373238393237"_hex;
                sig_r = "8e5b44e47d11be96b0a61a46830f1cec3ba622bee222bde305b23532f3aff839";
                sig_s = "55d56c62d531e5ce09ac86fac4bc020b5a5d0038b5c6c5185a30981cdc7ef7e1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303530383732323032"_hex;
                sig_r = "44d6f35ceac727cbcbb28c9220547380c2d7a3a8aa3815849841c21426aa3983";
                sig_s = "1e9ff0aa876f6ed247cdd8904d72b30c74fcb9d064f90b3d6ae0439dfff73976";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353037373237303332"_hex;
                sig_r = "8a90cc3ffd676a334a54c79b5ba860afe94e39c188d06fbf4212c9f0800a5c00";
                sig_s = "2b4a743be3399c2e2be003309ecb6bca9a9d301c4b6dd4ff39918740b51eb79f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373139333435393339"_hex;
                sig_r = "89c337cfcb19946eb03a63d423a6a67ce16e202c0fb6aa88e50de813363c91d6";
                sig_s = "7faa8d6a92c6f3dadb5e22ec87f17ce3f6eeae56949c037bd23ab5bccd8d4e01";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363337333035373633"_hex;
                sig_r = "96008f8ccd6224d20fea4d342fa61dbc534e519474d148680f26e210c271c4a5";
                sig_s = "19a917d7940f043adb25726642a27645d0e65698aee4d15758a518a476a22ba7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323431323733373133"_hex;
                sig_r = "2f6bc34adc9e8849682e0e37d6ba6c1b6ecf1bcc7fccea1912779e2cbc12bee0";
                sig_s = "976ba20f1355ab13cceaa11b40e4ff356d026c5e4b0f4e5f50ef5f9bed044db7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343735363134373337"_hex;
                sig_r = "97aa19a17aba120e980923817061d16f4f1e9ca17bc06492504b89e36a4526b9";
                sig_s = "02d9ba2389a366baef8ae0721ca49da1fea96c1e9aa8369b81045b64ad8d0af7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313632333237373334"_hex;
                sig_r = "4bee9a122b5be02376b8740e85aba2c24129880912a21dc2802a41cebdf9c6fe";
                sig_s = "474db2bf547c68a2713ed2de1bd46896492c4c8ef106ff97336cd0cf31527f76";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323232343034313239"_hex;
                sig_r = "85d3a12940d1ef57875574f9ddeb688a421d1d9f740a7aa1a8dce2a94b5daa0c";
                sig_s = "38f7bc3421c752067ae1f5ac8ce601d3edd7c67a718f236d24d363fd9526db66";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353234353833333638"_hex;
                sig_r = "7dc36259a5d96de102e57d43e6f3061df77004b52899f88a26da2eeb76eb84b4";
                sig_s = "04f8bad78ce1cb424d3d1e7fce4689483e64bdfbd08eaecc23e3553058e885af";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3331363334333936"_hex;
                sig_r = "10a69623c61133165ba114d8b38a4f0adb45f7f4a55a4e7f38cff074341681ba";
                sig_s = "64e72745887f950318d85cf2109625bc15b1896fd7319f28b7f0868bf0be7693";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353332353938343339"_hex;
                sig_r = "39e3baf7b801f902c9a25a5a6f0dddf03b534d04d3614682678b8e7f1974ac95";
                sig_s = "44ba3d612d200b62c80770133cb9379f9532980932fbcd974d9c1e7a9b3890";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373338353138353034"_hex;
                sig_r = "826b115b5f13153ab40b155afddd33edb84b6a05551b1b863e57bd3743e98177";
                sig_s = "a0f185605a3149337e6a6f6e987850ae93cda4581bb6acf6b34c663dc6aa2f13";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343635323636353739"_hex;
                sig_r = "0af239d782346fbbcbd74d4be1f871033a71f1b1378b816d2285dbd606b93263";
                sig_s = "097061e7c273864dba126efbeb26940fb38481a5cea7b45e2801f1ed5492c709";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303334383839343934"_hex;
                sig_r = "22d16b132518c27b08c5eea30b45b47b972ae0f0c7b677020e0d2220c6b1ea1e";
                sig_s = "8d7ae5e900e9586d16197e68bd667e2f1e3c94917fe7fc2c3001f38a987449af";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343730383836373835"_hex;
                sig_r = "65c553630a7838bf31a3524645cc562da00557c6f2239f06088ceb9081ea951b";
                sig_s = "965be34c6f827b7933e1f24b0d6af98d5a16d17b4401df6286365fd9624f5184";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353537363430343436"_hex;
                sig_r = "375240515612669b8ea7ea65fbfc1ed8b746c840d9c14da0465b3dfe3948f18b";
                sig_s = "9c497e207ca7d47cf55ba9f5aa90afa3b7f4ea90c8ae385acdb77de10bdab5ea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333434393536363038"_hex;
                sig_r = "3fefc958edf01721a89f3baa381f67c5ae57bbdf88998a7733e14372db2612ad";
                sig_s = "70fa58b2b6ef7487286d960f93c50dd244628dd535159597313332989a33e64b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393432383039303331"_hex;
                sig_r = "3a7158d082149b6baf8ac34defb471225143babec5fa62eac3be5d8a74ff1d91";
                sig_s = "43b3e04385af3f733ea6071d6193f766135d39cc724235c2b082f61a2988b619";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323636353831393339"_hex;
                sig_r = "51fa7f7434f18bbacf210645e0e9c352016affbaa5ce527ad2a8929c8e7dba3a";
                sig_s = "1ae516de56de176f3c9a13930973b1a1dc30c8ca751f7f6659248dd31b1d54e1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333332323134313134"_hex;
                sig_r = "60e8e5b328e41667993700adcc63573bba75d68172657c031ae5be4f4ecaf1ae";
                sig_s = "369952c938d87586315b58f643b726f3b78a2d2c6b90a3e2d458364a1d9d9b88";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363136353237373135"_hex;
                sig_r = "612751cf6c7e64a1654b57ceac7783c365a62ac8a0ddcbb1563426a1ea33e033";
                sig_s = "9abe49dea96227b2257a106fb943bb68dee51fe78b40400e497f20f17d34aac1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333539393535383133"_hex;
                sig_r = "8fc0495f721e31329374b39fba9db7e40776ad0210310f7d5001ed061193e685";
                sig_s = "7c4916f329b88fce8dfeb8a920853ebc8491277efcd94163ee113f4cc4fa8672";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323931333631393538"_hex;
                sig_r = "5c29a1706fc8ae68dabde31e517716f1143715e5fc71c34c7098891b5553a6d5";
                sig_s = "40c998427588ae8c32cab8e0209e8307c30d8e077a85b3dc79e61203289ee627";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363230393033333936"_hex;
                sig_r = "28c55c6681a6c50cb8f2689298be0e7d9abf3706d6f19f88e4a2b4079ef7816b";
                sig_s = "9c23d049e9c06f5363e6307d891e7717d646b37d276cc8b9e5893dfa0e763379";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333633313032383432"_hex;
                sig_r = "837293f4ee788a24e6254b805282788f9f2f9e82044dcb8f058e98169f7edee6";
                sig_s = "3eea594d9da1e8df1585a3d96096b5aa5110ce262c62fc081660e8991d3c64e9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363237373433343931"_hex;
                sig_r = "37fb6eed1ba2c5fd0d830441077462c7158fb9dcb549ddd3beed5b0d358c9363";
                sig_s = "5ea0872456aca2c20a741806bd1799ab182ba8900dc2214f79f074b0e6658ffe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383536373938313437"_hex;
                sig_r = "4b85570bff8cd32e092164ee2c9dd34afab98184912d10b678b1ccfdb670708c";
                sig_s = "7dd5d9764f25241e652c42aee48a9a64fc6449e7cb7e7ebc9efb20ff913dc766";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383831313830363430"_hex;
                sig_r = "4d333eec7733a0ee3dc2e2979e50551d61ec7d74b3d0fdc1e7bec9b42eb8aa07";
                sig_s = "7730569947e4172594709c286542e49919ba74dfc0b4532c8e42aa8bfe83faba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130393537333934363738"_hex;
                sig_r = "5318c9e492db4c1d782f1c5021a7530dafb42aa7541382ad52ac9473e22d48ea";
                sig_s = "6dd1439225e3e762ddff0618e5b2788144921cda2d7cc12add5c2572f139c1be";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353432373131393834"_hex;
                sig_r = "a92d86eeebd62681072166dc69d30648c21506029efe64134759e5bf835250f5";
                sig_s = "06fed21d3062655aed3d9bb77d3792df465363589f9ee2754cf274e37f539b2f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313530303334333235"_hex;
                sig_r = "0648798e55d73a3908179f1f104b1e0c2db5dc1d034d3b4ce758cc83e43ffccf";
                sig_s = "51f88aff826e783f72267571509555c501df186e84378b8bd8d01561635a84a3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393939383231333931"_hex;
                sig_r = "52230f92302c0260cfbdaa5aa3726b378631dbf3a277f353fa5c388b0db5cd48";
                sig_s = "4f67e8a17b11b20d6e17b7553fc09021f65a0f6a6a8e003a91a1231494420459";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393731323039323631"_hex;
                sig_r = "2f8e590f98bc4ea9435a800ef02f6449543196e233c0444064063473ac2d903a";
                sig_s = "9060e6f3722a62f57237b98125484999f0fad124dd2b0937895401f11928af94";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353731383338383537"_hex;
                sig_r = "0eb6b253f3596c22a3b63344460352d9a2c56554376d5e41d96c3d4b11bf0695";
                sig_s = "30fb778dc08af2849345de1d0ad1ed4f6e2145efbe88a9b32ec2ea652eaf365e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38363832323639383935"_hex;
                sig_r = "60901403dfe34e2de5ec913057828d273b07b3a9c44d647e728e0f9a35db8380";
                sig_s = "8cfe902ecc6cda4d8382258971f9e63d5b8d7abff7e49749376c80e5a558558f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353438383536303331"_hex;
                sig_r = "690cdc2596aa164ee0d4abf8ef5743410b923edb846eb29837785e8fb4614a4a";
                sig_s = "11e7234cf30d0f2856c80d5ec8fb5c9e69ee3c61f50900e6496b9d468d37b370";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393935373031333139"_hex;
                sig_r = "8749def3948ec37ea4b70fccc6431b9172376fc48bfda6cccfa279afd8ba0342";
                sig_s = "873d39b5450719e75cf7374cdfc62ba3f1b3ee65b3500e3552c6387739b1dfd2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343536363831373835"_hex;
                sig_r = "3eb9855484c096dd22c07abf7cbb7cbeef5a48bfe1e0295d36e1182ff482f9fa";
                sig_s = "10f80ee15511c78aee1adc5f4ed711fa51783604a3a5c6fc3e195a521505a0ae";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313835333731323336"_hex;
                sig_r = "317921b3c180124f168ca56a52b9db0526a6e5e8fb228d6e8fbd5133c5f054e7";
                sig_s = "83ba4764c9c01619702416242d06fe9149754369bd46fa24834666928153bf87";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373237383439303034"_hex;
                sig_r = "309e593a5f3ecaaa721c80fc7beaeaa7a11252f0ff5819e1052f61a51f19e319";
                sig_s = "9813529c6a078d0d466d2ca9892e2ab4b940bb574f5ab994fa6b59897d7a65e4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353632383139333138"_hex;
                sig_r = "11e526e1c0a46e2c06b580bcc9e5cf01fc4e5c7fa3cb8ea446cfd51afb038ab3";
                sig_s = "21239d6aabc4249464b72cf189400a0ec5f7ec08edbb159e89669aa5d431101b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3231383739393238333836"_hex;
                sig_r = "9713dbd1a95ee9248ba9a308003ee01a999170b1b4f2ea40f8a58b80f8292565";
                sig_s = "27e434933cfd22acef5d2068bbfdef9e9150539d6d0f41f8984fea4dbbe57341";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e1eb3c5e7f987667aed17c6e19cadc2f55a8334023cb3ea1f584d25632c10d4", "7d8c7a2515b298f5a94a6f2ccde6d28876dc03af30cbfd63c7386161cb1f7095" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "e2027b801fc479308ff5399a8825fccf";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5376";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a4";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6938807dbda68ab439eb446aa8fd73979ccad0f3292c2879320cbf0ad13b1682", "01abb07c2904b1e0f4d488fbe694f1230ecc2854733cbe7808731a980b537b49" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a3";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b812f51fb276eb64e1236177a1f859a0ca1aebb96d92cdb94c519339b16dec5", "72d2a2da73512c80e824ade98d41c977045c09f44458baca73be3a543877d4bf" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "4ab8de0a51481bc45794b924518f2dd6ac5cce31f3228d624c5a896f79a2d6a2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4628340e3c6e07166b793b1c129057f3d8d7313239411a5a36f2d9efa88ad1ff", "1b9fbdd8416a6dd14a3daa0e2e739eaa9e2c3ded5eda9fd6ebed7a126d513c92" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "8b1b5f89f5bb74caa42d36e601a9f3c20b4e6c91ceb98a52fbfa9f81781b8a17";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6904bf0039ec44d4f78f39da89918745c0d8b565761c5cb9890a3bd5c86370b8", "6f30f70c62ebf40aba1ab170440cb3eb234dc9b8bcb7e85b0d2bf1d90d0d1675" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70cf6a9028bd07f540ace7c1936bf6f2979247e56a9aa1a58616cd4f6d582947", "00f840f3094c832e8d751786a57c17520201b9128d1806c866317e30be0dceb3" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "08ca9c9307a1964e579ce0243722c57c0144663e204c209967bd8b3b852bfece", "05ca6f07149865cf761b58f528583a17b4e9ce758cd81d5c3a06912e7c30b70e" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "133427eab0626276c19d37bc4653a76446c3ba42ccffbcd0fccc2651a026c8f6", "713ffbf582bc60502e1531ad6be9585d31688e0ea328863b08cd8183265092af" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "59913408fe0e66c273b8f1c4ab4c6a7ff89086c18f2a0d2e472b2470f6798101", "3054773b00d6af180422a8761be025940bd92c4384fa610c300af9e337ad559c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "288044898c24703157857b254f81ada6c7c9c16eca16a77c43d98036fce0833d", "7d3f970dac918e391cee32cbf119034ca2f64fa969a21d838bf9dde094f2c4aa" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a9";
                sig_s = "03";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008f22e8e8087340f983b4743180ba3da0c50a96080b6f1acbeb98537ac88ab5c0", "20cce20f7cb6739e8cf8ae9a0c6cd2e107f7d4b6b65e736969e7b0d2195f69a2" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "02";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82975b2d2e";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0cfc0a3b79e49b57241dd049e9627bafe9bd443ff181399ea8145d0a4deb1ba", "54ca255ea5b2a6ad4eddb675b08185d8b1974f1e53a9d29551ac423eb282981e" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0101";
                bn_t sig_s = "2827370584fdeb9f5d5a9fb9579a09390efb6f9d99b64fc188d8bce05c2d4eed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2ee5ecc47f0c054d1fab8678b721a4bd281c73367b81f0548f865c642297a531", "10b3a5427f8209a9cee8d540c81513d436b29cafcc91f1bd1c73da12f5d87e08" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952ce";
                bn_t sig_s = "4937a087731df4febc2c3a81ddfbab5dc3af950817f41b590d156ed409ad2869";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "326d57f742e0f92fda125f9b012eca442edf6c37fe8fe054d452b31482f41949", "6b36683b61d3ffa6a45f60ef03b310c77d9eaaa080cc72d2d265debe4e2d9391" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efb";
                bn_t sig_s = "91827d03bb6dac31940ba56ed88489048ff173f0bf20cab20dcc086fca37f285";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b28b5a8f2c20cda6f560f229d877a00f85bf89c42031689df9aab26f10aa9fe", "3a3634780152c39f7933c951c8abe7593cb8f07d719dbb01e0b40598bcb95322" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0101";
                bn_t sig_s = "3eb35fe7e8331f71e4c63b45f349a99d47a5e781798e579f2386195d3827bb15";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0a28eafa6990707aa9e54125fae0fc66ec3942b02b393d76e1fce2ebae01e918", "0082f1595d33f3e3760a9cb5292303f365ae566f2046856a39b37729decfdd373b" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c25";
                bn_t sig_s = "3eb35fe7e8331f71e4c63b45f349a99d47a5e781798e579f2386195d3827bb15";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a2ab9590f64cbb46f261b838cafbb61c6e41cf71cc204183a8a761190ad7021f", "0088c059f5942bf7cc69db600c0afd58a57ab7616dbb473fc1a37633a983a555fa" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e8297485628";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fac907b1e46cf40ad9eab51b67c71e75b245c47786b178bc5050ce3020ca061", "34ad94fdbb65331a2d6942857de76cad0b8681bc80a920e9f76fda5fd303cb6f" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594f";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "357920c20178f9c95183dfb081c9c38d1a3308bae119074f4e6649ba0fe514eb", "41aa9f98e44e50e319ce91d8dd17cdb6254a47b5c4812318d014c5ae7610f983" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3533d5d65ac5f4270ff42bea3880b1ecd41031985cc7d27654ead4ec50b3607a", "0093bb7bd11de59958331eac2fd4e99fe2e9832b2689bd0cfd4179d4a2e01cb5c0" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367b";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "04f4eda07ec78c730fe753379ff70f09295a8e7dd1849155cede7366dd769ee3", "00a3e38af03dc68f77d3ca3ff5ce93a15525b2e27cfa3ccac69655b9febd9069c8" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48321e268fddb97c84318983f5f6aaff174077f80bccc965f3f19053f01d5c74", "0c615c4a64b2d1d86181664ace3bf3e16880428d439aa9cc6dbec2f18716901c" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "536e160ff08fc1d259f92aed4fc46e1b1b76c894937f3ce1ce50e682619a5620", "1f938f6aa400d4907ac9722068f8bde3681e994333a7aede8fcc8101a882d98c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "253f2522f5ea35c8d48a5aa79ad3da0af8eeaf1a5e0aeaab295494c94bb615b4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "38c5f7b40e2851c796d88efef5fb41a8a56688dcb146594a2570a2d14b9b5c24", "13473ca79ed9f4ef362ead385a27ff4c0948667798394ae6371e62d78c95bb43" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "28d6daabb1b474bb9f4520cbaecc882cd23bb1042fa657473fd4078ecc80f7c3";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "68934c8bdd432a920e62e891f686e0a42a4caf03f8eeb3d8a20953fde413feb3", "009351acb7b12599e3aa17e1eac9e59bab8a79a70aac0c812cd52d82b5eddca241" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "43afa375cba6e7de23eb4f70f36fd9ce3b7237e43ceaec1fc2fda055ca9871f8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "323eaadf1a22e3d7edecef3c9a5b9327ce7428ab163306fc0f07b71bde27361b", "3e8d5cf63e1ae9115de626879051e4531d18c1ca56fc7cc8586330489faa0e31" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4b57b5f040bc7fdd6cef6aee249d68f7ce2bf021fbfcd360783dad600b584064";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "65d22f424c9a20ff58103c260bb9005e943fcbf1c8fbd311bf32fea5be906807", "008e14c2111c8e2aab36bcc08b3ea3ddbff9463e7a5fe08e38cd13fe2669c14384" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "21dcd8dd48892812395c8974ecd00c8455842e5181884da6035f353dfcc48d45";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "41330a6c79b2781782dd5ace6025d49bf02521113d375800708f60118814ce03", "009aace65e5f21c66d6843199c31f458cc376ff567b7ff044316347cf69ac8dfda" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4c89edc4076ae899f22372689f25460a929a44aba87c1e51070212564beb8cc2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6a9602bceb7e03886bac62f01e12ff64113f1b060aed58d0f1d2af3fa832edb8", "7102549b5c2d251c1c7394f41bded269b8c40dc693631cae628a822ca0c118eb" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "231fa4702f31c86a790dcd5a013a757ad954950b941a7db865106b6de48eaee6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78084bd411afddfbb9e3aec4af693291ed143e0d7519afbb4ad8d441669559b9", "5ccfb4b14bf8028a9cb9baeab02b193ff46f6de0cfc1f1354d05b2237b0412ee" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "3f9826b90802b2725f4f7be70ded05d887e98ea726b3079c0898f078b81f1e71";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2d4abd4ab5947f2de96fe2585c2969c457f2ea292c62c4672ebcc3f6c4dbcab8", "7fc76db526abb84dd893137362417e5d404807e36e0031066bf2cb601ac675c2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4cae4be89cee15d91fd495d8a91dd90ad1160236a74d8bbe0f409545042ea5b9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "65b0448e11c17e55f8d54362d09428c6539eaf85b22fe2ab339c72564c947d73", "208e7682cf9dbfc745415d87ce4752b29d5a1d26f8648331510597ab8983642a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "328f4ed5ab79a8a1c901b906a0f55b4bab77401f58db4d555db7997c11163426";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0080f2e7e7077b916605249be30ef87ab94f9b6c140d646846ff98e246144e294c", "315c0f4ba1b32eef8fe5785c7f02fda0c7f2fc74ca9e98c9c85924ca107a9e0c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "310c2a34ac6ab050ea873ea26aa298a5782473469033e021f5e1c13ef0630755";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a81be0116bec92694ba6672f63b1e2ddd5f848e277ea9fb3e3dd1f0374dfcb22", "5c5b329c8668fb876b9189e8aa99559ed6d6c338cf7876be7cd4bb85216af10c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "241166115f5e25e286b882c3e39558df1d1e6ef90551115118f6251d3a566adc";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "28e479f1a1618760c664ce7693986f54cef758ee078a2ce9d1cf1b79beeca20c", "00905f3aad0bc94335540145f75c54e1439de798de71e0cd2abcb74367b6627da7" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "204373ed57d86a4103e275333a16ff216ea450a5ef3c2019e9351a2c57466d6d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5ca90c3145a35798b391eec3866674795e204ff0e5b1acb62114618a7aa83c74", "33386886f91b4810b04f4d3463ea8abca5946b5db826be85347eb6387a36667c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "1804472a04273f8341952e89785cbc7fe86f74edc780d1e89014dd6d5f6f7f37";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3238104f49fbc1c62e7f5f67004c9a844e48d07c9665dd6238602d5c9ed6274a", "00a005643228658a81f2049d905d5e6fc0874434e88710d98494fd0c59f8ee18c9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "3549f9e472cce3d5a153ad22dcf0b11f7ae5090c8ca925c9897e89f3de070855";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b6c8429f78188b32a39d02681ba07a09b54d98c59b45dc3ba98f4d8aecff92b", "5feff7418fba564c5d7b0b9db684622814292dfd85c30da6422db8a95f473e35" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78fb47982223887cb723401321e18c15e9da3201d7c54257997c6cea01488746", "0d35249c1cbdc9d8e597230740114935c7c9653d0ac6185917bd0dbe4a575ea2" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "166dccc1c50cd1e27b5b3a520575d4019b6f6253f69382db5f69ea7b1e3315e5", "7edb4a26fa709c78fdc6166eb5a0c252c2b5f74d9478aa6e5b9445868ee00bfb" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b54";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "02681a0f6ba6f5dea35f6ff1f89adfbdca42e4aed2f579262a2d721d0a969544", "55f9cc26a0a7f5e464a995e2b924221d73237bc0629fd62920f6f1aa1e684449" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "5731b7c4bd04cb9efb836935ff2e547bf2909f86824af4d8df78acf76d7b3d4e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "11d7c17f9524526bb1aa9d5cf1a6d2db2b7c92255725ace2db8beff3b1e3c5aa", "031196815e3b6ab7e0fe7da45d03f6b172fbaf42ebdc03fe37e77a41dc8bfc71" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "52c9a016e4e9de1d42e2a15a9e5538f599a8db1d3316b21eb0a5618b29cd1959";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5c6dfa4fa95dfc400f6a31c62c289cca3c945464317c91ed27f1344a17f61a50", "39f48c452bbdb0065170d8d4462e8cf765e6031916c16188d78959f2ad02e0a9" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "79d861cde2392a21b481b2ae5621e752b4da2a115d6cc82071c0538af6b6272a", "008fb5804b20adde5cc6a8c23f6327bdc1c17355f1621978d583d759e2275a71bc" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "71523a926bf4712829995c6069025e4bb2d0fc6d23966f4fb5695f01ba3039c5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "134b0ce73482b6faf7bb86980ba06b78c040609f94668531ab598a8d57eb8536", "445599e651cd4c2118ac04e1a797b084a4eacb547cc3fda8c41582dea6a4df12" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "1d109296e9ac43dfa92bcdbcaa64c6d3fb858a822b6e519d9fd2e45279d3bf1a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48e12e669fc1b86c0276e6b7e5a6e23fed6e917f6262bc7c37d1616406d73f8c", "3a1d0e775a2b32fc9922004f0afad6d5f656d016d431513594849e1af60efe44" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8c2128f5dc4e0b3457ea40c55a89e10c8f42fc8ea3f8c92523face034ebfe9b8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "796f1a0ae4c7082a70a4568890bc423bdbe33e818c9691d501cb8088380e9532", "7e1a6e26b98abeef038ae97651752e9ff75f98b948a58433a25e92212a1ad413" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "82a87706d98abbc48325a0f7fe6938ccd75e98439d25848f505ea82f492d96e5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0088957c950ed384f600ad37f83cc29f9dc1d2711f40e622de210420cff6449197", "496d739d064ee9416d4388c79cc18f1ed1a4840a7ee36c8d711aa5d3ec822a72" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3b95fff42513681088902d87fd9130092c08879657ff7279a2da6bc0b2cb1e89";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "762a9cafe969ad88b92b42c6d2a5ca539b94985de36a85a2a20fc38fa6f34c6d", "120f0715e1cdd1ac3837bf46d87a533b2c4f34d4a0c64bfcf04ea5abd053ba16" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8c19c62c81af96573cdb47362296b7438246f1d63cc4ac78ce40b526af6ad5e3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7ef326d81e603f80db7ca21a7e6c6e9e077a07e72f933ffade8950d64672f9b5", "008d57018d569879f4077d46384f068f8d2de11882095efce324d2fc26bcef3f89" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6e38347d617082f23b5083dba7a9e11578546908c427b1fa0c635bcac78d551f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "23f4acb9c5c58479f4e783286e65941373e1263b83de2b544bc7ce5288c0db87", "7acfa518e4f7572bf1109e926b912986568647c30a0e47fd7fada09a8eef7ef1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6ff922125a63f82d380b75dac21241a89653aeb8137cad2a943d5cbd50491286";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b8810c9bc3442e2999b0c7c98d84faef2432cd7c13f9b41274ff984bdcb60a8", "08bf47af0eb7671beb922a3c9d6c1e96e19c6c359edca3a7580f98bbb3edc664" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "050e2deb40230cf4fd7736a36cb789168aff681d754a1643014b96b898577800";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6ffd8da5d0f06028e6ed05711ec74eac956010c5ca965c5332f5fabdb777c9d4", "4c1f1eec39656664a7e450eb39b9ec606ca886824decc17f7b6ade3257dc6bc8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6c7a2223efad1082e2bcba164c9c3d285e3abaacc7040c601ac638f3fb3799eb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d03b4ee7ea7e06f33f3dea09b4ef610ba2adf5d043183c47d531f30c6304e74", "07bce7ca0e6b6c907c81a3d9da66799bc368775eeef0084145da8bc31d66828c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8ceac544b84265dc953a3cd3f31ec69d90b3f02189f35559f04b2a301d74978d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48e0dfeb287670685c1b34f189b7517ca42d622d1fecf8d703b7fdaa57a5493e", "00832f102d2c03f1e48d31b9ad1af7fce77627edfbf532b77f1f3155b858d54f2a" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7e627bf9436c43ecc0a455f59dec633392f12ae0743c2c8b2061b806e08ab800";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5c71221ef1a42ca69edfd6ce9138d7395c95850019e053ee982851b513de8c4f", "008a0e9f4e1c6e0e80d043615595a4f700d61070a4602d12680a5db39c152be129" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "9651e7713dbcb2c060c5d5c44df6631f31cc0973a94395c3703e5b58f03af6c6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4a290d8d3f8b60f02fe6b3139b233358abbc807128bc04895297e10cf287801c", "5d9e881b5a8a7272ffeb2f756d723ea9c4e125b0b1eb07aee6b74a4c20249267" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6353c7f3e0a4e33ebf7758dadf2bd9d0841328e13c75e252855f5a2b87c2c78c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "60773902191533aaa8059d66fab175848ab959b357d686dab1dd1e1ea234884a", "7d09831c178b74c57a387f1e29480e1645a3d07b4b087010067939e04a6bead9" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "14899bc6ff5e72338f3c9847fa6531c4337fde3fcf1c8c32f768fba3a402a964";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0083b1b3da8c421eba1274359f46a74811a92640d0ee2a40c83e9ba9cc72bcfea4", "6c0ddb304b86ac3579dede10dea184a0385f9c3ce9e14466826bf44ab93d1ef7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "72655c5e4f1cefca22f413a612e5bfdd7ba9ae71053f68b0c74d9a73590013c3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5bf5100f5acd4bdbe472465365fe8a812b60dea8e7ad6559f44a52c779768e0e", "5603625f61bd051b8ff077aa69ce2a884222612b71069ac55e4f4ec84228a1a7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a2030dbf01d8c9de2900dc3845fda4e4c6bc049c4cd5717a9c629b9ed29d1859";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1fe51c4f385ec8c8120952c19e0f42a184390747b347d733120d0ea9a15b23fc", "008a225a691efc213dbb467d4ec8d2ec6b10c2253ceb5175cc868c3ca2132dea1f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a1db7293b6f01594b808718e61a4d642dff4fee2fb471167ef7ab42959a473e7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3b389389a1ba1ce02aab1fd3663232414a5ed4c3b9603fb908725789acdedad5", "62b520aa89b6d426b6c9f564ceda0854bd18fae09415bb4a25e6a7d033afaa71" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "99bb8d4bcbf1816d31aad88c25c61f1433b08322412c7bd84ed759d01c009127";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "72e15babc57a00c4e514ea1963dba385c875cf20fc50b5d9d5fdc03bad104e49", "5019c868931ad8225a5341a0360ddbc380d4e610d81577b24f2f77bf6e8480d2" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "41cee82a6957ef02ab3aa07a3315accc0d0d66c2081d530246d6e681873c90d1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "08d757fc7cca95f3a113d787138f13436abf981f85d7569559fc3e1f21c6cb62", "0f2e63d47486bab267d3bca912a47dd9df40a7572e0ccb31841085e8e8c9dc9a" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "746d61572ecae774691e7809121986d9b93279b00934ff1def1f4798da89ad4c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2fb18733a9327902afc952611773661d2de4280c226f6d4df6431623a211ad4b", "009fec8ae43c8703f70ea2e87ba5d560d9a552afa7f078d4c468919a40575917f5" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "281b26a0908968099f8e1f610f4f358318baa21107b791ef6f24cb244677a64b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "54b4d05112fe86d5ad3b0f15d686a61fc3c2aec134fd0659809397091fed3c87", "0086bd94ade4c9e2658da6fbf7a72cd71f4c3052452f2f0c62d4b27a46115d49" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "46a78fe7c149c67d7eeeb1b5be57b3a1082651c278ebc4a50abeb4570f858f1b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2517e4e13313bd19fb2afa90c840c62118bcdc63e9dfe0d8f658c2f7ba919b52", "05b688fd1a648d5ccc43d1ad188ae75e889e75da84ca15d2e4ea45d1e904d038" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "14fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b55";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "492669178a5c35d6c4618aed32dcd58142247a6e3ea43f39ca9aa1b6dd9d8c86", "7b953440076a2f28bf6cbd69343f30be80bc37868a59d02713d88f88d5d603ef" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8e305a1cf885ccc330ad0f1b5834a6a783f1948a5d5087d42bb5d47af8243535";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7392ca7c91b33e8628de655d15855ed922d91ee74a7082a5bed82ff6c3237f80", "17ce47579b7bcb5ebba5309a80f9aeda79c21b182f7f9d086e566ea3ea1f0653" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "074c035603e1eb49ab5382819bf82af82929b500c6e78841c1b2c3ff54a615dd";
                bn_t sig_s = "950f12df902702c52703a52023e3e4d15273369aa38828d72f333c220c16be7b";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7392ca7c91b33e8628de655d15855ed922d91ee74a7082a5bed82ff6c3237f80", "00922d10840672de5d82c0d9f61c89de97f479db0ba5a6831fb1bcd979354f4d24" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "074c035603e1eb49ab5382819bf82af82929b500c6e78841c1b2c3ff54a615dd";
                bn_t sig_s = "950f12df902702c52703a52023e3e4d15273369aa38828d72f333c220c16be7b";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "330ea7adbc48917a431967580dc3827b160feb627aa441b522fcf360f5b1e09f", "03fe9848347703e4c060456a19a41d9babfcba14ed46ec61306aed5205a3994a" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4487";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "42005f92fdf527ad5696e61cc6576d6b930e02a6eadb2bf5dbaa348567c49220", "44b4d482cf64dcb4be0b94fab4c9aadbfc97b66c1d1f33e3e9435fa3bd6d0f30" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009b91576b08dc63adc9f8fbe3619ab6232c3721c88448a19b40e73ec88dee3440", "71acefeeeb52b70ee10c59d367d58ac160442b7d6c25afe604fbe9c38c5fa8b2" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "796a6353bccf0b8675b699d502cbae2c88bb5799818ee4f9f93a0a5d477cd02e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3d0e7513d820e886c4bef479669c4b75c1472a66dbd238c8f645229b34c26196", "009d16487634de9cddb7c371ef8fe30f75e37120e16449f939c16b76d5e61e569a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "87fc46494e5887c9cb84d5407e02d78e09c7954fc44e1f2c734b3ecedf6d121f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009254ff5b11d15ee4f1924fb3fe7cb4a2384200897d0ccc8786d9d8090aa92de8", "0d4ddf1ff73da2d2ddefc5bc2cc38be81864cdb6d6f2033cc38d854a506daa78" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4488";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2f618d223e384da1b17f8a0d1f8c9c11d284cb4bf699bb24911d159fd54f013b", "3085d7295996afa893dcf254c0740260f88afe62786329704a2eb10548a0e6c1" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "3090f487e51f9e35c8af70bb9ab7df45037e230a33d2c1fd96e404254fcb8679";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e94fdd1348123090db23ea5c43811be4d914a17511a30c87394d7d8b889fae2", "5ee81c865fd9ab8ae64859bbe19351582521afd6860dbafc57d7523e4c3a1c2b" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "77472d9a28b4ece71cf413a68eac0eb423a16fb462b1f48706fed48ca437bd2d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6f50cb633ced6cf3cd331c2acd00284dc92aa32138df5dfe0160be1ab22f4e46", "3b0acf4c4c7fa4832bb153fd86d4fa496595ae6f46c139fa2c8bd631a84763cf" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5876c95c7971fbaccc9fa9094c1c86c283f16ab663a205ad119bd30b7b1d3c55", "409911a566c231a9f42aea3c026b2002847cb718af7821075523abd8538eed71" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "796a6353bccf0b8675b699d502cbae2c88bb5799818ee4f9f93a0a5d477cd02e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0df714940dab1d89db3090e5cf8d8f8a16268259afb115b3326e06c79b75887b", "009f24c7a5f9123cc6522c351ecba8e038e30d05f7a2df914c240762d514a31d" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "87fc46494e5887c9cb84d5407e02d78e09c7954fc44e1f2c734b3ecedf6d121f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "774818a1b45de6aaa572af3a582b493938139cf992ca6e7e0f9519f8cde80e34", "6de9d55d25e51069afdcec5413a3c0558a7a01c6211a061bc1ebca0b0080482c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4488";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3fcb64a053de3c29a9536e0cc8bedc0f0a8a387cacf614c524bd572b9d51c350", "4961421d773ed341c7e24e0fe99519771c877745db90fcaf58808620cfeedb18" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "3090f487e51f9e35c8af70bb9ab7df45037e230a33d2c1fd96e404254fcb8679";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3135f9b02a2013363db7540431a235ed38f237a3f040b522284e8bb35d6b0207", "2f5f1339b64e3700b7c5a9280f9c03821a82cb62b4784a31b47a5a6ecf5411fd" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "77472d9a28b4ece71cf413a68eac0eb423a16fb462b1f48706fed48ca437bd2d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262", "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "5731b7c4bd04cb9efb836935ff2e547bf2909f86824af4d8df78acf76d7b3d4e";
                bn_t sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "52c9a016e4e9de1d42e2a15a9e5538f599a8db1d3316b21eb0a5618b29cd1959";
                sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262", "557c5fa5de13e4bea66dc47689226fa8abc4b110a73891d3c3f5f355f069e9e0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "5731b7c4bd04cb9efb836935ff2e547bf2909f86824af4d8df78acf76d7b3d4e";
                bn_t sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "52c9a016e4e9de1d42e2a15a9e5538f599a8db1d3316b21eb0a5618b29cd1959";
                sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a9fb57db62501389594f0ee9fc1652fa83377fa302e19cef64252fc0b147f774", "009507acf5b04339ed102b9ca60db98c165b94ebe855d2202e46dce15ba1e028be" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "9e8d7ee48694337a6410bc221ccb43af751965345a8576c718c7967d3f7016fe";
                bn_t sig_s = "2ad44b1702a0cc8a4f8c226b2bba3d23f11c5d8c1186386318149fb9d39de90a";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "6ca04cea3f989c10224fe0edf37c5c9b94b1c5c382e4c745a1b256e71d2509d1";
                sig_s = "2a3fb7073c9ec8c2c7d17bcddc73b7d8f08e999962a572683ec993512d3ae8d6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "3d8259b2334c6b0976d00cd89f051d3e12fbd211ee58517b96176c5bfe6b38ef";
                sig_s = "9992d6e8fe401d1d9b2cca4243ad7e5998ac0545adfb5da1bebcccf5825b7915";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "351a45fb920f2c9f1b178438fa3bf272ff9328b881c477a1f56a8c0e88465276", "1270f806fe40ad97ebf76c6825384b780ae6afccc792b05f2fb3eb7b7fffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "52b2b92c9e9c3e48db672c0115530c3608d54a1c4ff8dd00a8d064650f3446c3";
                bn_t sig_s = "8aa15d2fd366a3c723a7b8cec0443f5d260b3069beba20f3ad6ef4aa9010492b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "447d6115695da4085fe718c84dd096c9137a725e69940e79e923f52b74385b8a";
                sig_s = "68c655e01c00d9c77c88eb226bf5d08db20ec62155f700cc12df819f8829f50c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "92d7b7fd656dec65d658addf4e2cb82d7b5b931e5280ae411fd05d4c00eb16ae";
                sig_s = "25257e0b8c6033ff13598290157b8e1cdfc4737d003960efd64ab0d404cba537";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0129b2146e36fc055545bf8f2cc70f8e73e8b25e539365ad7577cc3535", "4a2b8c0319bc4ccd3e60da119477c23faf8fc2dcefc42d3af75827aeb42f6f0f" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "a661e42044c25fbe0500cfff430852ba933e8b0549c7b60baef7f78140715ff4";
                bn_t sig_s = "888953259b2b38bfda78a60fac8eb6d32f70d123e784f99c83f447ab7b6fc417";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "4e2eb5bad00a6df1365d3d3a6c229c129a2555f940f5defacecb500e591177dc";
                sig_s = "74933582e1811b7c19f42dec068c17f6ec8c209638031c1e908d259bd98d511c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "647531b2bcd13b46662f8ae3b59529a4987473d3caadb1162dc662718d7b4d81";
                sig_s = "0360c5348fd41f3aea94021ab2e88b9c97337a3029ce80c026078adebf50d92e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "680becabe7d7df4fadfe5ae01fba5ea51b76759606a2e30612e667419b885d05", "08541dcb0723785c3c766581a7514a1ff42e4437d63f878271cb860f00000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "6b9d743cff6746170c19b10f9754bc6f55bab0c1747b59725278e2fc0432ee14";
                bn_t sig_s = "71c20915b40dcb2d46bc6a8cee777f54535b4d6a2cad53e5cf974e75b643a98b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "63063dfb0b4b62ff62f80f533116714cb08656071fcbf192a9aaf1c77cf2d512";
                sig_s = "6af7e5ec881834476a7cb89b2f02f4bace4c1a54202099ca8d54f708203baf5f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "a052d9daab043b0bdf274c65eebda9e9605aa9546eee9be3d5072e86e24c2d42";
                sig_s = "34336e73ca99efcab84916b665c8dd61f6f40e8821fc9d50e70bb7c8d0d18ba3";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d16fd656a9e6b34e45d8c8c3b458eae7bbc2879f8b4f61171a96f664eee9061", "01469fb456ca6a1720ca8db25d567e121cf921ce13e34000f8c12f5272" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "9703683ef0b9774b675bddeebef0210563da0e1ed3bda0d3b6c061f87cba5bfa";
                bn_t sig_s = "638b0e61111aa6f5c47b632da8d4d2429c6255fbc042ef1c8a113df8be48e744";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "722c211d9bd809105cf762b3d44e6b7c69fed153c25767f1688c536b4e97c7a5";
                sig_s = "31201ff894b7b6d7c3afd438e4916bbf7c0b6153d3653310681a28ecde6362cc";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "7364913ccb333a27beca4112cf988a504017161ccff2f67e2b8119eeb7971f24";
                sig_s = "47970ab7bff28f758981853ca85c69f5b4c95e6f759149d505dc5b1eb82834ff";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d16fd656a9e6b34e45d8c8c3b458eae7bbc2879f8b4f61171a96f664eee9061", "00a9fb57da5b4ef56573fbf36fd2f5db1517bde406dc0452143cd347245e3f0105" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "72df73fa6f930da1bbe3701036770cefccffa24e3dd74450daf080296eea6f04";
                bn_t sig_s = "1ccd18e0dd6680349122ef2163810b46eb73a9fbcc9ae82369f0e112577b7e5c";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "855818b2611728024784b2c13cac726e8a7a52cc668565c36e0dc1e72e763bb5";
                sig_s = "9fa291faf3cdefee34460261232f0c078e59be9a1f889d3b107ebdc4d399c791";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "8312ba6067b4b3e191d0712beead0d93068850abefeaff480178be4b964cc165";
                sig_s = "7be43ad1db8369f7e1073e3db0a875c5133e1c35476f9ec7a5953b2cddd3184c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081528b7adbbebf1b6b3c7fa1d61284b07759b9a98d31a5702707b018fdecff11", "75bbfccb545381bf8601031731841829401b08dcdc68cc34e06a64e412038512" );
            {
                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "51aa4ecb988af43c944de217ce327ad39f4d1bec88c3e5cc6466e3ae876b8f87";
                bn_t sig_s = "a94ba3ab937fc760420aa25df58bacc6dba958a03dec2acfbe5d7ee5b67321d6";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "7c0dbc412118c58c4650ab5bdd7d9ab06eab42409bdf645b7615d3b22ebfa10d";
                sig_s = "59184531bcc146bdfda20d482246fdb5b1e20fd356e690152f2bc57f5d3e9f8c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "45be75cb7281bdb08dc914d86a5b32f441e68573da8788c389ae5274490c6510";
                sig_s = "4ab9dba3758ffd45a35b4189c9126e75a1cf0093f7e75b10f2d91b7322332716";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3a25a353caa94ac4eed3700f7d56b456a0fc670d56a166d5219b7c97f30ef3e", "16ea8e03c20977f20aed58106b6d9d1085b4475f75b5469c5f426cb27ec6d872" );
            {
                // y-coordinate of the public key is small on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "1a54307f9af26d77b75806e8e3fdc2fb3d43984e2e96f2ea457cfb28efc4f3f2";
                bn_t sig_s = "74b9b021a3d96a84e6dec8e99284c60c388da03869f3acc355ca0c28c27e3894";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "10ad224012fa969d7b12664ab20f8c614e7060f2dc5a52f8e90c28e63a98f03f";
                sig_s = "5b1318ee76c065f5638acfef237eb5da24b9cbf260e91938bad80eeaed588d12";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "2a9f1cc11d0d582eeacfca0ca75b2dc24dbb5586ed0328344971cec278fc26df";
                sig_s = "4a42e78efc78c8faf4100a5ad51044d060e12030e47832a05cfd2fefd25612b5";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3a25a353caa94ac4eed3700f7d56b456a0fc670d56a166d5219b7c97f30ef3e", "009310c9d7dfe531ca3378b2803215f061e887aec45f70d98bc0d0db6aa0a77b05" );
            {
                // y-coordinate of the public key is large on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "743a8596b775047757f24fb9c7f99ba236c57e1ddead441cdad18b3780999b35";
                bn_t sig_s = "515b6ba67b870159cf45d1ca0ad2f13295d08392a1760b6ee0a9a91a31049f75";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "4591277f05c6f10be0b5c530aeadc8f7a623d70f5de97572297840160e07b9ae";
                sig_s = "0d8c543a4d4372f1c2484f9a3a9899630ef474b1ee6038be93e1e24cb745a779";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "61fbf6b91439212c0f8d0aa8741a9b71365d6f7cff93ad77732e3e06022916c4";
                sig_s = "43976a3e0c7ece5e327a09e2b9ee6b5b6509e53fff840a02477fbdf0c0c27a10";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d499b077ab6d77b244320a2cacab91a764595dd67a7a8dfcf84da7d38b2d8f4", "5994c07b833ff4909c1a92cc9f24dea88be8603b407b00d228faf2158db2354f" );
            {
                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "9fb9da3ab3424c2ced23d5d0050d425f86f88a3fb605e58da2438d3764ce72a6";
                bn_t sig_s = "11864a598557fffd2c922b3be0969fab1f27bb49a247e9417224c21921f485e8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "763433b92115c225cbf24a6cc57fe02d9c89e14e6ace84ce4afbad1f2a7f2996";
                sig_s = "070dd1cca68fcb52899e422afad5004131865543ee6c142524f3582a53304140";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "9d7918344d1c78b4090a91f8dd7b4bc9a90b28c1c1ce38ca3ee4a2965b21837e";
                sig_s = "46ab957a8d23b17959c43ee3c34bc043a36b7276d9eb4fb32cc00f0b4ee799ce";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "08c2f95ffedde1d55e3f2c9dcf5884347f6904c6492273ad760eb7b9b35f036b", "2bcf7a048caa2c726ae8808dc95312eb2350275a8f4fbeea7c0f32f3839c7b93" );
            {
                // x-coordinate of the public key is large on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "1f9019731f574f8a5e842b6847d8dee824d5ad54462f244f7f791373f872c93b";
                bn_t sig_s = "0a42f9b0e189278f1aadf579a55d3d5e8ae85615dfd67c89ffe866020fa1514b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "8834acd9868e5f62f75d8138dc4a0ce7c33a10521909b79e49ef95c8e9212ee7";
                sig_s = "1ba78de4947212c87f0b8cca74189d7855fdf38887b6d40a2244af0f5babcef3";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "819979e8dc2f74cb11a9444480ea072402ee4d8618d81d38335a6752e7094eeb";
                sig_s = "59a6994a157bd8d18856ee4aa878d03524d37db6f3a8d98c82dd6a8dbdd93638";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_256( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP256r1_sha3_256_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP256r1_sha256_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP256r1_sha256_p1363_test.json'
        // Note:
        //     Test vectors with flag(s) 'BER', 'BerEncodedSignature', 'SignatureSize', 'MissingZero', 'InvalidEncoding' were not included.
        //     All test(s) with BER/DER decoding related errors were not included because they're not part of this test scope.
        //
        // Algorithm: ECDSA
        // GeneratorVersion: 0.9rc5
        // Header: Test vectors of type EcdsaVerify are meant for the verification of IEEE P1363 encoded ECDSA signatures.
        // Notes:   ArithmeticError - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA have arithmetic errors that occur when intermediate results have extreme values. This test vector has been constructed to test such occurences.', 'cves': ['CVE-2017-18146']}
        //   EdgeCasePublicKey - {'bugType': 'EDGE_CASE', 'description': 'The test vector uses a special case public key. '}
        //   EdgeCaseShamirMultiplication - {'bugType': 'EDGE_CASE', 'description': "Shamir proposed a fast method for computing the sum of two scalar multiplications efficiently. This test vector has been constructed so that an intermediate result is the point at infinity if Shamir's method is used."}
        //   GroupIsomorphism - {'bugType': 'EDGE_CASE', 'description': 'Some EC groups have isomorphic groups that allow an efficient implementation. This is a test vector that contains values that are edge cases on an isomorphic group.'}
        //   IntegerOverflow - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified, so that the original value is restored if the implementation ignores the most significant bits.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   InvalidSignature - {'bugType': 'AUTH_BYPASS', 'description': 'The signature contains special case values such as r=0 and s=0. Buggy implementations may accept such values, if the implementation does not check boundaries and computes s^(-1) == 0.', 'effect': 'Accepting such signatures can have the effect that an adversary can forge signatures without even knowning the message to sign.', 'cves': ['CVE-2022-21449', 'CVE-2021-43572', 'CVE-2022-24884']}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SignatureSize - {'bugType': 'LEGACY', 'description': 'This test vector contains valid values for r and s. But the values are encoded using a smaller number of bytes. The size of an IEEE P1363 encoded signature should always be twice the number of bytes of the size of the order. Some libraries accept signatures with less bytes. To our knowledge no standard (i.e., IEEE P1363 or RFC 7515) requires any explicit checks of the signature size during signature verification.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "019a2d9637743a63ddaefdbca0ee229a163b809b9b145e5313bbeb8defeab9d6", "548caf89bf5ba49499404145651234336401b9b2843a579ed152e090f11b9e59" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "0a5f8c70ba2d0842d5d0f841f160ad15195769a8159bfe692634d73d469d111f";
                bn_t sig_s = "426e857aad3ff7aa96e4d200c03b45f1846a36d089ee3917768ca1a0d6d4da6e";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "b45ae44c5c1bb1ff143702d28ee43a86a590e44bcafda560b652e5bfdde567c6";
                sig_s = "678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "aa05b76812a8d6c4813bdb88df74ee1ea152d20d5d7742f5f9444359d48ef3b81f";
                sig_s = "00678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "9f9bcb6ae7c1a1796895124eac22e05c72e210fb9fc5a88e69e9374550ab4588";
                sig_s = "678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**256
                m = "313233343030"_hex;
                sig_r = "010a5f8c70ba2d0842d5d0f841f160ad15195769a8159bfe692634d73d469d111f";
                sig_s = "00678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**320
                m = "313233343030"_hex;
                sig_r = "0100000000000000000a5f8c70ba2d0842d5d0f841f160ad15195769a8159bfe692634d73d469d111f";
                sig_s = "000000000000000000678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "0111882a3c969d5bcde5e743207acbd4f19408be76e0d514d7a9af7b6457bbd2e0";
                sig_s = "00678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "aa62e4ae02e3586e500d8bc92d60d5b90c4149e7888d1a6570379fef7908ca2339";
                sig_s = "00678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**256
                m = "313233343030"_hex;
                sig_r = "01678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                sig_s = "00678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**320
                m = "313233343030"_hex;
                sig_r = "010000000000000000678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                sig_s = "000000000000000000678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a8";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5378";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3638393434"_hex;
                sig_r = "0c939a92486c6d0d619510b4a94162b9221be2eb15faf878bff75e6cdf4e3707";
                sig_s = "3977619b43e6b4ea1870d861206483b306560e3c4a3ef82b11a802ff8892dc1d";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343236343739373234"_hex;
                sig_r = "5583dd480964bd2332885fbb50b7475ebd428399e7166fd9bd529611534b9f34";
                sig_s = "0ed035a02c4b665cacb70de8e822facd71645a15f93fee661324f850b847b51d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313338363834383931"_hex;
                sig_r = "300e26027ce7d3f21c8571dc690b1bb990e8fc49ad3e95374bd543b2e22badc6";
                sig_s = "22bc8f2445cd4956bc0db553966a0718aeb5ead65bc66ddb21fea0e571a87ee1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333539333331363638"_hex;
                sig_r = "2907cb01a82a88046640a523f9b9854d95b7ec2ddd67c20723d05829e8438a77";
                sig_s = "38ca08e58623560f724a3e3f9ba0e9ec7974976dd34e6940c0fe6168d540e39b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393439343031323135"_hex;
                sig_r = "0c35840f7b7319f19fd72f29fea4cf937aba2c3fe1dc01aec63c21094c5d3548";
                sig_s = "7bf699868c2b694547aebe9b98c01c5efbe982a84150390894563d4e2cb240b6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333434323933303739"_hex;
                sig_r = "4272ff20b8c3d19e8c84141fbe4d1681fa71b51f6c10360db7affac989274d23";
                sig_s = "6772ff768ee6a3edaf0dbdd7b5c6962c2acc8cb14e6347631e25940189729468";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373036323131373132"_hex;
                sig_r = "0a1e072c48a62a583bf94fe63809e95f3202176bfa6d28de8f75a4a3256ca21f";
                sig_s = "9514a6e5b235c29152561cc9492cf47477a0fe23f56040d7206bfb4eb3e18798";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333433363838373132"_hex;
                sig_r = "02bcbd38a3e3113445ad2ee42faeaee9fed00277e0b15521329f4c27c963af01";
                sig_s = "06cf399deb1f6fd692075d236272b99c3336aea2cfac34d904646cc1daf54de6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333531353330333730"_hex;
                sig_r = "62f3a6a9c9f457211b46b1ca3a782f11f44cb9360bb30702e67136036ccba39e";
                sig_s = "22f02e5f647ceb3d0c49f2e7ac9bbb31b7e3ae29a5ed670c96cad6d0f45df389";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353533323033313236"_hex;
                sig_r = "23d679aed9066b611820a8e02b3daa922b10d5596c8ceb7bd4e4fcd6e5e1dca7";
                sig_s = "9626e1d2205d60e39b633852f623f0f8b35e44797e08c6fad196c33be69b5ac7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353634333436363033"_hex;
                sig_r = "0e4c5c077f14a4db197654f8081f10ac2229e6f2084405aea525679e592539a9";
                sig_s = "1355d43667402b9f01959140c414f18d908e2559e57adf35ce794dbc8e222006";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343239353339313137"_hex;
                sig_r = "3246b33954cf1dd4a216218d49b14e39db82004ba0556fb591357aff76a1ea63";
                sig_s = "5b5fcb726ebf18c9151a26a5b0800cbf95b5edc084b42dc6dc7fbb9a0aed8425";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130393533323631333531"_hex;
                sig_r = "361a8def874057c715423843bd7bf0775ba6366fa48ca83e1cdce206bf94c2bf";
                sig_s = "365e97493d3382681f1d94657e9888245c9b0762ee7f4ca02e738afdbba274d6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393837333530303431"_hex;
                sig_r = "2c5f51bc91969fd5b804e751323fc80294b0b5b1e20e195ec9bdc6a7806da13f";
                sig_s = "4c246c949bce43d303201fa0d989e70674766555e8d3a99c26babb658d1f7db8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343633303036383738"_hex;
                sig_r = "a9e3f1e83108be78668d4bac7ffb2918d38100ba01f37de5b923eeca07cc05e3";
                sig_s = "3f0d81bcc08802a435599759f51c89f816742710885b4137758130e8acf707d4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39383137333230323837"_hex;
                sig_r = "959e9811bb18b4865fde6d5f9c246d67e48d7a5c7ce46d7afb6f5ec0b26d5060";
                sig_s = "0091a097618f2517ad6dcf49bcc208e94cb81af87f65b7880580f99858a9a915";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323232303431303436"_hex;
                sig_r = "4f9231b1cbaea183ed9d8591ae3e9f0439201e1067ff00535a415396b77811d6";
                sig_s = "9851c799a311abaefa08c412f6f679a000a6edaa005d05f550a62ff9a6a1a507";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363636333037313034"_hex;
                sig_r = "5479acb76c38d47f21940855f1800978a52fb10b7cc9b07caf88af67f2697143";
                sig_s = "244f3cdd683555b88a45e975073735d38713da4bdea340b5fb87d3c443adb0ee";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303335393531383938"_hex;
                sig_r = "14990149d3a8f3c96e9c62952f90ef21cbcc0d03da802f72432a041da54db5be";
                sig_s = "87427b96d28499707a6788705cd8a5ee9fd42e2d1f1273752337efcd06aa88a9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383436353937313935"_hex;
                sig_r = "5bb244b511a9828fbe7a041af341a93b242b513310de9f4bc366e18b93a3ce34";
                sig_s = "978be5d58ce70c92dea75ce2f8e88f093f5e4675e750fd088777a7411526c1f7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313336303436313839"_hex;
                sig_r = "070e64f4d19f9fd9a8d3f0a64f951c41db2f0e13490e7ac0b3f6066bc1e540a7";
                sig_s = "835b25029a2ced8df57b0343a2c718db72c2d31f7ef66b230c97d20281d49a33";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363633373834323534"_hex;
                sig_r = "2b5a6dc14e98d2e6c0b627568a748bda04c09500bc63bd744f5dee967db0f0b1";
                sig_s = "3452b13ef8dc01a0b785fbb4fcd057a5880c418427283abc7aa7fa07d507eed0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363532313030353234"_hex;
                sig_r = "1d91bda90d0831be058f610fe3e6451791e09689c52bd466ef74dd85b3cbd121";
                sig_s = "4ba37a9341e5923ea93e357344fe7b73446e207a7e449607b1482c510e93b630";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373438303831363936"_hex;
                sig_r = "6a32e1625c1eb7d40b3145f894c7138d6232a6116d50f1270a0e971e2b7a8e75";
                sig_s = "61b6aae56819272813319f7c214f83ce5fccdb58878d592ab0f4479a52d970e1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333433393133343638"_hex;
                sig_r = "5b7526f09dab248551ed8b1229c2447a4521d2d6e22902acbc176c501f5f5f7e";
                sig_s = "3186552f700d9e6b551c893ed2aed9556b3f0ac2a5e2772f8fb1a184949262cb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353431313033353938"_hex;
                sig_r = "30d0ffa9c2be042ccd2c9adbcbbba22cc044d69abf37eff2bcab91d45be9b0bd";
                sig_s = "482dd72aa3b3f3f2e6dd4a075fa962b8f6fc25e9d32d0dccbd80831acf7595e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343738353830313238"_hex;
                sig_r = "200d3b5f915863ada8c84ef5eb50ecf0ab43e2bac10a4c42cf3719121a8d37cd";
                sig_s = "9d137e11a050bfbba746c19ad5f7195c86f24115d1fadfb19ad2cb5624126cda";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130353336323835353638"_hex;
                sig_r = "4ac55470789095e9e250332f3790f865fbcc58934588c774babf22de6a8a6958";
                sig_s = "2cfefb0e2be0542c97eb61914f23fb37b58fb17d0d6b766a8f63c8d0dc79e52b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393533393034313035"_hex;
                sig_r = "908c1e6da625879fc116ddb65173b9355fa8eb038063de2cec1934e8fb2bfc27";
                sig_s = "6e084ff7c043edfb161aea2605a111cf43d58388e061e8019e99526376e4c71e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393738383438303339"_hex;
                sig_r = "97328e1050fc2d44ec89836a7eaae360d6f9d996855e8b144d0c273c4866d7fe";
                sig_s = "3919d7ced9f3e3284978546394fbb277f84d26598dbe83da4ba7c1de372b3340";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363130363732343432"_hex;
                sig_r = "9881e8f75db8163d2be1fc11491926c4125374440da94750a19ecaf8a83b71fc";
                sig_s = "4a9a191a9da8fa3d5641cbb5a88cac5b3780fbbef8ef1a445782394925efc5b1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303534323430373035"_hex;
                sig_r = "70cb8bc7d5c372c73cf36fe69aa1a509fe0cf2be642e085ac979d6eefddaa9e1";
                sig_s = "500402f496dc8d904c709695ff02714e607c4bee9d064cd4654b6c466f4010e8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313734343438313937"_hex;
                sig_r = "39c8f870185f87957e009d01e52fbf6c7ae50d734d39ec4113b37b7bd1b68066";
                sig_s = "73d6da2b777ce0c43d49080857c6ec58546fddf17d2676f10f88ddc900ca1891";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393637353631323531"_hex;
                sig_r = "2e95b702ed138f42614f07a1b21548ea1d247a4a7fd765628bab68551129ad38";
                sig_s = "2e9a6af078b51812ed71b0eab65350cd081f7999a24a56e96af9d5c5f6bdaf0f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343437323533333433"_hex;
                sig_r = "5837b687f2128063dc67f512cb6670f122b611257f536d45e3984f5ebbc3cd4d";
                sig_s = "6a6c0c41b9cc37ae02c2218d3b8cd80cd3c4fc25771c0caab3b8ed2c611cf7cb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333638323634333138"_hex;
                sig_r = "5a73c75d2b5c48af17b7847244262bb9b2c3f2697a9d8c605758a2d33cccd18f";
                sig_s = "97f12aa04b2582373f9bea646bce1b129030ea5f35c9dc2a149e90aa3b56345c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323631313938363038"_hex;
                sig_r = "32b603132a96c5b957b08c88532e49fcb73cd7c5f71a1e6ed14a5cc1776d2da7";
                sig_s = "93be0e4c9844bec9d2b62b424e618a845a98537b2356c1f473bba13b08458eea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39363738373831303934"_hex;
                sig_r = "9b76b7aac0a13bf217f24d335bc04694ecdbd5acfe4ec23c065efeb7936a1c62";
                sig_s = "432cde74fdbb4f5437cdeca53cb7ab79f692694f91ed3735fbc4e08a3f527881";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393538383233383233"_hex;
                sig_r = "8f2565b517f62a3b1e19b0917ab2b223fc8193cc0fdf3ab9692bc42cf40910e8";
                sig_s = "1dccfbed8b90ee5391ea743e35b60ed31d19edfbd94504badca4aa4cf2a7bb31";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383234363337383337"_hex;
                sig_r = "31c627fd791f734421e5502618aec447c67029b2794ee12b08eeb6c59aedb3ee";
                sig_s = "08f91f3789bd01e5b9d93941cf46698d5e1a2708e70ee9a226e81e7f4a414e9e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131303230383333373736"_hex;
                sig_r = "6005293132d7eac0e72b9b218d03212675d5aae0da97bccdf1a5ff784de5cde6";
                sig_s = "13a155c74a9ab27cbdf6cae18d4d1f18b8212d8018551e2baec91979ea5b4c49";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313333383731363438"_hex;
                sig_r = "3a6dab51ed9027f5cae192e0586a32c8ef2276ceba3b796059dca135e361795d";
                sig_s = "4bf16b0e62e32a945088f55fb428159af78296dd4f8dfd9713bdb2f677cbcd12";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333232313434313632"_hex;
                sig_r = "961de77ed9cf6170d925c233bd3e20eef9bbe6d6c8dac28acde46011f99f8bff";
                sig_s = "977de04779ffe3afe708d81ce8a1ed6c7d2a9a25ef9959c7a951a0555a6d3792";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130363836363535353436"_hex;
                sig_r = "778581b3d4030031141e555fa1dbebaef0eed019e0b897b5076544ab80498b9c";
                sig_s = "7132c8d109c1f1a6c10f81e9fc11adea4b9cff599208b6d9cb4e4b27f1972846";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3632313535323436"_hex;
                sig_r = "9eeac8f07c40cc8ee3cba107af49d526731d8b7c70130cbb6efa3c61505d6337";
                sig_s = "62db38226b71f64a5b598ab7c4e3f89880fe0d0749dfd5c7a38a3eec3c793876";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37303330383138373734"_hex;
                sig_r = "673d41c17e727f0125175b2a9f0561ecc5cf9cd49035828ba7c47545a0b338f4";
                sig_s = "00459ef978e7b03468c80fd4533a334755a0826bf5a30df919129e352d347562";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393234353233373434"_hex;
                sig_r = "8a97f19b0809042cdafe9c32bc0b0b01218a49867a6882d64d5b7bc255eb773d";
                sig_s = "904662b5dfd8cd94eaefd57e5d4f2d14268e1b8c4fbd4ac4e5080f79d53fd24c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343935353836363231"_hex;
                sig_r = "287a88bdb561fa2785ca258663f86d3b07aac949f647ee572621b0b70eb3e9ca";
                sig_s = "4a6d7916418443deb4c43f5c69f6490952cf53ee69eec1ac69e144b8f9e26307";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303035333134343036"_hex;
                sig_r = "250db6a8b3813b13b6fb7bf19896f13a502be453c204e6a813a164dbdd9c66ca";
                sig_s = "1d96683ac97f5874ac9538b57bf1eaa50a11a33e9abb825d6b7a7546a698606e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303936343537353132"_hex;
                sig_r = "a29b2c4be50f1724a1ce9acd4c5129b391b4b9009abb582397a522c771d54abd";
                sig_s = "0ec1d7aedbfe4e743d7627ea8d207c2460ae4c9f2134b0f84a0255205ac23482";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373834303235363230"_hex;
                sig_r = "149f0508aef9fbccf32e1bd3199d630240bb6577593e87566b0a14a5b6f20999";
                sig_s = "5d37b409c01fb9b6cf4ea14432c35631694402d2875a301d761d81811469628d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363138373837343138"_hex;
                sig_r = "6c9b110d8e4453d82ec51a5a691b152edf9fb1a9947bd001beb24d56f3bf27af";
                sig_s = "2a80bbd2f827cc23157526df6ea4e0e324b765a50be77f7e9667558a165eb692";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363432363235323632"_hex;
                sig_r = "9086a5c93823b1df21f63951ed6e707fba0d899eef711100e32f2d6017da6590";
                sig_s = "1f831ed30c129dab4266272e01283210ed823c55907ac5ecda85d70bd80279c3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383234313839343336"_hex;
                sig_r = "2af63547dc5ffc8ba4d168d368d9228132a0efa20e3255c332219feced800395";
                sig_s = "3642f53ce9521fab754be7711f00af7888222bf2bbf1ed8995e03b55c98a6022";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343834323435343235"_hex;
                sig_r = "91e9acef9bc28c910891b80320af3603c4306174f17e97059267fc817814ff1f";
                sig_s = "7a9c833beb73bdd62df64952b4c848d2180fae385f8084f1fc5b1b1c64575007";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b402a9ae18fc1a87cda337483900499fe729e471607671651a263fbf0d93f78", "1ef9b0f98fb73bcb605a7823a427ea5f0d98788c7dae42a04536202022c021cd" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000e2027b801fc479308ff5399a8825fccf";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5376";
                sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a4";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "40a2df0f17c7873459d5e9ac11fff84deb5f40ff9a52df8745bb4770f6dbf581", "0099c2bf4920e9c8f758c2de69e42c1cb77c58425a9dafa41d7b0873efa894cedc" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a3";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009de669f9444da82e429f842f31c64418d4d7b05e93f41daddd09fc181ac227c6", "1c86210e8291fc5ae30c72e2013ec22bb97d88bf376d4a85dd1bb71b22526d1f" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "4ab8de0a51481bc45794b924518f2dd6ac5cce31f3228d624c5a896f79a2d6a2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30345b6451377b78a54ac6e110f50c7de71c2c760278373607722c53f5867907", "59acc40014c93d4ad44778bc1a44ebaebe1a97c88ad11c1025057b6bc4377f2d" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "8b1b5f89f5bb74caa42d36e601a9f3c20b4e6c91ceb98a52fbfa9f81781b8a17";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "149d893f1306fb253bbf3a8691aba8a50002b0a27693aa97435a7b5cb33a55ee", "24b075fcdbc1a739f2f492dbe4799474ee3ad3804447e7d584e3430ce15a968a" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "156e626649ce8236982201a24935fb3d36b0d73041b6fdca97990a8d152efb8b", "326f4b20a0cc4623b02a6bb17114901a01de0df1716d669d253de440cc8f9cdd" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "10cc7992ede28c7b4dda5c35cbd71174918e83adab0342cc3d556a413b4ce93b", "3f9c3b38aef0a0e687d7ee6afde70d47d6900ff0ce62156e8645b8103fc66cad" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "77b640fccd8eed0fd78ab7c8fa397e14383cc025f93c6f0e6bab22eca761e6b5", "7dfb114ce223f2af64e7fee5f85b70b14fb5b5c1f3834ded78a4628f3584034b" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bef8f57d0dbdbb0af035d2e4225f10a61fb97c763f9a4a8582590f495d1e94a", "4c34e7550bfa94480c4919e001cfa53f08a1d2f501dfdd5f2da16ba73f587c25" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6db366ee784b945641ae1fb3c7774b81de9fccb6ae3857ffa9df210dc31b78ac", "77f473f0c55c1c5476d72d11dcd872e0993fef11a4a0078d6064001569d62239" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a9";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000003";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3a7953621ee48821323f3e15918e3d9bcddb5517557f61cf2ef25ab5235e82b2", "5d135c315cd4bd43ae7b97d314dc8aaf76ac84e88622f1bbbf5b375e494d01b4" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000002";
                bn_t sig_s = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82975b2d2e";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "113489555bdc112352b08b7ffebcf05090f94da62367646b2e03a3478863914b", "4b4a0a435462a122f6d9ac801319bbc6d2c59228861a3414b500e5cf5943c964" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000101";
                bn_t sig_s = "2827370584fdeb9f5d5a9fb9579a09390efb6f9d99b64fc188d8bce05c2d4eed";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "34224746efa8c5d4f4c6b82de4d76d3e7150c1b69e23339f098ff769bcac94bf", "0094618e3624a57d48d19e72867dbc191a0fd05cf6f4b5ec497b797626a57baa22" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000002d9b4d347952ce";
                bn_t sig_s = "4937a087731df4febc2c3a81ddfbab5dc3af950817f41b590d156ed409ad2869";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6fb0cdf3b08dc5d8b7e5259c7d1bbd31a2235345b7b445631e894b567d23c079", "53243207df5c446011c1cfedde6e5351958affa8f274fe5af435759de87db343" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000001033e67e37b32b445580bf4efb";
                bn_t sig_s = "91827d03bb6dac31940ba56ed88489048ff173f0bf20cab20dcc086fca37f285";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0b8d3bef12ebab43f2f6f6618f0843d5f45d97874f26f9a36b788cb7a69ecf5f", "00855588c99b3839ca9361ddc77645f7592ad371438ee3e186c74081c481dd5295" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000101";
                bn_t sig_s = "3eb35fe7e8331f71e4c63b45f349a99d47a5e781798e579f2386195d3827bb15";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d24985342a45a55fd99e47521fe3e991b8a1d376fa73899d3bacc067c12ee0d", "6542f148599fccb99b1ba28d3805814292a99bffe371df277b09e8ada1253dcd" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25";
                bn_t sig_s = "3eb35fe7e8331f71e4c63b45f349a99d47a5e781798e579f2386195d3827bb15";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4125e46820f41206b670882a9d8d51b6bac39091150c9cb33b6d009e0cff5223", "65749240622b40d70a63407952c1b8761c9f8e85aba6f03bbc7219e24e6fb276" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e8297485628";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43e30112f72779d43e5cfe557a2be4297d757a15f2c3be2dad2bfc897728b5d9", "0db20b59c22bc83b6727eabd87a06fcab44fe828f3963d8b72a21d8425d308c5" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000009c44febf31c3594f";
                bn_t sig_s = "000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "161aee41ce7304df1837d010f42acb64f9a46a8f20aa66b9f7a1aded99f10c5d", "222dea3683837dba9f44a9fc7fdb6bc731e4b7296ab3ef5d3c7c5d3bb7446e85" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2a5d4cb811e3e22db26027f53ef495d270f5cdbd939f919f10fff6096c9f6125", "008ad926a15fbbed68201d6fcddf09c79d2944c3cb3033f9abaa3e6750279d354b" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000008a598e563a89f526c32ebec8de26367b";
                bn_t sig_s = "0000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0790b8083bc30fbd4012743417f221b32ff620b276b77e298d8f20f9c9bf035d", "33413b1798fd8c22c46b23d0fde70492c582dc9d1dd4a836f08d815ec54c54b1" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0091ba1706a19ce58faca26366dced293399450efa488f2c4baa95693b974d075d", "5e8401565a37b05b9351e408af542bf0f7957e5eed182afeabeafa2bf7bbbb47" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                sig_s = "0000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0082abe2f6b8150d11478d0014f6bac230f8396fcfea4ac5b6693189ce342cc006", "40252a7f09dc8b0ba0a8b62fcdb00e8ee1bb65c2318a30cd294f856be9cbb639" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "253f2522f5ea35c8d48a5aa79ad3da0af8eeaf1a5e0aeaab295494c94bb615b4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6dc1877977bdd7a4298ac3509598b772a2a6ba6cc5d57a8269dc62819787cb30", "1ce6111f39c930b0d5c8b51b177109106ea1ab353b60034ea08170db6db48a7e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "28d6daabb1b474bb9f4520cbaecc882cd23bb1042fa657473fd4078ecc80f7c3";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008518d47b08a0d7d81bdeaac9092248d4cc562e129c9e004af6384a17a8cc8571", "47110a4111943d1065648d047082770366056bf72abe2f41fdc2cced271c6cd4" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "43afa375cba6e7de23eb4f70f36fd9ce3b7237e43ceaec1fc2fda055ca9871f8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "163c16600e97ab9d6bfc1d5c26b7a4d0024039894449049bf2f275de58c88920", "363198ce524d6c0abea9c577c1fbe84b15ee5d836e7458c1e361233e8bb73ba3" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4b57b5f040bc7fdd6cef6aee249d68f7ce2bf021fbfcd360783dad600b584064";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a6aaf73ac594c2ffa8cc1eaf1024d8bee42d6c3684654424646e5bfe458da304", "0e60dd5e3ced1d3fdb3fb13503162ceeb0a17ef3b53d3dfe7e95fd056931b3c0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "21dcd8dd48892812395c8974ecd00c8455842e5181884da6035f353dfcc48d45";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "54ec5794ee0b9ae31f46a1a7515c6e363f310cd1d457fc2734c4086986738e09", "008421f0151e38eb4c4522e2b19ff8ce7735984038b46d4cc8ebcbff12046e1bd9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4c89edc4076ae899f22372689f25460a929a44aba87c1e51070212564beb8cc2";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "333a60a99b382db8388eb95e1c67847f2548db83d1eec6e67b1445d4df4ddce0", "009938281530fdb420c72849bb98ffa10f755d1403fa6658c0e982d4d1920c4d22" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "231fa4702f31c86a790dcd5a013a757ad954950b941a7db865106b6de48eaee6";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "183b1e79350ff450b1b727f58276d733b0010793ae3472e47cb566e0c6dfcf88", "2209e1b684d658927217ccd01d568dc6b2f0a4edc0d4b0c4c0fed5d90c021f7e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "3f9826b90802b2725f4f7be70ded05d887e98ea726b3079c0898f078b81f1e71";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43b3f86154e15185cc6e12ebc1b3fa5ce417a6d919bc120fd5406c8493b93b79", "00927f0717ae132796a1323250b05e87ebc71ba0dc97ffabe83acb16e422834424" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "4cae4be89cee15d91fd495d8a91dd90ad1160236a74d8bbe0f409545042ea5b9";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0080c6c9bddbb9d6e6a4dc02560985fceb25adbda24439fca562c829b16df20403", "0099e67b5d696de3f1d927023dccb97ea5c237282edeb06dd59e18f4c8eba44047" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "328f4ed5ab79a8a1c901b906a0f55b4bab77401f58db4d555db7997c11163426";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6e54d8370ddb4d70d5d663b3083f0cbc1a30d29ae92a845c678ec99bdebde6d4", "2885d710b3cc0ab3f7c4e770c825a50b945d20906ef9e24038400a41fbf5f44d" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "310c2a34ac6ab050ea873ea26aa298a5782473469033e021f5e1c13ef0630755";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "249a3f311a48b9ef8eb20cdf2376a345434977638130f3a5525f594997acd4dc", "73b3cbf0bcc5c5e90549a02b4c78ee5585333cdd2419034305d3f0e617779ac0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "241166115f5e25e286b882c3e39558df1d1e6ef90551115118f6251d3a566adc";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e95cd0da49750be6a69800e80d7304ae5d18b6203bbf9dd28ffaafd292c6ee5", "6c0a500759810462be9e5eee8c2a3e4a25a6f5b813a935cfbdd75cb0869709b4" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "204373ed57d86a4103e275333a16ff216ea450a5ef3c2019e9351a2c57466d6d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009acafa50929d5ec370f5146373d6eae8c27e6368dc2d61c3d9517f7461c77c15", "008bd7b63d7fad07517593a309e6521300f4537d844b7cfcde2b9cc4951b82aa31" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "1804472a04273f8341952e89785cbc7fe86f74edc780d1e89014dd6d5f6f7f37";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66575bdbde4ee69150393d008663f6e665182997d0e64608c6c95713943695a1", "2ddee0c32898da02a9feaa261982be986df69d334d94e7a4e3e9c1b8f648efbc" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "3549f9e472cce3d5a153ad22dcf0b11f7ae5090c8ca925c9897e89f3de070855";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "25d17570e4bae1e468e6dd0975b382368061e0c704241c1d18fd5baa8ca8dc13", "5acadcd13992f6665b469c9f9ab7797e3c4b881c6d7f4d2601c96a1536f76d05" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1dc3325ffa55e179e2171a66b2e7534ae12cfc292af2e0fbf1c3fcce5558fc6a", "2420abcdb7df8cf38634648264a681d5ed195bf16a970ffa68ab250b34a93514" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3fffa6dbaf667b0a94e5f86b3774b975971a4d2439607def4e5de1d17820a3b2", "1bf36613b50b925264551815c5da783bd158aaa1c6244b40a9fa31a2a433f8e8" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53";
                bn_t sig_s = "54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b54";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008afd47eb0667860bec98d5dcd2f60da9eac1ae99620569892f14e094d635872a", "5e8f0bc67b98a233ade715c04d9daab11a27517a92cf2651c9e5f2fde4e2db98" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0876616636a8dbc82160ac01af2941353ba0eea4a3b8fe31696b47317d4972c9", "23180073061d27984ecf491f394004c3a4846d773f58dc2ab5e43dcbf968d027" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "989c5cc31440c1168f88b32ba6e47900183c0d843f9c41671898030664305d2b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fabb052217eae8e63fea4eea09953d51862427f341307d819ff6e933bf72ba9", "4b897f2c4a4cf57054c363c720da3d242471cc8e493becb0de022251d2ee4c8c" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "72ebad749b504c874d21bc5e4bba545dd42eb5fbf78af42043f5cef10aeb3ad7", "45227464e1e9cef662f43fc80d4ce7eb7eb615a23699d48e89b278abd46ccc46" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "71523a926bf4712829995c6069025e4bb2d0fc6d23966f4fb5695f01ba3039c5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "744e218a04b31471b05e679c9481446bcd72a4d0fca7a7af1a1fe2f574d9362f", "60c0c52843d8d72cd636153f0f510a09089fc4478372dfc50e5b91d5301ba75e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "05ca53b2d9e4a2e1e4f47276fcdfb17b26a9cf0a7c9721dad28203d41107fdd4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7ea53d3c4635a4d5b60d79aac79d974c759263363472146a4605280d935ffc75", "59790403c96459b20477eaa437b3c7decd5e690faa940c0891de0cd07d41813c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "5448aa82fc57740b2e1ebdf989baa145b018b423b3761feb055959eb6a01f1a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "750462a163655746af66ba3eb48009a490d970799280586cfe59316365dc4ef0", "00a2f1567257bd9aa1dcca3cd276ffaeb1dd85cea28d888a98642bf09a98f69f11" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "65bfcce69b89eff545fb0a67d2581a5f253484ef538b9b55fa862dfd2d488d52";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "323ae5754b417552cf968f5f3eea7187f7b1726e8c2e510f98d26430ac5849bc", "327101d82adf87c932e8eaa6a57e1d11bd65dc8f404c113f65abaa6eeaf5c7c4" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "7a459e047395d81d3b00f4b8d5ad34442b35dec5e6c1b45a0678e65a1fe9e9e6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "37a105e3ce3fb636733032d1ca56b4c659b451f64f4ba7378b087987e7a544d2", "782bad9b1654f2770d7a3ee35b672a366f685bc7191889ff2fa5c6b94ebe7ab8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "3b7739bbe1048b69fd05f9262f628e03b0770e7ecd82337f1482a72db0293232";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "13dd59454f6af3e9db115b7ec8c3a1c8d308fdcb4963c3b8ea1264e4afda652c", "5d260b7fc9bfd200896d229f3c8daab9df2f55aa9ad95d4ea76aed8d74c5494d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "76ee7377c20916d3fa0bf24c5ec51c0760ee1cfd9b0466fe29054e5b60526464";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2c1dc56459bf09df50fb2d962f5989f3643021c5c360363e10e695a70b5942e8", "6216d3ca0cca31dbd92a4d28bf951437f6f45db41e8e41fdf72414a293f53087" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "4a992824c737b00f02d23d2f2e3decf090b28ffa0e90e6d1e5dd157070719f65";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "137d6fdf836b1824378c08b35fa7ebe4e807d8a20105ce9cb3cd281f0a47c9c3", "07d6475d4958c16d950f0439d3dbf86c2d7e2b12e8b137efc62dd1c723b83a62" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "9c092d165ef1b11a82b59c73aab3496631e3032038feda236db7b0f5a8e0cabb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "640213be1698b166f0c54e588e1b57a64826bf848adabfef60681d77747d2ca8", "646e45d961419d4ad1338c361228e1c6b6615398582c0e3e97f7ebc85a504423" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a90449e87d9de3ebed92a227735e45325b1d2d774b4876a86d0863349471ac59";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "269154ca58317552c655d2a9b3804dd94c2711145b9cd93c360f2dfe34cc1971", "0098046cc90cc6a8ac48ef7bacc5cb7e57334fa91facbadb48952c9fee543d1bb5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a4310428c80a06da59719819a0a3dbf6658fab9938ca851cbd9c0aae864058d3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "240e0b64cee2e0b8890c2fa82de5848a5642ef0f7b2414f88f585281df7a1ff5", "3a5990f860da3053f821bea914059ced85c9c2390b0d860532dbccca7ff66692" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a14bda4f5b17b56966f75ede22340338d23ac413fa7ef42f545b08c47dbc59e9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0096f3cb5eb0c33be205ec058a22093d739fe80a7ecc874399c14f7f6c38cfcc51", "47b3eccaecc9add2b1dffc988f13dcab15b7e910d0250e70a1d79b3b931c32ed" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "32dfe6734dc4f7faa2fd8533e92c0d2f929a4277a9c5cdaafd4316fe96a446a9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "103b1bf6343d57260f652d272aaeff6cfa439f1583335eba66fa72d00eff7f85", "20f2bb035bd056c67ca22ca952abb5e1bcb68d67ca81790d24097f13d45209a1" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "6353c7f3e0a4e33ebf7758dadf2bd9d0841328e13c75e252855f5a2b87c2c78c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00959b3bf372301993b37e20b4344f13c06d5c1c53c7737f166efb94832c3b9bbb", "40d35ef46e4cfad475ddd1a1d9609feca7069712d30bdf4638d4c88bc9a12100" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "14899bc6ff5e72338f3c9847fa6531c4337fde3fcf1c8c32f768fba3a402a964";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6e69b17d83894e2e71ffce351b53459c0bb29bec379ff435f23c01a9b37df49e", "3ba1053ad84236d82cf7c762362b37b24e3b0ee1f8ea6c543a2591dcb6681a8f" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "72655c5e4f1cefca22f413a612e5bfdd7ba9ae71053f68b0c74d9a73590013c3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "336fc28e1f250485276747dfc34859b4741667b3ac46a0f6384decc1ac790304", "401206b5508aa06601a2246e7381dfecca6adb2b197ae14549a24c355cd53be1" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a2030dbf01d8c9de2900dc3845fda4e4c6bc049c4cd5717a9c629b9ed29d1859";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00913d9ce35b9c73203578e255d4dd35ff20212d357227d26b8a959180665b542b", "00a503d922d3fd65a07eca18c0a4e2d3f2cf7c05928b406458cb286e11dc62dcb6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "a1db7293b6f01594b808718e61a4d642dff4fee2fb471167ef7ab42959a473e7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6b76915cc1c854744a78dac9baecd59845b90ad9cd308f5a887dccc909dacd4a", "7260456f8f8d31760d81bf85348d9f50c99d9918b480b1ec25f4e2e34de03769" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "99bb8d4bcbf1816d31aad88c25c61f1433b08322412c7bd84ed759d01c009127";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "647b37b731d3ead759762751995483469031084cd709887c9b6bafba462cbf84", "00888c5b171f2b2fb7bb2b9d88200d79ac94d7d4025f79348e2283511c047891bf" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "41cee82a6957ef02ab3aa07a3315accc0d0d66c2081d530246d6e681873c90d1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1f761a1ae1e82e4af277b399da0a523e85644ce971c7b90236d03115aed9855b", "55cdb3e104361fd2e0979863f29a3b0bf5542c5105c91dfc7c94643b78a2b7f2" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "746d61572ecae774691e7809121986d9b93279b00934ff1def1f4798da89ad4c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "63d303162574962899fd9a323c5fe24a09188fa20d47a8d92ba502d4f886f5b3", "72cd0d82b3fd4f54fedc5d8618b142f63553e438cc1269719dee3abd3316fa21" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "281b26a0908968099f8e1f610f4f358318baa21107b791ef6f24cb244677a64b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3e1d966e05f04c44e162133d97730f6408a88ad990a2c6efb7e3e73a886f7ed4", "00a40e3b3fd8b005fc417437f21011d9fbe38b329a2e7959ed9b040c8e1eb677fd" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "46a78fe7c149c67d7eeeb1b5be57b3a1082651c278ebc4a50abeb4570f858f1b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56ac8e49b319d5d041ae3d3f91de229c0a820d7ffd97ea06196eee7507363f42", "787fc05eba606f77b984e57cabf911209700b5d39147a14c5d1a95f56cd5feb4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "14fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b55";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5e2f228631ee7f00ceaf936278f2e2681b429fcfb8cb2c019b31f188839884f5", "30e1079a6b889393cc83fabbd524f21bb486c65b83ab0afafb17265d971bae91" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd";
                bn_t sig_s = "8e305a1cf885ccc330ad0f1b5834a6a783f1948a5d5087d42bb5d47af8243535";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6dbc5605b4e113932fede7b4743f4dfc62fdecae16735b51653d79ee008f2fc5", "1288fb2ca09ee336ef316b73919a7f3b329fca2f5c365cc427425fecf64f7bf3" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "074c035603e1eb49ab5382819bf82af82929b500c6e78841c1b2c3ff54a615dd";
                bn_t sig_s = "2035ac9ea7119e30e54f369cd22aa27af38b566ae6093f1df35b612de6f07598";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6dbc5605b4e113932fede7b4743f4dfc62fdecae16735b51653d79ee008f2fc5", "0097725caf014fc6854f349f1d0be90e373b9c2bf478efc363f8d0e830291ed784" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "074c035603e1eb49ab5382819bf82af82929b500c6e78841c1b2c3ff54a615dd";
                bn_t sig_s = "2035ac9ea7119e30e54f369cd22aa27af38b566ae6093f1df35b612de6f07598";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008c5635eeaf7e994ff163ebdc9aacfdad1d50f9929a8035c36cf1c1e16d5b28f1", "3de48431f3eb823a384c940b2b0a01512da98b8f72bd9545d179d6f1cd5a2a63" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4487";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b9999cf86f15a7471ff8d212ca3f9a99225851b6d9608034ce0af55fd539b5a", "25d1d06449a6a9f4db833ab69d1170b4f0f07d2e5f74a9b56212563a0356e0b6" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008d40dbb264923c02a484fdc7f06108c727e5d18172c909f79a3845485c939f45", "0094dd7b7c67653a712074d94890a8eb56a7d4b975024d3c82a1151669a6b83821" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "796a6353bccf0b8675b699d502cbae2c88bb5799818ee4f9f93a0a5d477cd02e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1fb44c46fcdcfe8e37f047bccf57ba1890643f0033d492c4b197ca7057c86067", "763f1041f8c38be3ad20945a6f0fad6f530af96fed289b4e8f02abd80b2f2d83" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "87fc46494e5887c9cb84d5407e02d78e09c7954fc44e1f2c734b3ecedf6d121f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a42aef32568d8451e187a9441a6e886342d0033b04aaa4ddbd4d600c6a5c86a", "00855fbb0861c7a642333f3723c6c3dd961f279d9943779d4c237deec94bff846e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4488";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "67f999eb1a40fdda28044d2af23357aac045172ef1e89c6430a68deb0a5e2c21", "550d93565dfc6a0c5b5cf4e7d9111bf4e31a0d0f94b8adfd9b800c5b38cc22b0" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "3090f487e51f9e35c8af70bb9ab7df45037e230a33d2c1fd96e404254fcb8679";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7cbf2bd2c89069d23ef7417cb783dec50089b3c45573ad00e1214b0c6f51ced5", "6ef5cbc578da2f35cd8a43cf01a7078841fffef2bfaa4b931920ada792019b29" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "743cf1b8b5cd4f2eb55f8aa369593ac436ef044166699e37d51a14c2ce13ea0e";
                bn_t sig_s = "77472d9a28b4ece71cf413a68eac0eb423a16fb462b1f48706fed48ca437bd2d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "33d4259f3ac0ce8a534e7655f2068f80f401c742ec04084784d269c49ef0701f", "3e1dd6fc7c206d4d759c80e3612da4d0fcd4200afe7a68300e9c13f4ef23f880" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "38a91d4935fa389414ccae3034812f25d9687e3691cb37a7dab4af80dd181ce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6eacd3ac7f7be63942b897b75d2826210553e1973a5b38487531e0db4a8418cc", "6b781f1ec2302bf27f8c4a46c9179185b92a53a28b85b3c64171139dede35a05" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "796a6353bccf0b8675b699d502cbae2c88bb5799818ee4f9f93a0a5d477cd02e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "49680c57a9644af8a3cb5d60f33bbeb54c910bd40dab3fdb8daa09182e4d7918", "0080fca5d924092c316ae8266b2a32b74f186f6cf22c29520871fb2ad2c44ee71a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "87fc46494e5887c9cb84d5407e02d78e09c7954fc44e1f2c734b3ecedf6d121f";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "69566f1e4619346bf81d4b7e76705781ae6a3e8470806ae4f73d53bb03c207a1", "396a54d57b45951ebce9987f6adb457d7ce77c6c3820d657f9a8882cdfad66cf" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "21ff1192539621f272e135501f80b5e38271e553f11387cb1cd2cfb3b7db4488";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "46868fbfc7150d0bdb1c8e9976d845dc4b8840f4d921299b6d8f989d4dce8657", "0083921b9a729e51d2deb5955f4d87cc2b299c7f01372ae82cd63f529a266d4b52" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "3090f487e51f9e35c8af70bb9ab7df45037e230a33d2c1fd96e404254fcb8679";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4ba9ffbad26f909e59ff58118fb25d05e1fd2722cf1b9d88abfeb716c9f5461f", "76b2f395fdacb89f3b85fdf4cd733630403068559ba12c0f438f856286773f9b" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
                bn_t sig_s = "77472d9a28b4ece71cf413a68eac0eb423a16fb462b1f48706fed48ca437bd2d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262", "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                bn_t sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "989c5cc31440c1168f88b32ba6e47900183c0d843f9c41671898030664305d2b";
                sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262", "557c5fa5de13e4bea66dc47689226fa8abc4b110a73891d3c3f5f355f069e9e0" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
                bn_t sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "989c5cc31440c1168f88b32ba6e47900183c0d843f9c41671898030664305d2b";
                sig_s = "18487a43f28fcf1ae457b85dcd5befa281bf118519e960fecb720212a7e5c33c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2676bd1e3fd83f3328d1af941442c036760f09587729419053083eb61d1ed22c", "2cf769688a5ffd67da1899d243e66bcabe21f9e78335263bf5308b8e41a71b39" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "745be1da902d19c76c8f57d4a1f3362b4b20ed7c8de8fc0463d566795f979cea";
                bn_t sig_s = "5916c317a1e325b53735216a0fa37737f08b32245c88084817b468a41f5afee9";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "0ff9279a0775740b7db8bec07f9a0401b7903886cb198c1b18c46de0673b31c3";
                sig_s = "8b3c8686bd1a1508b5b785e762fece8c6cf19b6156983e5c36b2bbe724d6c23e";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "351e727003896ec02949a3cf752223bcc6c2b611b30391edd60dc0c83dc9c98f";
                sig_s = "924ad9dc00364d4aa2091416d173862f9b02965ff176e880ea62a673e16db98e";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "44a811b2321acbc65cacf80d2dbe848946f1dac528f3e1ae38b0e54d083c258f";
                sig_s = "55d7edfaecdda3bbc062d5074e3c3719d32761159d027ca27c1725ddbd62f688";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a9fb57db62501389594f0ee9fc1652fa83377fa302e19cef64252fc0b147f774", "009507acf5b04339ed102b9ca60db98c165b94ebe855d2202e46dce15ba1e028be" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "62aab40a36d6a0d25644719ce31dc629ec684f6f0da32f9dd034ccc421dbd0ed";
                bn_t sig_s = "a1fa6b0dfd9558da29374fb77505ee8ab3572161711f821d11807c7fff910c1c";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "740cd3d3a9cd9dbe05ead4e39e54db27c0f1579da68e3aa5c9245b047aebc3b8";
                sig_s = "8ae78c12233d378fe2ce3c0fb2b769f8463830a71a5e5187c11b20fdd7e50445";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "a28f30245c5fb0c225fdec23924dc2cd4c2da888d1ee1bc5445858c646015ca8";
                sig_s = "0ee364c1491c4551ef3509be8f88db0e04d0afb36528aeda1301b14948cc9cd6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "351a45fb920f2c9f1b178438fa3bf272ff9328b881c477a1f56a8c0e88465276", "1270f806fe40ad97ebf76c6825384b780ae6afccc792b05f2fb3eb7b7fffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "7f202f54f591b51105b227ee6d6da3adddfc4b5e819efc04befcdcbf7484f783";
                bn_t sig_s = "4360ea04503955fc3f025928b2dce50ff2d58b9060b34bbedfc3c219b3b4355b";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "62e218dca32e4ef35692e9315e1e036bef1766073b846e38de20d2d29349f9fe";
                sig_s = "519d4d4c6158d95474d793a0ee9c260a0c5469c5aab79510971b41fb4fae4baf";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "a3902295f6f743ac754db7b3fcd823be917b1191a5705728f5682492784da7f1";
                sig_s = "43def636660eff72e6435edb850c9126c7067938668f249998a0e4006b8ee7db";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0129b2146e36fc055545bf8f2cc70f8e73e8b25e539365ad7577cc3535", "4a2b8c0319bc4ccd3e60da119477c23faf8fc2dcefc42d3af75827aeb42f6f0f" );
            {
                // x-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "86d05b26a9ca7e10ae0681bb4c35a06d7a4e918f8625e3dfa7ac2d5aeda91c05";
                bn_t sig_s = "08c5f475a95888769da4a0e1b635c2292f654f934a5c5010fe0c729f3d11e1b1";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "43c4474710d25094a2e21a9cc08585c26015f9f94012b100e72c0763aa9e0cff";
                sig_s = "8345c46fd5592cefbd5ebb258965c05d964e6e6a278198ddc1e388cf1e75867c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "6d2724167e816528491cce574f0526209de52cd0f2af0085284fd050163d37c5";
                sig_s = "76dd1dd50ff9b553b0e142b7e6c6be8edf3708dd292f03f3e9bf157d21daa9eb";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "680becabe7d7df4fadfe5ae01fba5ea51b76759606a2e30612e667419b885d05", "08541dcb0723785c3c766581a7514a1ff42e4437d63f878271cb860f00000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "321009a06c759c54cd66baafa0cbfd07eedb19f12a1ed654dd52b56f9c4fac7c";
                bn_t sig_s = "1956310a7e4757ec83ddb92d2763607354678149f1ad92387928cf887b4bed0f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "9bdd359881c239e2415ca2af3d18463bb24be53f6f636cbd20360b6b333bc345";
                sig_s = "0ff03bc36cc1975bdc8680c44fbf2aefddf67c118c304b8b3d360eb10203c3a4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "48565eb7e7820d40754b5f264a4ceafa62bf75084241514b491995e7971e6995";
                sig_s = "3da6df3d354f48daef6d078cf1124295fc8c3211f2757967c781dc2e9c62ed1a";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d16fd656a9e6b34e45d8c8c3b458eae7bbc2879f8b4f61171a96f664eee9061", "01469fb456ca6a1720ca8db25d567e121cf921ce13e34000f8c12f5272" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "518e885def022eb5020fc90f4024d87122dc0f3ed7f869ed7720ff74a009fb7b";
                bn_t sig_s = "8a3e26a8cd426d21eba5cd7a5614f3644395cfcecb24fe760a68a7a9e8f09c02";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "04b01e5cc3ce9bf10844bc1cb21deeff6ebc9e2a7010cfbb3af0811354599c81";
                sig_s = "2e65fb8db62f255910ea4d5235bb21aa67aa59ffd519911ecd9893000ab67bb4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "94bb0601198c4ce266b0932426ffd00132d7d4e2de65ef47f56360825f262438";
                sig_s = "2734327d1989c9580f5458f04aac6fd5752a1ee5e236e9ed1a7c0b2d9b36db10";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d16fd656a9e6b34e45d8c8c3b458eae7bbc2879f8b4f61171a96f664eee9061", "00a9fb57da5b4ef56573fbf36fd2f5db1517bde406dc0452143cd347245e3f0105" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "4dde197f962c63a7799c862e897b3bb1e7a7ddfb9ab77c2a17a54151ce604ad6";
                bn_t sig_s = "017e7aef86e533086425a2c4b32082f118913ef3667c8437672e0bbc7c2b8d7e";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "7c53ed1d504ad4ba53d39792012a34d007250a2b8d1ca189c0d9f75ccc9a9957";
                sig_s = "09b97dcc5c67487114231d601374a8364cafa39581291762202b9215d51135fd";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "513245ab2b6a4206bb0f6970c8ad040a94725ddc9a08db0fd9def93866ffbba1";
                sig_s = "a53a7ab37decedae18dd5b5c48eb642b7a9c927e6bcf6bdac3a757e6d2c169c5";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081528b7adbbebf1b6b3c7fa1d61284b07759b9a98d31a5702707b018fdecff11", "75bbfccb545381bf8601031731841829401b08dcdc68cc34e06a64e412038512" );
            {
                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "a50318c3066a4966ad18ae8f85253fbb5835a34b2f9187daac71ee28d3d5d0eb";
                bn_t sig_s = "0890ef0fc93df222d11197cb221483ce897b0cf1acf4a909c306c5a485776abc";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "041e0389dda2cf2ae3a9562a0fb5d41c1f7533e6cc84a896e99af781e2109770";
                sig_s = "366b5d88c36f1227df522fdab65e12347d68eb64f2de82c648115fd565bd37b7";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "2a76394a04ae19b25c54291e28bcd42a7edeb20981b8a3b838f9dd0e29b574c1";
                sig_s = "9ce89980ae432c4fa6a68025da554bf900cc2eb0c66906420d322c14b453049c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3a25a353caa94ac4eed3700f7d56b456a0fc670d56a166d5219b7c97f30ef3e", "16ea8e03c20977f20aed58106b6d9d1085b4475f75b5469c5f426cb27ec6d872" );
            {
                // y-coordinate of the public key is small on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "66958be3379405826a00daf5495b1657698126a5ff449f9649af26ca96df9667";
                bn_t sig_s = "9b4100816e2741f86c5c0b0dcf82e579f4281d2b8e70c234808d84c1a495079f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "53ed0f4b8fb33ef277cdd1060435ed3dec518a225659f71f67f9a1f07f85c1ca";
                sig_s = "124d5f94ddf12bb4cbe3c5cea6d2686d4480dabb8ffbb05e5238c877fe20383e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "46643c7fe0f308b8af4ce2978d797e8c46a7e1f8bfee0b5cdbaecde1f59be41d";
                sig_s = "1bd11a814d1fbd9ae97a49df99beca7fec2512563c0031c5aad5b9fc2fb0a507";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3a25a353caa94ac4eed3700f7d56b456a0fc670d56a166d5219b7c97f30ef3e", "009310c9d7dfe531ca3378b2803215f061e887aec45f70d98bc0d0db6aa0a77b05" );
            {
                // y-coordinate of the public key is large on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "4f833bec9c80185beacbb73b5f984e2c03d922359be7468ce37584f53d1aea4a";
                bn_t sig_s = "6636744ab7fecaa53541bcf5f37c6cbe828a8efbc4d00f6469ba390a86708a26";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "a2869da416523aad2b8fa8aad5c3b31c5a535fdd413b71af4dffb90c6f96a669";
                sig_s = "29ff3e8d499cabc3cc4cccd0fa811cc3b04770aa71f0d052185210b14d31993d";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "63dbfe29249a506b89fbd2cb1fafc254a9582dfc4b08d143b6d25bf2ab49d55e";
                sig_s = "44cad80c00460905e103f26da84cefd71af4bc7a71962a3bce321bc3b5842736";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d499b077ab6d77b244320a2cacab91a764595dd67a7a8dfcf84da7d38b2d8f4", "5994c07b833ff4909c1a92cc9f24dea88be8603b407b00d228faf2158db2354f" );
            {
                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "9d907cf88e10d60c3f23892498fe43ddb02f824fb18e6be313e02d94f2c8e090";
                bn_t sig_s = "0c16b9e0db4dc8606c023b001f69b3c886080794fc9d7fe31b00c1cf0935e421";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "7395ce0ef652848a86b61097cc9543998d39dae88a1fc9e4dfdd696429495489";
                sig_s = "7de29e256e8202382f91c116a667a8b946f210447a57369ba61ae4fae73dd136";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "7baf1fde87ccb1bea0f893b3bfb2549c04bca18835d8eb5a31b8d20506ff88c3";
                sig_s = "289ebe829fefb9ad009d7cdd622874aef5fa088f0508a4b43d5895d61645cecf";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "08c2f95ffedde1d55e3f2c9dcf5884347f6904c6492273ad760eb7b9b35f036b", "2bcf7a048caa2c726ae8808dc95312eb2350275a8f4fbeea7c0f32f3839c7b93" );
            {
                // x-coordinate of the public key is large on brainpoolP256t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "33e37c3b66acabee3d68cbbb9c55cd52b586de51647723fa84e532a3ec5953ef";
                bn_t sig_s = "3b8a9ee707d1bc5f83e17ea072adc2ecda92e637d7c06060f1af79b929a850b3";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "1f8ebdc94ecddd84f90960cc55d0ca02e33d70535fc1c7322b3c2783b9dc9238";
                sig_s = "205aa8626c3a5da214e5485b11154a378d70b0d3323ab868528ae8048d17b696";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP256t1
                m = "4d657373616765"_hex;
                sig_r = "6b0d70e09ba1642adac06dff9b52e22a3e4aab4180e372665691412241e743a0";
                sig_s = "4d7d30ff8a210de69e3e6d1ecf7175f89f481a4d9ed06beaf7148da47f4af9e9";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha256( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP256r1_sha256_p1363_test
    }
    EOSIO_TEST_END // ecdsa_brainpoolP256r1_test
}
