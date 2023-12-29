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
    EOSIO_TEST_BEGIN(ecdsa_brainpoolP384r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<384>;
        constexpr auto& curve = brainpoolP384r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( brainpoolP384r1.p  , "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53" )
        REQUIRE_EQUAL( brainpoolP384r1.a  , "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826" )
        REQUIRE_EQUAL( brainpoolP384r1.b  , "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11" )
        REQUIRE_EQUAL( brainpoolP384r1.g.x, "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e" )
        REQUIRE_EQUAL( brainpoolP384r1.g.y, "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315" )
        REQUIRE_EQUAL( brainpoolP384r1.n  , "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565" )
        REQUIRE_EQUAL( brainpoolP384r1.h  , 1 )

        REQUIRE_EQUAL( brainpoolP384r1.a_is_minus_3, false )
        REQUIRE_EQUAL( brainpoolP384r1.a_is_zero   , false )
        REQUIRE_EQUAL( brainpoolP384r1.p_minus_n   , "f39b6bacd3b2eb7bdd98f07a249d57614bbece10480386ee" )
        REQUIRE_EQUAL( brainpoolP384r1.verify()    , true )

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP384r1_sha3_384_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP384r1_sha3_384_test.json'
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
            auto pubkey = curve.make_point( "6c9aaba343cb2faf098319cc4d15ea218786f55c8cf0a8b668091170a6422f6c2498945a8164a4b6f27cdd11e800da50", "1be961b37b09804610ce0df40dd8236c75a12d0c8014b163464a4aeba7cb18d20d3222083ec4a941852f24aa3d5d84e3" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "1daf64b9ed9a7168b5cff72717d48cd81f01ed3c4b53276cd2e4ab2d2f077847202469b233bcada1fa62938b898a65da";
                bn_t sig_s = "4319e8549570ea906c8b3b8f8167b11f3bedfebcf866c181cea8fd96eaa62d0e492b783cb475432d80c070a0be9d66a6";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "4ab385f21c710db04e0b81a6305bb0fd64fe7b2a99b367439f7889db459b7080826fa42b61b417c36615f322a27bc889";
                sig_s = "6fcbb543f871762f50f722b32baf28a22f5e525093a9fdaa7f200af055589efed307d7c093d8a8325407c8b7d348c878";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "383e9bc44741dca761705b98c7b96f10c419d0e4f098f890dfc599faa66987068825e78f5f0a1e70a25b5dceb28665c0";
                sig_s = "26683ebf6fcd3d3650773f9504969d5eced6a8f13c78582c04970a6f016db0259cfe1c4be2432bad1dc4c48cc1b7f693";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "61b9e34e28a930a97aee912c83e89a4ffb8e8c6e64b2146b17fc621291c2c1ffdab2b1c9bd31d910f83bdd03326904cb";
                sig_s = "7c6e66bc46f10ed74f0a8d1de7b39c9314f7dc8e5bb7debb7a22b19859d47f66a4ae053bb356b539206ff919b1098375";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "192ed5ce547d2336911d3f6cecba227f08df077f6242a9147a914e854e6e32d325fd23ccc42921dc4a7e4c2eb71defd3", "631e69079ba982e7a1cad0a39eff47fc6d6e3a280d081286b624886ba1f3069671ec1a29986d84fb79736d2799e6fc21" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                bn_t sig_s = "7eaa2412f7983858566190c20c141a3a738094348e8e4be6ec9475c081de685886ff9b1d012e7a0b56a1d5d7b45e2638";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c50000";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c50500";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "1871e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae045";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d0000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d0500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0c0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63fad";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "ff0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "1a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "a72b05ba398751eebb9e251adfee92f89c4e3177b4f69d9f5bf6ebf93ea402582a52f7fb8be85b5460fb4b61aa6f462a";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "8db8c8b4f316779e9ce3461e3e220f3a71ef4f63da4df0391dca0f1fe69bb7088bdd8a9cb4e8d533e9eae75bd8667b60";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "8cd39069dacebc0cd609b033ed754a302eb68fca5b1bf8fa0b534eea3896c5847f95cef0b7a02ba87fada51c47c5d045c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "e58e18c869b11b3953bf4a6370f7aee678e13f92385db913c31f82736d60234fa4e7beb3df9767bbda8ce6a13e951f3b";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "7247374b0ce98861631cb9e1c1ddf0c58e10b09c25b20fc6e235f0e0196448f7742275634b172acc161518a4279984a0";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "ff58d4fa45c678ae114461dae520116d0763b1ce884b096260a4091406c15bfda7d5ad08047417a4ab9f04b49e5590b9d6";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "011a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "0100000000000000001a71e737964ee4c6ac40b59c8f085119871ec06dc7a246ec3ce07d8c929fdcb05b18414c206898442573195ec16ae0c5";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "9ac818f24ed8a1f7c8594e3a95b86983b6de4ddf4c1a617f51986718d629e2f71775d241d5d10c15206e8e2e1daaa492";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "8155dbed0867c7a7a99e6f3df3ebe5c58c7f6bcb7171b419136b8a3f7e2197a7790064e2fed185f4a95e2a284ba1d9c8";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "8cc72d7d12e40d5cdf166b5d0d2b1406b9d11fe6c2b31cbdeb48f065582e4b651e82f1cafdea1459406d185f14390ba42d";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "f1f10590545fcb3047042143bb2dd85b5e51232aa139f533cd7e0753d5da42b0b7c4e46d95aeb6fb1b19a3d4cb59c0d3";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "ff6537e70db1275e0837a6b1c56a47967c4921b220b3e59e80ae6798e729d61d08e88a2dbe2a2ef3eadf9171d1e2555b6e";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "010e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**384
                m = "313233343030"_hex;
                sig_r = "ff0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "0100000000000000000e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
                sig_s = "0e0efa6faba034cfb8fbdebc44d227a4a1aedcd55ec60acc3281f8ac2a25bd4f483b1b926a514904e4e65c2b34a63f2d";
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
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
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
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
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
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3234373732"_hex;
                sig_r = "705c790f8f50061c508c15fc9aabc1f58193ab15b394ab2195e358cb620a5bf4b65449afb9c417bd1a3105e53a9742ce";
                sig_s = "0efd01efddc284165aa2ba53b5590f17a188340c619f27419d74d267937e7f3b883589498ddef7502f399497595bca63";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131353534393035383139"_hex;
                sig_r = "565125ffd61ccdaca07b49ac99f3a96b351696f118ad55b8835e8bebb9845c6d41e3ba17f1b43b6ead947aa97a5de1dc";
                sig_s = "54c07b3b304a76841681bc82f946abcda3ace577093adf18d955ad2681307f5b763623e191bfbf578b4e3ee4873a8259";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363831393031303832"_hex;
                sig_r = "05ea63c3519708908e1e679519dd52799ed0b14a9416cdb2d7f52ec86232679d672bc4d1aaf756a40fe56152dae89a8b";
                sig_s = "6494acee7320f80fbcf82b78a834c36daae4c8654a60eeef84e197ab002adfc59755f07f48bd9d36adfdb5caa41158dc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333336353438363931"_hex;
                sig_r = "6d53f8544233998ed06ac75addafd7ce1764b2aab810845a494983ec7fbe1720ec339e7f7e90c691609758e4c12f333a";
                sig_s = "1c9231fd30704345f9e40beaf1ebec9ad615d8623cf45eca6a73db30fb9e2517d5e78ffd6e131ebb4fc19dd1d92cd38d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363235303538313232"_hex;
                sig_r = "13c13d7a66c394a659412e01dfe45ca7782a3bfea1cb484a61c28df44570898957f8a80b9d6523149c586069d116299b";
                sig_s = "72af0fb0998fdf50633996468dec7e9e326cc849d391e58b26853d385e34a588300780c8b8f33927deb546e868caae70";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323739333237313834"_hex;
                sig_r = "2063ea75a49a9d3aa184fc57ed68c48d0f2ea1f8d827fe31a960ba6419e570eee8151b08af94f4ee2ecd48ce994a34b4";
                sig_s = "7a1cde664166b07e30d103249a84289ab2ed2600e19bb658edf45f7f51a35f396b0767f48864ab8f9fb685c2f83305f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383836363432313439"_hex;
                sig_r = "44c2e0c4ad78cb695885763c6e8d9ef5f0bd4f5a09196406b68f36bf992851f4817163070cb0f35baae0a90bc94a1d1b";
                sig_s = "591aa095ac806855cdedc05f57e7378a8b59ebcdc4fb905ff1d4d689797656c361b32b42cd50538481485cd6f06047b0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333737393036313539"_hex;
                sig_r = "75ae6e8520d51154acfdff75e3af664656cdb160607386461af876ca4a2eac7e67b5704beac4c886c297a2699aed861e";
                sig_s = "3a8eac7e44fdd9fedf4febb309ea01d78dfe3142a49d3078b54fbe307a38706d22c570ea5df26d3872c287015e35b0b3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303833323436363234"_hex;
                sig_r = "56d48a28966e9f49adcff39a1f77833fe461d1cfc27fdc17951c0e0746352905bee45bc342209023f58f1859d63ae9b5";
                sig_s = "053702840fdaebe1f089e320a82e38a628c32c81247f20af2f4168103a8f1941ccbd09ba50724742a7ba35be3f21df6f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343832353634393539"_hex;
                sig_r = "40f907da29e38809dedad413605b8ed127c02d9d20f15c109fdfa14afebfafd37af8fced8ede5344bad3b800ea26f23b";
                sig_s = "16b4cc3a9d468b4d6dc42b97b375c1022d46a500cfc5cde3f0cc79fa6a20c51ddb36a8bdcc83d3518ba9ce687ef905fa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303635303732353033"_hex;
                sig_r = "3fdd7a8ec5952f4f173f3268534110fb03450bc365eb381aa9ee46b2864c78193ee0a7a5977cc5b5a6bea70a71fae5ca";
                sig_s = "07398b269557d30c3a7ce89b5e272746086f859818e9cb85e6bc2747d1e4255395a7eb763d961f2a5a75ad0b8ec8a941";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343932313138323033"_hex;
                sig_r = "2fa5a988b83979fb34db3fa3ae79e106a9aaf8b22401d0b57e36a454879eb4daa4f2284fe21f53f9dd7097183b968cf8";
                sig_s = "06244acfa15f5e3be2df351e663b7b3adf7cd8c63deb7e4b15ac24952c9c08b2d36a930d493ac743c166fcffcde4a3c9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353535333230313336"_hex;
                sig_r = "6545f033bfd39380014bbd6712eba808ca3c2ba4ab34a3165a1593376761e7ee0fec2eca0348ca3056151d1f6a5f1233";
                sig_s = "3a6fdb15cfd1aa3883e784c95fe4b1dc913961309451a9ba050d10e4edd87d60ea54651042d4f91b291cda5814685f21";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333331373032303036"_hex;
                sig_r = "16b330f061727c2e3f9b00fa8c2a17780f178b7656a2ff708879a1dbcd2246031b7be4ebfadf3f55482dff8cec25e4a3";
                sig_s = "09d2a8b07dc2dbf323d1fa2acefd4414f6a7412e117dedf1b7703693b0858111f4ce26bcb4b0f2e79998d171df66ab92";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373531313832333938"_hex;
                sig_r = "27dcac664f82fe3692992b82d3c5952e647168e923d3e51a4e7f3426efac6b5dbf031b8d203e836edccd8fc4dcca897b";
                sig_s = "2b32737bca118829930cca7b384d099424762b3594678aa13af89e78c3936d2096e10c524a6d0999db928244fc704e6b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737303439353436343831"_hex;
                sig_r = "7ad5a57699933ebc27fd37a66c2985ae6aadefd6a62fe2e8c24aeb8f1419b01d5e7ec84c76a0384284bf871928b670fb";
                sig_s = "760d21026b3dfe11076edd085b19bcac2e7fb9e25a649f1dade75ee14c89f1f462908002b3eb1483a598db971f1ec177";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323539303733303333"_hex;
                sig_r = "7fbfa01642dfec5b12ee47330b0cbc2fc479219e9257ff581ed2e80c611a3843522a7c3941d891df8f0c545fef217713";
                sig_s = "4ec51a80ae925035e444910f5b2c05ee6fa408568364b6e0332064eb7e3a7dad42a6cdb00682933fe56ae05b9c17468b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343139373133353036"_hex;
                sig_r = "89214aab319ddb223dbb4e82f8ee72cbe89633f9146e299a650ff0579fc69f95821155144138eec27f2a69d369a2b828";
                sig_s = "73fa0b8ef1ddcfc8508d747e887201677c685052d47fd2512f0f2c6ae37dfd1a9eeae03635312593f115dca881181c77";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3231393238333534363838"_hex;
                sig_r = "785b60d1d2dc21eb04c34b77d0bba1363bc57bfd4ed52c4630c3c102a1e7409fc63c2303917f581ea6941a52c555cb20";
                sig_s = "83426967f4e82f3c2856ab9dd7a8d98991ac98358486e9c2bc85e772a15dcab63e578d1d45e67f5fceb4018317cf4bb5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363235393934383739"_hex;
                sig_r = "2ad2e67a354549b987124a0dee2ca8b2637323672ed1ecb0f37a15e652f455cad96344c600b7a1e1e9560354224d3a9c";
                sig_s = "523b665a7e9e81a5e29367dc75d064dd37afd08939b167234723599880146a51209e921c5cbd248b37b81294f60bd855";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393538343937303836"_hex;
                sig_r = "24ebd78249a8af58bc84197aff563348cf783c6d73bb6c4e2d9e8e037763c628b252ee80fbf54bfc03db647348270f77";
                sig_s = "0b7f61227028eea8ddaa19b1c6d91a07cdf94f3bcd387e37c16dfbc9b047fe3e75446701ce2b063fbdc4cd7df0a9e995";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353939333434393638"_hex;
                sig_r = "33351b9eec7af34317d95447ba7d0c3e9c5ebc6a7dadff2fb90ccc8f1c9d1a835372720f2af06be906b5875bf3063bed";
                sig_s = "55a0fcf16682e36281e6019eff070100abbe16537845fa63aaaa55d89ddc96e3ffec152414ad83ad9bec3f10aa62170d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323332343733393531"_hex;
                sig_r = "6d746dec803866a4bca6b163f8de02620fcf9f9a0d27e058593cbfd611a64ea3fffb2a71cd57a624362f235eff7c5259";
                sig_s = "3544fe6495cce10c4f14d9dfed4ecf1c822e5f3cf90cca36e431dd802018bd2e436687831dbd69b6aceb154c34bbc59e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3737363033313033323137"_hex;
                sig_r = "0dcc1b58fa397933f8b66813583fb948c18c29aa3b4dda5745795a086723587663ee653d06b1c257ea0e9655b639c2b8";
                sig_s = "0788d41b5c4c740e0592c5e9741cfb452e177fa59a00c920d928e7af6d9568ab6bdcc7f7f28466dc761de0d0351bedc2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393534383338363735"_hex;
                sig_r = "6c83266be6e540467295a948c295aedde9bda1ba5e37a2a12944f0dfd5d9d5d022bbf9fb1d8b3f8927f82f67b94b0fbf";
                sig_s = "239cab00903e63ed01654222cc0c06d3e9f48598b7d297fcb3d488c381449c324fb160d7e27b498fb0bbb8ab6a74cdfa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343533383530303035"_hex;
                sig_r = "097a10e72312061e1f20a25feb19f74fb7808d5bde2de7455bd03a71cbb746df5c7daff07d018ac353493e7b457be147";
                sig_s = "50e92e7e516c18096233ccd23c5402e80c2c8b4af7ab34eaaf0d22bcb114710f73bfbcba9716ccf67e71d9c0425bb873";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363934383137303236"_hex;
                sig_r = "3cab21b288e5a20ae75609785924844e9d7c045d4a32f696564d17ade3a9279a6bbeb5812107e496396799c562167641";
                sig_s = "829d996521dade6d3f558cdacee55cde45153b8a7aef20646a59150852a5600a57a099e997a4cdaa9dc7c96808dfef99";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343331323036323937"_hex;
                sig_r = "0137a95bc18db25460a8af35113f707fff27d3ceb425cc44d471e1268d40a9fc3593f339f73a23defcc86216d5f8ccf5";
                sig_s = "1f4c9962b2143f6debc2c1c87030c343cb0e95cecfb3a98817d5e8cbcc4ecf116c09e75414d7188bdefd42886f1cb1c7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323031313936373336"_hex;
                sig_r = "3023753eb50bda7e06bebd6d1a91387322bd32df60b538171590628747bad5073fd2db6538dc0f90702a9e31b560d5af";
                sig_s = "6b422e92e111ba1e5d699be9168af8ffc1ec2b6703d0fb69470f7c58c5e24acc2cba03f10ed9c85dc00080a189f789ae";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383330303038353932"_hex;
                sig_r = "0bf7154e0e55012a9bf4e02fa96aa7ad879d3f929eed6406b975f6ccfef6fde8cbb61bec18c5c7c55bac893843e33388";
                sig_s = "75620ea5d958993db548118b4df8e4c1eef97617fa3e7f95c27004815b637cbdd8edccdc141f0cb70f34b0860421f696";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383834323632353236"_hex;
                sig_r = "63e27f2902ea8d8d85af24de6445f85a16e9d67844d5999149de289c1e690276ea81bdae0c46db16f5cf24d698afbad2";
                sig_s = "7a68a0aa32079f2125f88d1cc33f0cac17b44262306446eafb541b1350799b053302915c4bdbae504d8774d3bacdaf7b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132333434393638393037"_hex;
                sig_r = "6ae4a41527f6eecb460563ded2d4b922a44ab8ea97c9e92c691e5ea1a7f30ea533db07534b4ecda7220f4040f5a5b14c";
                sig_s = "7b8cd45dbf984783e7f55710efaec6e15ed8bbef8c62ec145a1df7390c88590910b065f1585c13743ea1f4e751c4740d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353439323433353935"_hex;
                sig_r = "26a71859fcb9b6bcca4a26bbf1488a01a4ab92b921b98518499d28f07840e577739b2c774ae32efb5377b1a6c6b91e51";
                sig_s = "7391d5453978a920dd31ebd2c02e6b5171617783c3eaa7c9791bb11415ada86ef833324c8c44c7eb0ac0ca7a83420d60";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303832383235333337"_hex;
                sig_r = "30ec58c3faa5b5aecb5361307bbcb68bdc6d9971eb4eabb09592ce330b49b2157ce16030e127af740bb8b0a0670eb7b4";
                sig_s = "5c97e8d3c3a5a34b52a70c3ccf0fb0394a27fc6a65a29e8d506cea8df4023ead6ed5091898a52dc2c76cc5e66484528c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38303337353732353536"_hex;
                sig_r = "6992af8e9608815628a4b326ae031d05bb38a24a095fe1fda0fdcecb78700ec4b90d5f51ed3674786ae328a0278b82cb";
                sig_s = "5e61c47c790c974a5766ba2b93acdaa12a4a85bb7e8d8f22071747a623f6e7999a26930cf0c7f05adbf7f75ac29fb876";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373734343739383034"_hex;
                sig_r = "7f882ee50a853b1fda9ce77f53cf097a1b787615584d796f94478d3da390e25b88861cbef5e8ed737e9f859b5ac755fd";
                sig_s = "78c9ab79927d9afeaaa3d057fb48727c13aa016d86205ab7de61ade0fa8a288c9e4f11cf4b395e25af2a86c9f7ae0318";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133333732303536333833"_hex;
                sig_r = "0402167dba17a64103893107f3c8def95b8b838f9c6f0b1b3843610fc0c0c08d0021d91fba432ab957c7e0c79d2ed60e";
                sig_s = "465b8523cb86949c386992b62222161689451e6ac50ca1402a05ddf7eaa8beaf73291d6f87fcdfb9e322da46149beb1a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313832373036353336"_hex;
                sig_r = "27603b118c4ff61be722f9fc7c26c038017713c64ff19c918ca5338cbee5bedd878a05610231e1310f182b661cd6002f";
                sig_s = "6323edc1a9865f227670fda2265a2b20834b6b0ac5335d8036d77f153b808fdde30a04bdb620afaeb1dccee98d2d08bb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303337363939303936"_hex;
                sig_r = "16edfacdae6f2636062ce0d953147260272ad4a0c6f3cd9e6a4ed63be2ed87ff5474d5040338ab4f8fc129ce132627b8";
                sig_s = "3276272ea8d707273965c1691a11b70e422c251319e16b7392043f58468d71caeea34a949271f25b53ff078315be721e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343230303039363832"_hex;
                sig_r = "5ec863f8273a343c7724f445d0291068b5c13fc94dfaaabda4b1cbfa43cb5f0686e94e05683323085af2b443c73a1f1d";
                sig_s = "6110f4477f47c89b6c64f9c303718b516e721e1af186f03889bfb8558d7a631b68d20ee181c9b6c9de3f02719da6b175";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323037353534303132"_hex;
                sig_r = "30451161007c9e31665889f57bdeb9943c1980340360648f62cec14cc35c504e201db3bcf7d0472280f229ddfa0cd73e";
                sig_s = "6e45017a00fa408a610a1935f5eff073b79fdc1b02c24b2b8718e93a986bcd709e3a719f57b0b0fa0738c003851e2174";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383536323335373531"_hex;
                sig_r = "425d991606b0197a40195c5acff16f45cfc30cec3b65b2225de9d0ec92178869b9481ac0f40afcb0d9ae5fdd0a998b4a";
                sig_s = "43071699dbc0696c9851c89f4e101863071c12003d1547fcee16bdcfac813a361c583f57d23a74c8c295e8c4709c96f3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32363736343535323539"_hex;
                sig_r = "5d7f10955454f4f84d8fedf8b1a650612e7cbc90a5d91eef683bf55fb1f3355d9b82329929d9306e549b219dd3c492fc";
                sig_s = "23f1964177842d65667b689e9de323733f4816d1e1e9119e4599fca51224df550144ece9a43b2c4ecea71d1bb6762bdf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313832323433303137"_hex;
                sig_r = "21882d0811711afadcc82f2dbb7f14ed813a4fb9dc657f2984708259e7bd24d35791f5ec042c21beb42fab921f90a914";
                sig_s = "25c800a5ebb92f792c76569f5f8251b4131eeb4e3778617978f04b9a0dcdfd6bbdf8a4ada1cd25a6cebd985df1a22dda";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353232393434373333"_hex;
                sig_r = "329057280637e0ed09c25a182ed50bc76f33935176305141a2d5bef206a9f599ec9cc1681720a4aef3b895e6298e5c3a";
                sig_s = "57f69b007b4782ed7e32f4aa43b69c63047f6c2e8e74ea64782ea04e3b42b0f2c10b4adb80fed630d9c8248167d338c2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343535383431313936"_hex;
                sig_r = "7845d03f8641f31e25b1ca48d1f8cc2d19e446b4f67823a5904208866b0230b4ce1d22ed8a53a76279b93c593d6518fb";
                sig_s = "3ffc0cf301e05e51a7397b90d8d4a28768b2fa0cce53dc7c815ee7e0b57cb50cae6bda5a3c925492f5e288f2719cf89a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393134353430363938"_hex;
                sig_r = "129479285afaca85ec17526f9fb149bccbdbe366860d7cfa65fb1ca53c60c0bfd3234c90d764e7671427211f3a6aaa89";
                sig_s = "15f206287c8147eda7c7f70f7c5ffdeedc53cc91690293a63fe14327e5f5b338460c383ce19fb381994facfc5d200458";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323730323132343635"_hex;
                sig_r = "7d8092296c8723198a32333dd0dee17e2ce4757b24122a38c6e62654ce44c9b6f6f5595c7de8a016bb1ca6c253a40d52";
                sig_s = "49e0ad8f638d33bae8639fff3a5fad0e94a94ee7b287f7be34f7f0073314a439d4f3943aae9ac562c3046a65efed8a16";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313732353737303635"_hex;
                sig_r = "52ce3c80be8c13a38702451a19447571786b0763ae53c7eb6520001b718624cb1eded4fee376d4d391ea740fc0adcb72";
                sig_s = "6199919c0ed708cfd6f6b9078c931fa51d964454031c01021649a1a277a663abb9a0adb5be331ffb3f405673aaa23bad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333835393530373037"_hex;
                sig_r = "382d205bdc0d8cee39c46cbef65c4da2c9ad126d9a1012e7940746e6b033239069f24a5c2409e62f5e172eddfd2320e2";
                sig_s = "6b3fa5920f3331f1d551e0e7c99b0d16869a287ad8edb05f862ea0e75df0b015e5470358741f8e8e704b47b002325421";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3634333837383033373037"_hex;
                sig_r = "82cf0d374b2760d73df2fc555f5a34aee24f6a89fb0fdd428be6c62200a002816b65e758b396f68311c83daa364548aa";
                sig_s = "107d5db3378dc658f13050611d622e986841de85f9c23f4ebca0fb5825ae3c72ce6b62c4bd018989f6b6bbb655e0f4a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383637313133303632"_hex;
                sig_r = "4b6f67c5926555e8a4b70f9e23641d8c14e21139cbfb7a263e02fb5630531d48a873e60c133359ad290d9154e1caee10";
                sig_s = "3e984268599d714e8ab1d7370b47b5f7390eea02993aedf389d36cbf2012e58927f3e01e1b910f5ce10f36f2dc0abc70";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133343239363139303533"_hex;
                sig_r = "274ac2266cabdf5f4ecbdc591be781e8a80838ff59127f62b49e3a8fb195bad493f71c9fc6fc6dd9829198183911ce75";
                sig_s = "101c9347d33160f70ec0ee97dc3757b19951b2ad2c8c38a4d78f5d74ed1c6fab534543b60bef269d7ee3e706ca2e3c8c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303634343932363338"_hex;
                sig_r = "3ed1ec4c1c76fa7c81e4ae1a775ab80fc79f959137e5c3187b29f4f04e303136dfb1ab90443a3da9ee49d029595cc8ee";
                sig_s = "3d9658ef7f8f004b7a7f0db676633af40fe8acfeb4bd7a47a130c956fcb9e1c4cce9230463e9becf31c7168d480241d0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232373339393133"_hex;
                sig_r = "208d493794509589f583dd296f60f3c260ca1ece26f21911ddf7e5beeeaf930e69039c7eecffde94a20b7b9565d4a31c";
                sig_s = "125fe71c5d2ee7e8d8c65c9183054e577cf89649a5a7df1ec0ce4a4c3ef018fd4db73f7e4f1e43d9f6847372a277e830";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333932353736393433"_hex;
                sig_r = "337e4e2b33e326d716090fd4ba90da3fd9956baaf14c6ec497cc3ed2061947530210a7b64548396028e15f652cae841d";
                sig_s = "5ec653d9a921aadd339fac777a8e93eaa5baf1f73b02977dbf3b4569115de9b4ada8727e962b3d655b05d796f0c963e2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343435323032373632"_hex;
                sig_r = "34af94ad4c7ac683ac2796fb058a792d15fcf8065054779fdfa64cebef5b9080aecfd3b053c662ce7b28b10db739acc0";
                sig_s = "6c41ba1f2292e890bbb83f286937d761eaa2bef4cc37b32cf91a66250e6831e205cac55726a6f02ffb611198407edfc1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353934393639363532"_hex;
                sig_r = "38785fdfadec53397131cc888b60c215410ff2048a778a086b94ddd8c222c951cbb42ccd8e92a24e23428ece44441292";
                sig_s = "4201037ef25882724c7cc7714a9d78d85c5b3ec01b15b3a3d98da06048aabeecfb3371e9fb962561abc2f38eec472d15";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303134363536343631"_hex;
                sig_r = "72cd77fe013c9385b19b4e2d9b8eac9dfce9a9276b7cb2a117c449a0d9d99f77643de849438ddab51074195be4bba581";
                sig_s = "52063808217ac7b98a9d51126e36910cb88835e17cf82426fd1facbc92179080aaac1ac62e6555aa76da87b715d1bcdf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39373034363738313139"_hex;
                sig_r = "34324b1e93f1e60cf1c3faf7330ff5d879591530f633a9becd678772546a0f6f273a1910164120186dcff2d0cb342725";
                sig_s = "79aa7553e42b4535c669b4540a8da3bb6afe7fd50b5244a3759609307d5f07fd826b321e56abcc2790374272cd662be9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343131303338333134"_hex;
                sig_r = "08518d07ba1ffd64e48abc6e2573bf1823679a9b166c0cf1a802058096ee4f5bd649f647622a2c85b11c3231e9729201";
                sig_s = "3a6694af3ea13077120980a5e273477fc0e0b4643446ef582efe250153dde390d97193233f693d9fc05a3b60f60376a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353437383438353336"_hex;
                sig_r = "656af35df5da50da492a04743b934f841c3df13aa95cc6ac2953a5785d6082c1cd1e671c3b532c51e08b3b4ae0983c91";
                sig_s = "1d9e7c085bb372a95a212a44df1eadfccda14932bb9b4bf8dfa27fc12826af55cc3412c2930950ee149c14f2937cea7f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333738363732383631"_hex;
                sig_r = "1d222484c394ca1782d34b29cfb394bc2cf3872f47088af114c13cf2ac4b6a8816e824e58ef8da51a413ee9c3a49266e";
                sig_s = "1e0b0d67360f8964339a0537e4b6c30008299b43e5986fd4a1c69f791ad2dae6ad36104de0e1133aa0f8aaa3305d629a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313636353734353639"_hex;
                sig_r = "22b90ddafba261684df49b6870e3d85c5c827404e12509e264801b41a70ffbe00bc14626e456152e94de897574e110";
                sig_s = "74899ea162b763a24422e42f476a8c71fe244a0a2e7d1487aaf7172443d152adbd3c7bf6a3aab89713b281f9708403a1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363431343037363435"_hex;
                sig_r = "564570460c4a8b47e569b2eb21315f252f2ea296395490d5dc0e1183d1dcdf867b0eabdd31c8c24fa4cdc6c53813776d";
                sig_s = "0109989480abe4e198a0c1f421ae68ccdb29b8c899a404e749440d97e555f3a5ade9b108b8e6ea33c6aea60b6004ddb6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303833363036303631"_hex;
                sig_r = "765332069e4825f03c6fa75af51697f9e7c5d33faa5def0cf39f91792efb3d7e294d322b78c00efd66497a1c23710e19";
                sig_s = "340832c9d3b057df2d15074c10d53518fdd832f5729a454c52e1978da2b064d40cd81dd0ce585c26e9f5c2da850b858b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383235303436303231"_hex;
                sig_r = "7677e8149e8b2378377e1888e1ca99c182b89bbcfb67b83fff6ffb333707bcbc7c9990574b683090b26b168b58e94e51";
                sig_s = "6a76ef7db4018a0588469680af611107a3135229563788dce633b365cb0b051c52707977de70827792ef50893b9f11ce";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313432323938323834"_hex;
                sig_r = "03fcd6540d6f43e7c6e2c164f3ab10722f134fefb37ad2cb237a3a72cb4abd4f783290ab6c823ea07adcf15aae35615c";
                sig_s = "2fe038f3824425f1911bb057e34e321e7dbcc4b152e2accde28cc6b721c24d0aa50992e805fd4224b818efad67c6c2f9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313636343232303939"_hex;
                sig_r = "3830d6f01837f6f100ee8ba743c73149ac0bded4b57da111b3edca992d08f4e29c78d87bd0e7260d2c018e26a11f5a52";
                sig_s = "1e27bb19ca89cfb3e30f5d4b94f0e3bd7234ca214b1e9ea2890840ff54980d2c44a7d58d8edf4714acb9d9084b7fe391";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343830313930313632"_hex;
                sig_r = "2f6e9fed237238b0ee7c861b402d503d10fa3c29cad3b72dc775e01bfa865ab5e57467cd881e8c9570aa341ddad7c58c";
                sig_s = "4675957e5458d998885e7557fed87c015101e87bd33b5facba3f94930969db51bdb590ea9759e87faac495df23bf0c52";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323138393734303738"_hex;
                sig_r = "19e8ebe840e93711a47e4ba3bbe1a8fff87ef8c34b15ec5fdc495557011840c527285254194226ed55be74723ae76748";
                sig_s = "1e9faa2f169c82705c5c78dd2fc4553d094eae5743ce3382d32b9aced60697644bba31ce452cf39ef9815a2d98fd8d40";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343538383435393733"_hex;
                sig_r = "4614ae0e3456663c34770132bb2ff87a05b30cff5c7d8cc4ab9f6cd199fd043996690f1794f9756071be394b0c397b52";
                sig_s = "74d7208703438f5035c8e36a812e2bb80f2f3bf6334e234c7a22bcce4a669eef111613b594a15f336b97fd252e6581f2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343839323235333334"_hex;
                sig_r = "59fed5201f3017ad6f98749b1c96bd80a10bc95ec3739c308de63d2bece0abf9597dce293e289456bc079ffdeff74b8c";
                sig_s = "5b645d7d6fab85c6917eb1742114344848212e521112792cfeebcc64d00b97b87d13626fd79947dc5a447b45f2772f6b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303433393832313335"_hex;
                sig_r = "458efee6cc2ac89050cb5aeab43f7cdcd1a9bb8d46fce60ab0af0e089f03bd99051dd4880e8825ebc9dc923abdefad24";
                sig_s = "17b9178ae75f1ac7307ecfd92c4ac4d81cad06d13a5a238db41b5268cbd5a4c9263f6522bd88a6df610da638c7814b58";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132393833353030363939"_hex;
                sig_r = "2954391f9b8e37617480291a0231cc60c18d12091fc9cf5a0ff7ff25c7fa21e6900bdf11c1a374cb2420451e3d883ae6";
                sig_s = "4b269278a79baf8b806c0c3c7a794153650da366a1d543bb75626e280b558f7c66c6f9ca861104f7109d27474fe6d7b8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131333236373331343032"_hex;
                sig_r = "7129fdaa3a38e618d6022688a64887da92f9acbf45b58ebd06a1f7ba1733c365bf09b669b8dd16c0edf5c5a440833cb8";
                sig_s = "3abaeaa2195943882b1f8d103f15daf98463daf4aa27c565a17e92e51f02ac113e90c2690210b7f5cc0a7c3020742702";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353733323839303232"_hex;
                sig_r = "32209256d52aa9cb05d12588eb357d9a4134170dd9c3a32c1e27a06a9bf486ed3049226fe9e5d117b5ac0b52fcec15c3";
                sig_s = "0623b8226e793c5efce3f5e8288d925e746fda4a30ba3d5eaa6d432976f3be589a9fe0e52ef8023e82df7000a2cc9bb8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131373339353634333738"_hex;
                sig_r = "2cb08187f749007cf10ee2069886287416fa5a8a83086c28085fd8639fdffe4b6c9e5bc9724f98f541b86ecdc7257c6b";
                sig_s = "602fa324b1dd388aa13b72b6d41f06e4aa9c98d4e28d2ac374ce7407076e13011b82d80e537476e0a2af80b67160e70a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3733383230373935303035"_hex;
                sig_r = "40390fc2bf86c850b2516e3cbc13d7e9ea4b979c97ec027e7c87452fcfd3f843518acac74c2b5ace89ba8dcfc682e70f";
                sig_s = "71affd3c3fafe2d8384190c3e1923b724a30cbda8cde309442d598fe40b195b7cfc8f16cfc2edb5829135f68d52df11e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353233333738383430"_hex;
                sig_r = "69625aced2bd9f67f2250a75b4794fe2dd557934a4ba981f693cf1cc5ef732eebb865c355c5d591732280270eac733ac";
                sig_s = "68508fb0540cb21ab9e3e3f6e2f0dd138bc7a588d834f969383992984e4fdad25c05fdd745ddc852fc393fc49096005f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39303239363535323738"_hex;
                sig_r = "1291e74903bae73bc0860f6f2e301d6335e34e2a8bbb289af2826eaad84679588861957c0ce162507f671d8767123cbe";
                sig_s = "6b757bb7ad0b5859369ea30fb25e8ef2e823ee0271c0b3c30781fe031579159837f8e14ebeb1598bd4f8b6a79a24d1ba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363030353238363330"_hex;
                sig_r = "727854c0d62857453c799ca2af12f4c21da66bee3163b5871856b33f123d45033b6eedda51d38026552017dff869e548";
                sig_s = "2c9186327dbc6cc33576d7ad5bf54eec46baf407e82739aca7df9c4853750f50c987851a6d116c9d780bfa3356753ab4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333639343536343136"_hex;
                sig_r = "5d07589dab414a1e76f064a303e8fd4c53a42d3f03e543c254ce8b9ad2e97a20385785843fa12716c3bdb9ef86c52871";
                sig_s = "87a7b277b7ee0e10301a5e92f4878815aefa4d5f42e465780aed76eeba002b37223a8caf7af71b9130bbc70ccd3d40c4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303139393230373030"_hex;
                sig_r = "35e2abbee976bb12bf72d33f664391bf1a22790aab3ea15dabc8a8dd917e5edce570c35228a29386c8a4ad00c5256e2d";
                sig_s = "308621467605c3c0374223392fae840dbe8d0580bbc1dcc2e6d13ec805671919b859d470de12084386ccc54aa07530f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373032333133323830"_hex;
                sig_r = "1c06a498320108dea8c69e5c52bdb17e90c314fc8b0da81c5de0589173abe5c4b9a3564b249efa7c78b177a8261e2b33";
                sig_s = "393c27214ff8bc56abd53a9a7a6e7a0f53c10ecfa484bbf619782f517d14b2bb83be9dfe1e6430a23d83964e61004329";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383038393439383431"_hex;
                sig_r = "022433de87fc51fdcdc9aaa2f115969179f7564b65ac20d7370811d8a7da372d21b01afdb81d66b84cf780e9c53c83e2";
                sig_s = "8c4a0f5c22bcc87e133f524566e3d8ca95142d66c2bf7530d9b7d208a17d05b6dedc7ad475de13f59a59632d9114f903";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373438323839333135"_hex;
                sig_r = "7921a90739278a21f42c09637f87295636e8ef292d3ef61d88ba01b8d3eb3431e97e8d7f200d79e679538cd368e57386";
                sig_s = "8167a70e895a707dfa5b0265d09a8f6a8ef80cf4bc0bfe89b3b9146fb703efbcd8538dcdfcf91530f609bb9c68e49df0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363232313031303338"_hex;
                sig_r = "0a24ef2c73e968f0ad54391bb05abb41b14348e22b5b84c2b08730efa0bb7de25e2c81184729882bac6b67dcd128e8ce";
                sig_s = "0612ab554a37d07a127735b9b23c86d1516ca02d5ea25d1bcf4edb4c29b8a9c7998d8e3daccb86f2bdbdf15cf3094ef1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132313833363339"_hex;
                sig_r = "10fed07b829705c40fe5e1bcc4faadac01e10290a1846f916673058095e9651a481231e4959783ff446c3e460b06759f";
                sig_s = "850d0323b6cbf95bdcbe1452d8c4cb52b66b47bf9f0d02828a806be2c4725113953a65b3bfd999e76b2427465e911dcb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393535323437333036"_hex;
                sig_r = "689ae6bfa60e623f2b2135d1bfddfc34c41c6614902dbab848deb1c3df9644810bedd7b3e44a32f32178c99945384d3f";
                sig_s = "865687dcaa4a3b2a691c32b3eb2376b005f9225dcb8e5ff472c8f26b7f2d1ce5cc4cee8f4a8df90c958dc341db9e8ad0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531393636303731"_hex;
                sig_r = "14f7b847b8ae94722fe48cab58fd522a89a2d35ab8b18d3bf95f8d555af74be99fdc2556e4957ee1cd70b926aabda315";
                sig_s = "7d1735a44fe647c845522f461923802caa919ed5e724d55604814cb0c1246b478bc259e4266fcd9f01a6d3885d3d49d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383830303734303635"_hex;
                sig_r = "117397220e6d2a00c5002b58253239fed37ddd3b03b69940dec027dc98b603b874c5fcb0db9d4f2c85ac43d7a9d621de";
                sig_s = "6c6003a276a8af3e7c125cc0dfc34a77fb02d02c712b2eddee19a8680e282729b415917f572ee62d5783fee83e6d09d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136373937333631323130"_hex;
                sig_r = "662419a1e59d5ae6e58dd34ae0f8b87a2891d6badfeeb3da4c85f893578f7aacfef9e41f9b6272766192d4e5e885c900";
                sig_s = "692f597ff42afcb37465ff09c2a3e5518c071a92650778e1bf5fc5f6a0bc6840163cca52552508abba3ea5a2c00ae6d8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323235353833343239"_hex;
                sig_r = "6da0261261fd1874cca7634bfa415677123226556bd01380a81cf1deab080870bb19f25d4b16855ec4ad3d77cd09cd9c";
                sig_s = "4a271d7dfbe9abb979e20e41cffa96da0735db2d1f68dd2f8ac6922561c7e0914b5f63455930d258b55a465df1752d3f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3236393238343433343334"_hex;
                sig_r = "33d58c98a87d1547858f1e67ce0bb161b28fdbaf34906433934ab973b02fc6b19a62a781111845eb7cd2550335011198";
                sig_s = "5f21c6511d3301d21bedceec307796e25b6715f3ed066b54dff3f3492b01b836c17aedffed03de3194ef9a8debde544a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323734383032323238"_hex;
                sig_r = "7776b606316ef8071ec9aa3dc26be1096d770b86930fceaf8e80719d1bcfd10cd7bfb3cb204c71cf03086805e99670d2";
                sig_s = "84b58fe85ea3b097e59015a9269608532b965df486c5d25aed553dedf254a9c0904d8a4db6cbfb49fdb6838485b35ba4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313439323431363433"_hex;
                sig_r = "23203fc6ad5a5b21d95744c6a6ad9481c2943878d4a30083224d355d421be54d19fe9f6815091731a1d69eec55a51398";
                sig_s = "08f806a4b9211719b2c08b2c2fbfe70e22a4a63b5953140ae77a88513aded5c78f390a88a385831ee8eab0006ca1f766";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "165d3850ecc61e4621f0ae886585a3abd4318a4ac389df217d192e7c48338ce002c59398e974cce5cf5318ad5eca5971", "207147248ba5133ea27c77929eacb80a9895f514476f3f40c8961fda9eea2f951311a78565f1916befa93ef18aa3fedc" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "f39b6bacd3b2eb7bdd98f07a249d57614bbece10480386e8";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046562";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec4d";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046562";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "433be12131d380c25d82c456e363d5f2e99c97253da183009241b109dd280474797abb17370ef26a724b2e1f1aa8061a", "516206daf15b694fe0a517b18df4b0e61a8321f1133e7cda7556e5f3fdf65cedb69e2669b74464ca1c82a6fbe7802de6" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046563";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f111eabbd0b2abd8c9094cc1abe46cdd76bb6ed0bd9e7324678fa8acf4ff6768321cba8ef8d64071a628eb17f87eab9", "036642215c05d858899c4084cf10012179dee217ff81fe9c4c10f805fb743f59d72296f42de7c20cc95ca5abf2eeda09" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "480eca2874aa6ba71e7fb5711339ac0a7bf84065b3c7d59c64a2c6015e6f794e7dfa2b1fec73a72adb32bdb7dd55cd04";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0984459099a6a2d442d51a0994e167e99988181988232b314cab258cb6426ce26c2334470e9f933818d6efd60035bd2d", "78cb308954ef8a5b26f796f4e2d2fb277ac5bf2c39ea31acd99027209c60eba18dd07fd33e57b333572d55b9e04f2ee4" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "1629ef2d7182d67b6bd9cf6842251fe09c96bfe022b8ad9a0e546fdc8ecf5dc8636fa13059d7e9d83fde50e0d2b392c8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00861d2fdde84cbf052e0dfadcb53cf4f93ddcda9843afb010ab87748cf1b97018458ec55c35ef83dbaa4a20acc357f9c1", "5951f1b7f97e120bf9a3bd2435e2caa966c6d4a056f618fbe5a9198340e2ec2b41ba1744abc8a8a9837423e4f36b422b" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4f87cf2d4a95f19512562874d7d0b5ad80680ad1a0a290b480c6a8f8836a104b72261ae83c30f39b1dd11e954eb4f4c5", "008c5a3c298f7af488db67c9f82243729e07f51eb09f2263ca838ba4827719ec44448ef9af55426898c1df7c2bdc2f1db1" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "02";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0a516661a19876af819e1fc893fe9ce585855b82c5ce07a12ca2a7efcead7f470db1c38ab9d4266aa59e6af5b679b86b", "0709d833d740beeb7eb0525967195feb3f0dd16f338337dce5a4b310713b584fa8c2e8b3f89737d8faed6de05003b55d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "01";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2c236600c85d2a496639acce8faf62084a0f2aac25eef5cd3a52c4418e2f7828dd763a2c60b6db21367ee9f9d04b42a2", "674f1c018d6ad0b1a6802316a189fb01c1e8d513363bafe832f6f354c3cc7cdfc922fab2be91f0d6fd252a40e219528a" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "65f34d64454568371283c7dad9abd44c89174f389877282489c115220fab0b081f8d11e10452dff6c708bd1996db2ff0", "1720177810cde4d19c1efb9b1292729e5b48ae1c4cad5f6eaa8657cadf978d5e1f76d2106ced0b5cab703eaf0d4fea08" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66678df131b3941485a6bd170410245a6f5e62aafe89e14b94976885823d2484350b3e0f3276a8b056fb3fb37e3d3552", "0080001aceaea1763d29a35042e16d94ff440f4a0f5697d4c497e46e45ffa1df5f59b9a73889b79f008c9d852751c0c59d" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "04";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046568";
                sig_s = "04";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7a849d0bddcb6308b29178cb1c15bf4d421f1f4d600c2c710cd370982960518b77fbff4924d97144a901726fd5672408", "1d37727bb03ebf3f0c50a4fae93451d8099a9519183d52de8dedd392876f66045965650c64684c384058aa9fdc0c6320" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9173bec";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a2722aa0181754ac569d86f9a50f0c02c1aadefa9d1633747ed9e2482613e170a905c6db64afe5a39cc92f93e490c87", "3c726ddb39cd8234c5e0341ccff8618d6f4c4b94a232b3b30f5d5cb60c5555d8a70d43c62b5c33c3255b40e7946b12d2" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0101";
                bn_t sig_s = "896621d23283b12111048d1c978e2c286d60b6ef7ce37af36cf7aa4de268d626de7ddcb356d167c7483c69455c752c93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b586971ccb55cd7b80c501e9c8ec5d06d4d46ab62512adb048f84226d76ab0f68c270c823c513f71305270b1fdf45f8", "26246892f15f0cd2d0cad344e1b876f2247858f04b57444903deb7bafba74bec2942012d7b6f04d1a76199d2568e2ad4" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cc";
                bn_t sig_s = "38e8dae216c63f06b3edbd0f9ba7a5e4a332ec187251e3d627839d1baac667d7caad2ab0a1ea9fbb12dc5a71e3b49bc9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "72bd449c9fbbac20d4787929b27515d1e5b9e67c9fd4475ff128ebcfb4fec6d6998484d9f2b500119678d4763a3a2563", "629e0470cbe2c952cf99e6cf77c5e5e5fb7c1e4c0b25a380ac46c9b99409d1b7a43b214b38167c567edd1e5a75a416a0" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efc";
                bn_t sig_s = "0d2436a599b396a51c546e05d1c3d25a8f6d05935ae5031dad3cdd7cb36cf6912a433de28f8475d3b1e2e1ce77610879";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "04af06ee476ce1b3d772a5172d101e8c9f4a879d68bc7e5aaf4851328c237a884f0f678b8536db82e97bf69e2474a662", "0ebfb1ef878b18a4b3bc808319832ae9c179a6f65fe1e00decd7343275fa90eb4a067025cb508aa19f7736b02c83def7" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0101";
                bn_t sig_s = "4a289adad7ceec67ae99ef5da797b6bb17d9c168428ab30ea9a68b89652c4b9e9bae876ab3d7fbdf1eb92ed422bd3b93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "583dafacd7762853ff1086db9761e1b5d0cae7f8066946b96c5cc12c67c331d15bcd2fce4d700f763f0ec903fd48f468", "6eb17fd61ac9c62ec19e705782c2045c7f89ecd9be8814079f9699fdad2d4cf871508d236f89ae787cc36128ba71eff8" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "4a289adad7ceec67ae99ef5da797b6bb17d9c168428ab30ea9a68b89652c4b9e9bae876ab3d7fbdf1eb92ed422bd3b93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "28128eba7bbfc2c4b72ce86c9b822029e9d41f9bd292753bca0a56fa0a51f010eaf25432199e55f69c02ba001c0dc8ef", "75f77d6689d41d39aa0ee27b18e7f26414c7035f1fac7d958f2df0e3e1eb3a5d27c56aa197c75c173f18d2b925f659fb" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e90464e5";
                bn_t sig_s = "5dd0bf01c2259e1ab4e8f4fee099813f6374f6069e3839ccbf64499dc802c3c534d1cf1f9cffd76027b021574602ee43";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5f387561d6f807825667f9eddaf28ffc34ede303231e03ec94db618a5568a8851fa912af936d7b71e2a331e168b8196f", "07a34d058a61adbdf59f11489f788376325b6b2cee11b086c9021dc5fbe6440e8c93a583178be0b620895df88dbc91ee" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594e";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0479d78a564638d7d3cd95b178e50419380f585cd20a4d88853c1e0754c195fac43ec7d1c9b218efb6c2747ca3d2c36a", "1c03c8ba7974c9b7a0f4cb0669033936117f51958e9ab54d2d4e2814e9ae15554b1f74d19c7047b287673ce7d4221831" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6124849ee698fc0aa37a511a5dc38d0d77bf06263ac9a84f5038abe68bbbd1631da8546dcc45c38aa7dac3221594cc02", "7892029a11b2e52629060f30d9c831b72e794129de81052d8df6be1195598cd60682666e5063688761ae6c413d1ae5bf" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367b";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "57a407035f5fd271b32b77b626091cfed62be3a7e461c594be4c9c2c507294320922e28405e8a5e0dd5b310bb102123b", "103b070ed2370f92495858a8611d961d9b8329fb42b8fb526d3de342af7008a0e14f6405b312aac4eff1e6333c63890d" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "05250c98a02a70c27400cfb4d3d107e7d393c67bb818673cb1460e210af30eb0f8ed9e9574ee99669969f2e922e4ef23", "2555bc85a62aaea353a831b33e9f4cea60810b3a8d58cbbac7a7626471a855f2d8c39477951de857b6384b0accd911f9" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "221d71dd2b257309dda46c8c82afe18189ebfbf49146f18655e40931e05b7a203db5e2da64bc64ffb43a0bf55e3eb76f", "67a763a8760fd8a70e80803a5bfafa9a42029b95c7e0caedf309b022f140e44e8fc840f0ea4ddf2aa76bc5a44b796a98" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "27a1cd4f4d5acfdc4cbd02afc7a079a16af1bd59fc260dab35a3d3cd7387332956451814dae863a8628d608c380b852b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b999e6f7c39614fe6a35a99c5ef433e1035d051809dfadd2aa54a80a04ead2a48313840e18086c23e08d073c16370a9", "00819397a25fc5e7aed9f4b695043e28b181575472381b0a5ee405be7bde4478fca019f468b306e6ade64d85ca2134ae00" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "115fe822c3e7293e84b732283c95a0446f77d1dc754c456163e7b5262ee2fac43da1b7bfbac5121fec4c276ea126c163";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "72e473b8c6715e679165e67e1f7f977226a36b7db0bae4770b2c05d3b63920e266f4c74066e0755fbf65ab5dbe934ed7", "1b6724e298837766e331b6f25018caf12d8fa202d7b46110fc6d0de00f6502038394caa4cb47ef9531ed1864f2455718" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "38602328c4ca227ee0cfeeed354a5ece9a8c2466ab8ea87c3b67a33db109203fec4304417fa3bc0c2d8592e74a14a17e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "62ab9ca3e6c4b39e99ac5fb13f81a991588c865a37ed4042cacc7841764661b882386650081689972bfb39d371351e7f", "3552f128e67da32be68a109cab8f3c2c2c5df934d9d20e10fa884c4515095160b264a5474e7087ebbc855e6efe316955" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0af0ef24c77a97521a957d4102ea0de4e1d16a9cad02a9a9a5ba466bd1a99e4a078772b0636fcac3caf4e3f9321b84d1";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0080ff1bdcad9ab8c41c91267aefeebcd0cfb37cb87a7734f2b2cb1c601810b26800ec201cf6f1cc8f1517a5f394e6c2cb", "00842ebabd0610f9b66f18e339d5569e19e57108d5ef12fe36294d4d9beb20f3424357c499ca38471f2ca51a52b4a48180" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "2a23418cc9d5d7bc149bb47e0ecfb4f50f5f32ce49aec5c11349196bfcf0eebb49d977c76aa524c7dbc7e23adcd5cb56";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0626a3ca17b7a23dd9d7adbc2816bcc1011650f1779a84fd0060e8c89cfcdb90415fbadcf4f1d337d980d947a6380f67", "0085a64c254b2a3fa622782a2a1aceb97bbb532a64ff8d6dff039acfd96e98cbae99fe776a7559879aeaa984a58d594a65" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "360c166f35d9371b4e6acf6c87aca0876ac07ad69efa9383519ecaba2ddaab08253907c2cd41cbd56908f22ae4fe8947";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0088a6a2b81f7b74a0533bb36ae0da989c2e7b3c509ec34ea94d87e8f61ae5fe479979aa0d2b4cb408f7ee161cf942ba32", "21be457eab32fa0d477d16a291527e1beaf9728003e6e05abe2e77fd5a3492ba304f44ca55c7bd42dc1c726d4bbeb560" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "1eb43a98963c2d7bf910155abb629846e35794464a22a01f4efb44a9ca68828a1565ecd890e4676e1887eb9a7599dd9c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "279113d47cdc1ceb91dff43b26ef9ef65e7d8826a7df2e8ef582338d428ac8e6baa7b671356e610445dbf552c5939919", "0833704e251fcd642f4e42b0e04ac3d4542127c685249c15e64abe9735587f9535723df59cc2a999a8ebd997fe08f483" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0a66b016b638891819928a01f3e5b3cff629b9f0d878d7ab99e90f8206c062d11cffca73efd3a0f56fc160549b68c5c4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5ef8ff9ecf2849d44e0d74846dcc0d73a8061200516806e8352a85db78ab8accfdaef60d258cd1ae2483e2a7ab200ee5", "56e31168bdb642a432e3f4401e54029795408f2cd723f276105b51628c74bb36a94f1e2dca91b8e125c3c94b5b1b3e5a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0de1b2d3fb8cb15f4ba27fd5da391dd2f833797cd4332111879448cc079658ee6b0cda88a6ef9d921b0d872013f250d8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1cc73f774f0c9d91015483a76a5ad927d3caee74de86a6aaa01e1ea0dd84c1fd928b65f55af18a0ec59010cbe520b925", "45c417a3a12e4ddaf3248a75961f357c31048c2106d142e2873916747c67a4422ba8623f239340ede0b0e6165e3823a7" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "24f58fbede0aa2ad7cb2b26fc826925f65ca391b2b1db0edbe1270d28200ac5cefb297bc9e68d88659e82b63a925b0cf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0e3492288b59be042e92927b02d5a0cce6fca75d5a16477a11ce1c50474e79129fe3941615ca8deb71ff744705425db0", "061ae908b78c6b49a47cc9786957b20384290af299e2a1d10f12de9999630704e96f2996c437d3c4d4481885522f8d49" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "37b69194769dff477d4f0706933b9b2f0902b117179132a1174d8848b0be2bc8f2f1b82c3ef6b802e30ddd6fb8237c71";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "75e71f56d922a7c64867406d2c4cf7cb26126a2967dffe437876766e00c49e264b1cbdb5d7d23decef3f1d2ffe949cb8", "65d3e5fa79067614289cbacf0a5f2e23ed7a5f3c367f7fdb368abb87474c0c291e18f0bff5e767963144c73fab48e9ba" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "293fec2aad2e3aca83f5ec93420b651832e5b38f3aef0b5e1e028c521349935b5669b9d54d5b6e3e1c28d20d2389ea52";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b2269b42d41e95f52bcf253a86ab4ab14ba1874b577ca80fa927ec33cd0d223c7192d10cba77c458f037006e8745250", "4b126a0843ed8f57b77ceb9f1d17a80379deb22aad0384dd336ba1125bb35b45edeea5c7b02512c419f5d70f1f2f558f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "37c9918695071c1429e155324c602e8d34b8d38398d02e5ae8c32c7afa49033a020484fa6f356abe10e127bf9768874b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "400f5208219e4498cb70975a35edceb9b3065e4d6bbf5cffe18f1745034070ef1b82b4cf5f268b921b6546752ae7e598", "0aff5979d8ac6ae830449cecfda17f27e21dd92590b61889a22ab25ac86cab4a247487bb1ea339be80db578bf196ff7f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "041de947891467ddb8dc3c7ec190ac4fd330cffd55c6bbbdd008362e2d818871914b6b914a9edff7acd299c2733a7397";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1a233baa5ff74771e47cf1a1503010a683c8933166c4158c2943714c0df997fcf7bbaadc151262ea9b2fa25f896909c2", "00e1efc31f645e8e5236d558a61ca6efbd7e42c30cb1eec06091145cd752aa5c0ddf43d5f433d90e73012ae41ade4823" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "062979476086e29e3dad11eaa1ce5a2935c70bafee5ddefad188ef56d41ba9a70ea25f01a1483ad5ffae4031baee822a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2e39042a623fc881be5daa99ca75dd025495b1279e235472edd89e3d6b4d6f865ddfc812bb180a620010d9de87fb4b47", "4353861738537f766a86c51009228ad93328cf7be9a4cf6d4b60b31241e07b115b6875d06114fb2cb63e458ecd8ae9d4" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b2";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4ea035f9b52d737fb1b0405a832d8b7479caba4bb76048f2416fefd21ebaf1d2617aee6ee97e9aa744dc3401299cfecc", "6203db8f62e62864c47c44a4e5dfb854d17fe7a7055654a04fc3aad355573a5dcad97761abf96759a5e4d0b18836001c" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b7";
                bn_t sig_s = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4393d0d584299c1ae79ef5df333502e615d72816fa61d524e3515d4ee2b3141f84d17705c2a5b4030e903e5e76948544", "10f2d5d488776966eee74d907004b567efc29449c01f2e1145801f0e8b71e849fc53024f593156c465a9a366413c514d" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b7";
                bn_t sig_s = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c9ffa94a24728ed6a8cfedf23ceebdd69f7c5aa1606b9f6ea23e07b092c3650a81cdc2aba7309a3967b42487aed46fc", "0db0e4f74fb9366c7521f94977730b82c3f73343e9a9ddf6e2e20bb92e109fc564f72db220d9ccabc4bc1ad040f2c41a" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "309b446d14cbce84c919f7cc60c8f8c5d56875c3a32fbdd099bae90bfcce552d3c715cf9771b3e9bbe65e0efde10712b", "5bbe8cb8a707a54e9e39501eab3b89ad7ced5f47d536a0ca651f473be8cc10a0e8744e4426945712781128adb731f942" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "21000c81888c4aa1b08ba356c995c0d4d5b02100d7a0766aa6a0d42e3cae0d5149cb3db3b2dc11a23bc0bcf70ac4417e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b050bc1f8dbee85baf54231a2d9d66bb17ececb5db282f7125538382d1a320b08c4fbb7f1cedb02a4854697a01e4feb", "0d438dbc55628cc6521dca22d594f3fbe97d824f1b59ee0d1bc328b1d9e8bcf2f81a59bc6f0ee41369b7cf1cee124fb4" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "61950b9e116c0185d6a0a9d135964304f6fc9b0bb895fe60c5b07ca33945108588f0c567962aa81d20ec1883f54efae4", "20c7ba518b7eeb25122ee98c80f4b820928987a216f822ecca1c01dbe4a24e06437b91c146fd38ccc26b79e73f50cd16" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "5dd0bf01c2259e1ab4e8f4fee099813f6374f6069e3839ccbf64499dc802c3c534d1cf1f9cffd76027b021574602ee44";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0abbed69fbc1e5f98697a2e72a4b8724aceecba8e544a103fa78876d530cc29a9695b9309ba21d01a4f866cd2e4d0765", "267fce2bea29635e09dab69559f26de776cc4436f680315b1030cfcb2a5b395c12e8b6f5e9ae74bed5427790cf7b20a0" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "52d0bad694a1853a24ba6937481240f8718f95b10102bcfe87d95839091e14aa1c38ba8e616126d4be6fe25a426c2dc4";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "09d49878b5443e8a7dfe323d02044d32e3060f12b3020dabbb6917b8f544bab18920e2b7458b59d5d17a38093831f8fd", "2b37501b31f08802c46eb9026b1a363000ef573d9ab30497219aecd7c2733ad73f6e5f358233e263d1acbbf24b83fb04" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "813fc5f8ff37043822c3dc4cd2eb1b4e70f794d25e8513a75a085679b9e7437549508de93addb7b824cf96055fe684dc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7eaa09a14c8c2e190528e199ac9bcd503e9409d276f793970da094355cf8fe573ba57320a91978062d5fe841921d3c95", "696460275f0a1913d6da488664ebfc03b2a90fcb4eb9ded9c06e3c1330877db58256c2a9992d3c1e971d4d30a1951d36" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "1d1ef15cba432423c24d56a674802dc741cf8939de3ec56290e51346ad4196bda41a1f6e233f043fb36ebc2f34362f95";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "12722219ddcc63bcfbedef7e8601fd45361c241cf4dd9bea8eca3d67dbb52274f444acf455234e099398aad60662ee24", "0340ac71b2c1fde05e2b0415645cf04c93d946aca5ab205ee22a8e62b8c35b4b841474ebad78e9a4c0c80b80d5b6e3d1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "83eccaf00726160b0a752afbceb9fd442ba91d5da190cb2ca997ee26dc0456e4a376ea68911f2c319d8f40da1d165dc5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "39efdc604f6045fb9d3228fac15a6f4902013649bfe55fc757dbe8d8cd12a1be6eac36c3914c0e4fb08643c2c7fd1450", "7b558974aa703224c151e219dbce67241936f1e613f736445ed91e1c830cd8e4f4b31594c15efad71ae81089ed8fc0bc" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "809e7764b633c4e8e884c5ac72de725bdf65b63b08f2a27a4d807e18b33d9abacd2cf874e1d4e96c34a7a82d0cefca65";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3ece126b1b26b97f9f148fb81d0c96eab6362cae1b9ad15d85a6d354761b0c4e8ce25e247a9fb189d24bdc8247b3f023", "09ff4aaf3077f27162050912252b3244cb3cbbb96559c88f92cd21109c5a5d98b2e14335ab4d20406d9a4cb1924a86e3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "7483d046c92f1ca9c1ac1bda94d6a2d8a99bfb6c2490ee417bea8dc4ba770fcdcb1f3a3a582a0fc82dc71e5730db2f65";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "60fe6233b2d9082a47e802e445d5d1fe93e47980b2203959092843090913a28d3b5d4f29a1b67404473d17e61fa9bfc9", "613b117b1dd12957a9daec6f44f1e0c3136411dd63175d1804df496e1fdb0172e548b1cb92b60c6ad4b6c780f5a5c899" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "11ee58f613c6c41aa962a638ea53f63c2d52b352de04495989986212c642608599e1aff3a9e2d8e541f5e0052cca8f90";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4ae0c4ca63998347c4385d162b04e112366bcb9b134bc2ec672f5f8bc82e58b05c22c17ee51e744693996ad3b611a7b7", "729000d6c9dad30d9dafacf9ecb0c672f22c2c3f96f4c8afee80a6a1138cd177e80f206af3fd52ecc11ca59a2f6941c8" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "787c8284a545a0bcd2ba79b45220fe0dd3a2317efd91ed3bbec0c0cf34d75936614d7b9404cfb9746339f536761a5796";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0085d760b9e2dda55fcc4eeb506b56bdbb685bf10153e1d784a45dbbe71f3a564f9c6b6a142cc71cae195ae9709b9c71aa", "0b2c59ff91da548f6341e340e6a12024d255b8d228f7d69a7a90cc8c5f966b4f840aa8129fcdf02e1b5a03754735b5fc" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "5b0d13fbee13030991cd7148b1020fc62e77a6865b02c831041595bb9ec4bb7a1e800e54e3cfab7a6e6b11245a975ac6";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f8028b892284eaad8272515949fc70f76593c8751e185235aa0b02d9d4771261da5ace04a9d856fbc1bd5e7d547955b", "7f28c8f1c84c3ed25e039274719fc829540eb1270b0d2b23b5cc95ba7038dca80555f329d983b88af3be108682ec989e" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "6350c11758e7aa8afd003ae2acdd2162dc67a6316cd2f833db29c25027751b52c11e59683acf2fa5dc5040d5c7ce4e83";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78628594b220dadc3b97b0bad037a4ab55e7abebeef38d4bf64eea3a928f5ac1f91e3644a4f3ebada2583c9e993b7a24", "50b0ab799caf65cc35348881b2ef1cc95bb48b322ed76fd3fd31a98018feaa96f5e942b971aa63cb04d42cfbffe63528" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "39e863ac0e96e7edeaa3064708d400e6a39fdb58ec5199b4973d1633a2e610fdb301fc210a1e9c3b7d184fa8a69837a1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3c1f536e4b2642f455a7ed956e0f8421aabed66a2b88d714dfe232efc991554fa1162cdf71480eb6e453cbf3db2282de", "51010e435e63f7f3def8307dc2674ad61befd9d75ecaa9f537ae4a17fbe85222d3a9c6c0e7b58681cd9284d217209341" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "10800640c4462550d845d1ab64cae06a6ad810806bd03b3553506a171e5706a8a4e59ed9d96e08d11de05e7b856220bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2c88ab178b4eb40b60b909286760e05ee7b304a643648969a0c1819d47e9efc41760e4157fb5713af8efea1ba4d5b630", "036d78311aea2a2fbac504ef466043b4ecee6d9d1b08f43b5cc2ec3f60174ff5fdf31731f9e12cf267b297fc15c3c398" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "54ec07efaebdc8a5e8d5631262b337d32b7f7d21e5c98e0ad7fdc0d9aca2de32b9aa6b0ec75f63a7f77b77190e9d4a7d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "18964af402a49db10f9b7a3048106640b54fb623f09ad63be2bc55a6e21af06db54824e62d9d3979ee3512650a9ea422", "5df93caf8e9c981e5735ff18459577c6002a96e236ef9a8690bdf3ed06ef61f0b7469e2a3b998766996d2125d7af679b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "59930a2b8bbd79b8051f252a1af76b4a5c6525adf9c6c7910a5ccf798eac0c8d4513923a792a965abe82bb564dac21cb";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "79d9e291a2d25f06c7d41fe9f3c63e324559fe613760833689405e0db93943a13b7ff5e4a92383391b5080c227546eb3", "00860199b1a242caae029ddb9e8fc2707e64f0bd2ef4139dc5a8ef76d2e76ed4f0129faf884063cb66c39f2ba15a14a066" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "1449901ce4b00f0e3a5ff84cff8c134854b808e504d1b8f027ace9591234e3f62ce70c35a8aa8e60cafe1e0df3ed80e7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "727701750dba41518739bfbbf229e6c5e532ce46c263a2972d0bdf38127ae01ea7b071ba4b24098f4a9201381de9e5d2", "5013bf277ca6c0212ceaa8258af9b577b78940d1712e040e2dcc158f0a5e44a9b758fe8c067e8d5e2ae876734bc55fc5" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "89ae6f8e215bcf35c7e2afed1a6b9855171687d9edbea8af5bf8e9ddc667aac4e166f05097385fa9ea3a6245fc07b4ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4643d3406fa4c948bca3779452cf9494192521f197180c060efa70a67632e96e250cca46c14cbb3f89a29193823b8698", "3dca3a91f77fddbe0da9064220130c1f0c84d5c0617d5af6ff776702b277b31eaa7fa0803566bd6ec642de636f0cb092" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "3fc16256a0914ce2661a54688af4b2546b1b59b043667da6abb5b1a1e0e2e6ab862fe8bb749f7251572bc160567530a7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1581a1792c97aad0cd0622b6f1b1a98ea8629506be5b1f898e0763513724df65c74d4992b5e0dc37c769bfe367e2d0ac", "747a564cbb2e75bc32053b8bcbc2407b78b579199cbf516b9a1ff22fa0cda3a572f8ff7c7c8e82f84fce2d4cc0e35b20" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "64c1556c5eef311a4f3ba46316adf73732d6ed47b1ba2ecd178ff89bbc5ddd6c6419f62e045ea2d35c33a250dc2fb925";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3545409eb630c0e4588afcef6b526a8566e429f83bb7966faf84f9ef3f88b72d3ac85be8f5c62163803b2a30db1ddb89", "228dc92f007da2375d7fbbf1cbd10e83321a425cfa6a6b2019106a88e090c91833b56af68aeb71eb351dced8cfbe3794" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "3cc98c561aa5f50c8f19d947dc75ac8f507e6985762006e7100982caccb79530f8f935ac9d3d82967cdf129ecf5b0ce5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "788994540ec1124c9d27468728f79074f5812628b61d5148bb356cffe200a5a392cac1024ad150a0336b3cde2f814b19", "6d1e27fd447eb8fc948921fc9fefdf34d4a9fc79190c800d827353ce6281ce3b10db21bf002bb23be66605c0ffe971a7" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "3f2095530f36144e009019eee102b2867d83c9eb4f28bcb31b383e00c8c3746b20cc90e8efc813aefb5b6a4965204c53";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "563e271ab6edd27d6a44ac2afb036a2eb31c3f497211f5067e37b19cfe0f1a9dea9565fa5fc07c095e0edd850efb878a", "0080e7021e892d054b3d781eebc92b0aa1c78dd17d9d10fb510914db6f5509bef4b678b04267df6728f689b54bb7ef51fa" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "704afc6a72080d1728f6cc9fd023e9d2373023377f02599b6ea9fb2923dd7403fe2fd73999f65316b53f910bda4f6f10";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6960cdfb6a1461160d690e3f48bf643e87b6c5d87927de0d89adbf177693b0f1997df3fc0301621a86f22bfd9d868119", "436f637dd07babab5d36393a49914131c25c7ad20aeedf650217a0e5f7b2d95a14d1f650094e347fada99b1debc1b301" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "46f09c4741c1afe74e32f6ff14daaf90f4486c33f5d0e978f9af24f5751988e72b374c5faeffdec309330401965f7d20";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3ba7f9d0b3a66b129cb855d51148ff3976ba404d9bf555066bf275a0d10dc10c28b8222abd99e6e191dd558e3900a475", "008be8383324aef15f3e29be50a18dcbb773a37b9dd4a66028177366e2d0a0a8918f0e1be76c69689230d4f4b377d1ec64" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "19930a2b8bbd79b8051f252a1af76b4a5c6525adf9c6c7910a5ccf798eac0c8d4513923a792a965abe82bb564dac21cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "488ec5d4c4b208551afcfdbe25c5ee675d1baba6075c0c0643562196f56d860017b985252b78a1a3b0aba43a67bb1d25", "67e354af2206a42278618f88c75655440d4b358148e908cc9c7497884d9fb88ea1690baaa174f0f05d150eef3c5aaece" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "33261457177af3700a3e4a5435eed694b8ca4b5bf38d8f2214b99ef31d58191a8a272474f2552cb57d0576ac9b58439a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7382c4f7d6176700d3009431515ee38b7f21c050410be0f43d254747acb7f47ef92f67c0d26a8af65d6415e7454c3dfc", "4259dab9097d09fa6afd910ed4b21075bb7856a37bf71003bc9f285315d54febeda0d3ebc0f588685b765e97e06d8f14" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "4cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046567";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "46afd845374839331877709066652dd09610d49ab91c31f741ffffad39c76700a609eb92c9dafddd42433417fe81a0a2", "0f5857ca81244461f7884d68a49e124d09b8c7217834e614422bbea4c780e5e88c8927bea70d8d2c64244db743d97d04" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "8b33c708624a1e2eeba00fb5b5a8ed1a1622fc71ed897fb13d87ac253935e8365850d380015c115d12e14a2472860d09";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1a6180cdf899e53a2fdb9349577d0f7215dd157d593face3adbc1bf0b2c5320cbd7cb697dfbe9081c03e28db88dd6769", "46e89a80ae1a2d4303ffba439ce690778ff3ebc0c1820bb92db4275c3d615600538e4bf99c9f21e74557869ad351454f" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "8729cbb906f69d8d43f94cb8c4b9572c958272f5c6ff759ba9113f340b9f9aa598837aa37a4311717faf4cf66747a5b4";
                bn_t sig_s = "4a59383efc45e1ed1892dee91cf0d54a36aa42f37fdb83b9a1675a15a8811822864371111e3a7de588987d486a6dac1a";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1a6180cdf899e53a2fdb9349577d0f7215dd157d593face3adbc1bf0b2c5320cbd7cb697dfbe9081c03e28db88dd6769", "45d08401f51e3fe50b5db53ab3ffb167853b85492bd24afae4fdb2bd4255bb2359455b2ff37df88a41ef79785db6a704" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "8729cbb906f69d8d43f94cb8c4b9572c958272f5c6ff759ba9113f340b9f9aa598837aa37a4311717faf4cf66747a5b4";
                bn_t sig_s = "4a59383efc45e1ed1892dee91cf0d54a36aa42f37fdb83b9a1675a15a8811822864371111e3a7de588987d486a6dac1a";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5b1e699a8b7ac2ce0389856f112412286c9c0f162191b2f611e4e3a92f070dc763ef2630f729e5a376d73b399fc8c299", "3f7a0cf64e3991ac19932c398f52793ed572a8b404be69a667c8a4f9be46f4cbc6ada2b3f07bff42ef9fff967bc681e5" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "51965a24d7f19f0290d13792a72c843395c22051b338616c490a71dea737937e5b3e9b8ec1e2f7e6e5ac169db52d23fd", "6473f0cad9fe3b651e6744b9988b37b55bb69214f3e494f8ed8edef2fb7958a2483b9f3e9017acf69bb0d1b22e379d51" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "46a25aec4a5634fff6f9b913b16c3304d71839c14db9d568b77a5d7281197e631649c59621debd1cd9fd5e0ee92add7b", "7962ee9a9d10ad015722d85f817fa65229b91a1d0366e38ff6ce6b39db9771a8b535e1b11a9848f40c9c51198394efd8" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "054fc0100c01a28550e3d9e87f037fe7bcc43bc45c6148fd031a0a71f67c1677c71ca9f144bfd26283ec92a8b06f7762", "278b0dc167093dc943a5c02954c753287ed394c05cf8ea1f843a52a2080832ca362267a980ee0c5e3e0f9507692110cc" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5523b8f31558a2f784fc85828b356c02066542a1efeaf21fd142711e392219ebfa2545987d4dd98cc6a13e8d5e0f01ea", "666ec15baaf29e0cf5dd1e972457b2bc747c954f5a5b6d79ba37d87c00b7bb5c98def088494699c186e88f8904d3202c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "7094186882938a8672b125fea71e9b18ddbf8da18aa9def5b2785856f00351530c2ef88c55ffcf402fa0280254038451";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "09ee22a26010590ce22dab5c537c3f4510d5fe09e07caed4eb7fc4df953b991ea25a46abfe926cb6fec0923631b12a1a", "01b23c802d01d7e02bfd74e9a8a39aea48ff9ee55761d6cbd86f306bd8617e0c779b50c33ab20b24128c29ca2ca0a42e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "789eac6ff99e146b7ae25f90d7a0cabf36baf32d14916ee2aceea7cadc95d7221f56e5baee6d82a03307064ba32856e9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0785bb71e073e02c47ee2ab8fff41102391720d4a70db7199d765f8d9b54f7670bcbd47e175f6d2fa7b3f1b77d75ad1c", "019d41f9ae7bbbef490e32e5ef171598983de8f0b0330b70bbd6ca60d82173c666d7bdabc5d3ba1dbdb6be60a2e908e1" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
                bn_t sig_s = "64dc78d112cd6ed67d4323b302650a606ed41415bd8cfc40ec7438a70ee3d8680420e5f602aed591a324760c58140642";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "486d357e243fb7f40501b446596a02598e82fe226852331237ecd1347e05732ff26a0d005065f55cdf46ddf3ae414498", "1c80cffe49734b647cf53035093095ba7ac5a8afb9c23f8166530d28fcb8c19a6876bb05d6354f1fd24670328379e39b" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2b4b1d4ea334db2aa570df70ba3e078661822b236b287eb078d49fbf276ae2df7227ddf5172586758d1c3f1bed568db9", "7ecf665a25337f2702896c1cd96741d06a3753bc56122affd668bfd34e4a76031aee1bd6b1f1d3bcf199493fa7f5bf94" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43f64cc0732c0c45b271f4abf00bcfb5da0f6a3dfe093dbf8ccad74b35560947d38b36d1df2a32e5230e455096a957ef", "66f91078ed6f75ee8f4d8502a56fe2f28b8a765b4c7762249d3c8f4357b9a175705f3f57867c0a69aee0959ed9737d51" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6c78821410758dcc7b98cceeabd6a609260f3a0ad5335709bb6f19c0b6a17db13cc72db57ef755cf40b19e1f6aa442da", "49abbc0305b8d4a17b0208949e0337d9bb59f0fddbd9cff41f05bb41c310c1190551a2db1640f65326d6e2b0d67f729c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "7094186882938a8672b125fea71e9b18ddbf8da18aa9def5b2785856f00351530c2ef88c55ffcf402fa0280254038451";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "59cf76c463849af8d14cbe4198c9ea95188e9cd1dd67efc96778bf9963ee794dd063b167356b04273ee720b2e3430f6f", "3e96c199bf4c5a1f663de1c7268910486e72f280531fe6fdcefdddb76945978b4d2bcd7a191757c5aa001252ecbc606a" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "789eac6ff99e146b7ae25f90d7a0cabf36baf32d14916ee2aceea7cadc95d7221f56e5baee6d82a03307064ba32856e9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "061339234188a8e1e420c966802dc49cb8103cafbcbaecc4c18be407d4a678181ed01428f04bc9f32904a698d1026d56", "6f933f65e7b2851be983cd6d025b37a7291734113a1b89587ebbfdf4dfedb192e8f02954e07e23121b4073421ac01a11" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
                bn_t sig_s = "64dc78d112cd6ed67d4323b302650a606ed41415bd8cfc40ec7438a70ee3d8680420e5f602aed591a324760c58140642";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e", "008abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "21000c81888c4aa1b08ba356c995c0d4d5b02100d7a0766aa6a0d42e3cae0d5149cb3db3b2dc11a23bc0bcf70ac4417e";
                sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e", "01fb010d823eaa83b2ab83efbb166c8cb27865dfee67fe4f3115d4c98625e7fb9e8d6108188b996044c4fcd20acb993e" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "f8723083bde48fae6e2f3ba5d836c2e954aec113030836fb978c08ab1b5a3dfe54aa2fab2423747e3b4fa70ec744894c";
                bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "21000c81888c4aa1b08ba356c995c0d4d5b02100d7a0766aa6a0d42e3cae0d5149cb3db3b2dc11a23bc0bcf70ac4417e";
                sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "462117d2e33a7db1b95c8a6a3c7982f83da96817e749718caee7b6aa9c9da4e8f2ff7951674eed2b569ab846f59002a8", "50e6606a9726a9209c9e945fbf6cbbc9a487c4a4d81c52ac3684c26c3392b9bd24f7184821be06f6448b24a8ffffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "7d8b443046be350ed26c2e8d99ac20bf2dc4c401731692b5f786d48fd3c56ed3ad3a5fb424d565e7230f0e4f6c350eaa";
                bn_t sig_s = "84d28ccc2085b4457791b8d8a1f64ec4eec202b0efc81364464d7d2591f4edf95010a9264315fbf4d9a8e35e45ed94d8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "05d46f8f619d0c4ec1b1d17e31e4901e962b3d6314d21b77f45d4347e93a2ea95001b2745f5a23cdeb0e700f31ba4393";
                sig_s = "210b01315a6871fe35cdcead524af783be094e1faec9a5c049c724cf79eb793b78efc3237beda5dd36b1743098ba5a25";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "53838ff44cd184f466816340c3217cdde1ba5f8545edd0cbbaeb7f6a64e4642521ac015302f298ccdc3a04827f725ca8";
                sig_s = "5f0711f1e56710770639bf8cdf51535474767f06edeab32d4f48f92c305d525fda5f5747895244835eac1fd2af28be1f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008cb91e81ee5901b71a59a4f7c8174ae05fe3ba00f699dcbc3c9233265c640587b3c165593c2d76b5ffc4b8dcbcb0e655", "3a0e5d14f2d0e8efe2bd8aa260d8ace06bf964c51bab8207070a2d30410bb6b87aeecb7fff802f2d4ea3caf6e0e7e726" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "306ce4903ded55d260552854fdfb8e9b68f746df16ef4922f914a07c66754ff6d6996d009fa70515f60726ebc8eb4dde";
                bn_t sig_s = "481fe80d384cc129ad2b4d4f0803c238be582e2bf251f4f68ae5a916556257832dc4f4e97d4f8c920c1cfde5966192f4";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "38f6fae91830336a0397532725b0a6dc2f8fcda8b6dd9ca6a5da5d5f83fbe392cf289356d43b9a05e310fe4e5f90a9a9";
                sig_s = "26e038717d5dd4522b840326841aa735e43ba904f2e507538fdad82d7cd068fd0ab615f855b7d33dc7929443bfab7563";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "67b019361c256c87bdf26df225d11b8ae1fe491eaadb9691945083252601692542e76c12924e25094f42dccb235a0807";
                sig_s = "20823f55ecfdb8ce97429742ccc850a66156b4b73ba279671abd64bbd820c4436fb9cea575ad6c9370d3d7eface915be";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "69ebf332e1eb2455324a7572a17977a4e2955108ee8bd81bd6d1f555d608687f5bbb39858ebee304985baa7d09c830bb", "672b9c96684dfc007f015e39cdada9fe16db5022bfd173348caafc528684621f97fba24f2c30e3dc728772e800000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "1d1011fa8c26b01c7aa4de7c48c96f327a6c946ea84f19c02b7d284ce16bcefd700b14a7809fed4a14a541946fbf922c";
                bn_t sig_s = "6a8b59d5445ed2fe0bc09c1d47653113cc7eb53ad4e6d1abd3175cab83637e5ade4f7f8d13f7ed142e7cd36f2ebf2828";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "51cc988bbfbac20f6694ebb9fd361fe08fbd38477c90ce47314cb65a5203d97d31e081c0316dab6e3bbb0ab4b3ed9262";
                sig_s = "27ad4d9c28054c23ac606ff29d026ba40a08cefb5058b6917eabb8660473bd0056e3d38abd0b8e5f2e3f5e3adabaac26";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "8333a227b224d6ff2f291f5e23c22cc8e6a71c21439d6ae0745ca1548c64049d5078f978d5d07cf7fa90464a3456cbf6";
                sig_s = "67fcb7f76ea011cae03c49eb4007fd464c2c49046e34b61a1c1dc84a2061f1d8342e73d66cd3f00038a6905462069241";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4fb5688666673f104287428b5bae6bd82a5c69b523762aa739b24594a9a81297318df613f6b7379af47979ae7fffffff", "7e2d325b41fe831a23cb694cb80a30119c196143536ee334416ba437a419054c180a945154596b83d7f7c3a6b6059645" );
            {
                // x-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "721667f80d87c2d23c67505fb9c97d0fd8b45b4dec237e42591e59aaabdc8fc4d28783900648077d06948eae4a1fe09f";
                bn_t sig_s = "79d88c666d12812692b20e645a69366e9fd6caa22d76db1d55e14646e9c8e35cedde0f9a933d94dc9ee4c8c79d2025cb";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "307bc43fd7cdf9e526b1b2fa9ab7e482e1fa013f97140dd2f20ae1d1d005972f7ac424db31b871f0be4b80cfd9aa1e7c";
                sig_s = "08907c1531a8c979c747005fcfd585566bbdb399644c5576842df4456b6de6b44c71ed2cd301dc89698a4c9b121325a2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "5c85bfd1e059f87263a7a2105c274e029437e712e85a47f516ff39e1b43ddfde3375b403d9100ca74ff920b7fb38cd12";
                sig_s = "8a768cfbd67bd3327d58c5a319307b936e3020b4bd4959d6c27af189f8985c113d0f4ff997e2ea15e6f110d994b3b422";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "34770c73a7e42ce7a57d1de6e54f35f1752047f6513584c7b14bca17d7abc499f8ab037c70fd2e13a8b97b2ae2636886", "22421615ba363f1ffe9a8f2fe0f6e246fda11462a3ec000c685e09a90dbcdc2af6467f9ee69b5e7bead9b8461f4a4be0" );
            {
                // x-coordinate of the public key is large on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "0bb0a6b0952efd690c97d24ea73af0b706104d7293dbc3ee829f5f5e5bbe2b7304e6cbf771a8dd82f6c24552998730b8";
                bn_t sig_s = "5f2e71efa8480c19bdbdcb6ca40d5f66ff812d12a0a11eededcef465323902d563e236cab48e0854845a45fb6b19eb2c";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "146442fac12092aea525b33e3a6b6dfb316203fcfb894adebb618c6f672a41166cf40da344323736b7e5dd7ec136620f";
                sig_s = "3f2ddf11b3e8eafa0502119486294374154c3a1ea335944daa940f8078ba96476681bb37d8106d4f1737836eae166d5e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "2174b7e583e32e79cacb53c0bc186299c5b87f8d12fe8bb62175c91feb8598349f139bc5a407c4b20ac59a215c078935";
                sig_s = "8301e9d96a182667ec2e09cbb0feff876c98cbf96ee52b621ffb1f90d5538ba9c6ab64d925bc2542631a20ff2c375a21";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0086f0fc89b7861ec3bd582161aecfc95789ae402459eb7f3015b7dd24e20fc9b005c635fc290a0e2a9ff35863b7b82e3e", "01ebba489e923dad88146077914e3ae5c575e1bececec710962a18ffd91005776c4d9e4bd952c793587a70291ce478b4" );
            {
                // x-coordinate of the public key is small on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "0e258b20425ea2b4c073d2835781868417160cc3fc137b0b7686b24d7c2f83f032938569ab9f4beb4a6470804faa9fc7";
                bn_t sig_s = "73e6f23737d59c50bb9c1f6fca1a4ccf62e9d46cf0fc82336d4cb6133b0c9730f77031f074772d31b73ed781e0587735";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "55cd81d1afd8c732312255c475c6e6872add5bcf3d0878488cde7859f3fc713dc03691d9c33c2c3425e11ad94211d5a2";
                sig_s = "6b28fb39d20a564c42b5c0f595689b0b963d424ba3d390143554347a82b4290904278c182d7f669f8ee24245a97c61d4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is small on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "3531aba11c2f956c7a450039b37c1e4e4fb85640e5261b0692e2e1d32eb7d78fb6a142bac97afab3fc28d9f7dd186012";
                sig_s = "86c2fab72f7aa4e5b5571aa604392befe77adf00ed5eb16ef49daf9a182fbdacad226180751bdd89df94fd3cf7242a6b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "082f7dceb585c5ba4894b0faf6604da888a311ad9f41731a1d3937168a10b0795a1fae496cb9a90739e1c0a6e531e807", "2c3b8568eaa1c6f541a665ce7a66f78ea2d5893103e6028add62356492d8b5ac6ab8901d59621c33416c33981bd594ec" );
            {
                // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "4fb1913e53d3207a2699ddb10556e8896677846f56bbdf22c30821ef08e7d425d5716c2258ddb6d4ba554e10aa8bf9ef";
                bn_t sig_s = "02ab33fdbdcb76ff8ec00951b26152d00e4cdb464e91f9e2e152c4060a8117b152a882b6df202e8dfa4625cfaa444177";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "0deba649492a3b356758c5bd1f021803269b110c9aad23ff93bc4f744a114dc97a2fe20c5970d58c4131b5c662e4523e";
                sig_s = "729861e4845f89edecce431e88ea91da0e324ac0ba8046176ee966c1ff343dbb7e509acaca64f99b9e2007a296d60c43";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "0a317753464779f6f03647a3ecd5bd1c2cc437464ef9a199842a6644aed09d57fa94badabb52640d487d7d47f964621c";
                sig_s = "5ad431c073ecf9fbd8e3a70ed90ea31b9c7b9f6795305b0e93e83cf4f9a02a0cbe4ce5c386447f8b0f97031561b53a4e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6afe4ea7705492bda308b789d70da49457dde825d5258960a7a366e4665af9d326392c2672165ea4bbdc33374d88e749", "008475e6937a10a6f6a50f23de9126ba04e5650a1cd06a8066ca423339fc2ce53d91482744a4cdf2f937f76f12aae3f630" );
            {
                // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "82f269bffeffd534c413bbb4d05b0fe6c0c5c439c249e7482444e050384c21c488772f51099ed6b62b6d8268c3ff2191";
                bn_t sig_s = "37c3aabc5adb6d74053a7c7d154aac142435539e1a5ad5e4e52b4696e851e8947bc44c08241166f5461e9ffbd62e6e38";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "10b39fc11796007b4247ed9691aa5a3bd0eaa7f5368e3dfc140f76a7437881d334b9dd56a1d3d554e52693b3ff458347";
                sig_s = "382bd622fbb730eb000c17868e29328c538a4332ef7713bc412a1ab2163e35de0a0551fa367b43c00fec690d8f78e0f1";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "83b6ddb0cba84119fbf6e850390c5a32fc4a7d9ae2af497eb7e3f485ef4068f837eae66b916631a6e04c6c7ec5bdb658";
                sig_s = "2ef7f2fedd889faa079c744f9b792c09374dfb51ced559963733d448a5a30c12d5504173a19755792212f429275e0827";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4bc65262c22d322ea89146ccb5c60c4287b65a35228743a5b9dcd15493bd8642478987c421637dd0715079ec90fb8cd4", "7a45557ef653d0773dbe2630f8e000629ed8293e1aa4a96f3b159a245aa35ad92a1019c7e09a9ab75ba43c0786928237" );
            {
                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "5fe6e8c9905a577c8a9f9db81663c3037bd3118ecc17be52a201fe03b8c54b885eae3e54c13ea1034def0b123cc103";
                bn_t sig_s = "46e6a23ba52f9db143d705166c33bc5b601707c22d16e9255f95bb4cfb0cf0341ceabf3640213c7c696439fddde61093";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "1a65b2bdededa977bc586eaf43a9ba6e7659b078e84eef070dfdb21488dfac9180c51385924d684ff1553f68b473e215";
                sig_s = "7c2b319d06478b6ed656b409dee544f053e2fc3b149dfb1d914de90ec39ed4fdc303317a5e7b9b8e2182a8cb2fe6e5b2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "2a3cd54edc69991e6e31b60b90679c61152dad72ac1ee870b58f0b2fc841af4c8192ba120825e2db9980a0abfb018a8d";
                sig_s = "0ee72ee0ed12588ccf2d701321a90c1f4b8923d263229ca606af0e0a82e73c7e682c9c538e060fd851fb2c4e60350598";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2ac393f20c110e3f97065304397eae0e23187b2b6163dc66083e82aff568426843056aff8dc23eebce297f747830e217", "34c935671391c6efa8b46c5c37b3f84a82e429a7580feb9a1383b55c83a9398e8ecc7b15d699e63962329102a1576f2b" );
            {
                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "2b8fb41b330064dc47191e253e44654acafd33d18791863b83b86cdca0823fd6ff0dcace712e6662f5947a291c666e28";
                bn_t sig_s = "511d38cb38180f1642c23531753fd438a3eaad79d049340ff010081d2e007a64195d1db2167eed84ebf5e161d9ee3ef7";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "72152ef2e229b4e637d65c486d342cb3f075f7d9f64e00a5a35cfa4d11099d02f672e648e91aa71e354b7f66b644849d";
                sig_s = "4bd22080c4c5660908dc790c61e58df79eeec32d4d400ead24644b046c3b8ba5db5fc608753d1da44b2eb81669659efc";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
                m = "4d657373616765"_hex;
                sig_r = "0764c51cbe588255927756ef3f9e84925486baa4ac7e4dc4f8e0889950690728aa2f748bfbfd7e2f29fc5b9b58a2e4b4";
                sig_s = "522f73fe54b6efddc2566bb5d020eb8183d88f987219c2df9cb98a33958a2698f0384ce93578b1178233bca0411d4754";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP384r1_sha3_384_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP384r1_sha384_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP384r1_sha384_p1363_test.json'
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
            auto pubkey = curve.make_point( "192ed5ce547d2336911d3f6cecba227f08df077f6242a9147a914e854e6e32d325fd23ccc42921dc4a7e4c2eb71defd3", "631e69079ba982e7a1cad0a39eff47fc6d6e3a280d081286b624886ba1f3069671ec1a29986d84fb79736d2799e6fc21" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "0e8e114a1c351405560bf8d47b166bfe957087a8003b353433b6144f7ee7d6f79c8dd14ef229fa7a2f2782bf33708b91";
                bn_t sig_s = "83aa7ba485dc060df9922f9ccc5da29adb75d44671d18bad0636d2e09c5e2f95e892a79b9fd3b37e1f798b157b567a24";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "9b472fccbf6d812d65696852cbfcadddaa9ff8b1ed8f8be752cc82bc2aebfc9f6bc887fe5da9bd8a6aafb4c21c74f0f6";
                sig_s = "090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "8cc7ac93ed54a23c14b37b772561584b13c4e191955491e8534a2480fb830d7ec6d74480ba71ed0ab5b75985a837d5f091";
                sig_s = "00090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "7e2b0d3887035922b95176a9d5cfd5e07fbee961ed19217eeb605a1d2d1c4eb032ace5607955c8960c60af43b593d9d4";
                sig_s = "090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**384
                m = "313233343030"_hex;
                sig_r = "010e8e114a1c351405560bf8d47b166bfe957087a8003b353433b6144f7ee7d6f79c8dd14ef229fa7a2f2782bf33708b91";
                sig_s = "00090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**448
                m = "313233343030"_hex;
                sig_r = "0100000000000000000e8e114a1c351405560bf8d47b166bfe957087a8003b353433b6144f7ee7d6f79c8dd14ef229fa7a2f2782bf33708b91";
                sig_s = "000000000000000000090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "95c7c160c094d4422528af5fd56ee1234ee90dcd68d721b937f609f8bbaa1bb9b5e2c5c3372bd2a25796d8f056b250a6";
                sig_s = "090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "8cc22d258155c98f29733abe326aca7e59692aa6b0cfd97e252f4e083813cb9de1215ebe7f4b6f1fcda440a9d672135041";
                sig_s = "00090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**384
                m = "313233343030"_hex;
                sig_r = "01090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                sig_s = "00090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**448
                m = "313233343030"_hex;
                sig_r = "010000000000000000090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                sig_s = "000000000000000000090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046566";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec54";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3335373632"_hex;
                sig_r = "705c790f8f50061c508c15fc9aabc1f58193ab15b394ab2195e358cb620a5bf4b65449afb9c417bd1a3105e53a9742ce";
                sig_s = "6dd7abda4001bc416982ab4326b5d27b1280f02b142f040ce2497f9e153e4e1e3a35c5ffaef72694e677872eb19ddf36";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373530353531383135"_hex;
                sig_r = "79df11f0221de0473ccf844ca702b0d3981b8a97eb8f6884f4efeb84715d2c6ede43208c7e98db8e091e6c917fd9f0bb";
                sig_s = "1da9881957bffe209d61dde87ecd9c9d8c5cdad0e4cfb6e08ce2e06a431c3eeb2d141d3b13b5baac30ebfd622cbf5ed6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333633303731"_hex;
                sig_r = "1cfce0ce5fbf6178abb6c27db2d4a48ba5797dc9b99cdfe52f749d079c789ecbe1bd8e7de10e2ac7b83d0381ba0c611f";
                sig_s = "24c37f70691e443b1b70293100c98cf5494e0d6e0b14e4400eef72cd0aa10fb4a689f6b88ae0f0abc3af7d09eb1b0cf9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333632343231333231"_hex;
                sig_r = "8c297529b9ce5401f51e5eaeb53115f4b07066c79c4b54a9fac00638fcd16cfaaa9626dc6da6598833d924b0b92867a6";
                sig_s = "787762678f96858f222505f110b97a24987338d5e5dc0c290624c243904f65c0b5780517838a7ba217fac9ff59b6de4e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353838303134363536"_hex;
                sig_r = "69fcb752545d6576b0ce45f8903651831e79ef0e173ad1c8fdad99d6b380aa7ce4a588d14aaf0a307e5bb05b81945d10";
                sig_s = "3fc4151f72c111cd2b0a38fec138083f7d058b7389a266f7030fc55b7d69e490aee05f931c55b769cae93229e7af5e69";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313436363035363432"_hex;
                sig_r = "1ff39aa7f866347b6c5a0b62bbc9329483245d524e93dbae9fc350197143460ba6bff2a12401ac12c575fc331d89042a";
                sig_s = "1591933f0e33894abcb72c0e53de6889a00ebc0ab5974d3ab8613a493b168db33da5118f3f3477a73df49af27ed80d05";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333335333030383230"_hex;
                sig_r = "61d322d16ca80620bb093333ac1f7b5f38ad5d1bf39b686471b3838d194a4337d3d0ca300125d4b724dc6c7cd1b0aa00";
                sig_s = "595b3d2e24354810c5d20dc81b2ba3d719036c7d4073b170d31d210f58f3b5f7ca0f03007e33702be149517f8ed69ab2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333936363033363331"_hex;
                sig_r = "7c8cd6b9ab6068297f8bd2f4fb5cb86182843b80dd7582317e817899c612bf13bcdf520dcd61353f27a4356dbd167070";
                sig_s = "4331c14c7f033c5f6e5d9d2de76a9020b426357d5ddbaf125765b8ed476a18ebe1bafaf9417bbe0f8f9672fbf20a5cde";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333931363630373935"_hex;
                sig_r = "771117177496a9118f2883e57f63a58998d57879166659314c508b6028094d4e16090f277acfd47e097f5bef3dc65939";
                sig_s = "3ec4bc040aaf47f9acba6093c82c3e07c1e607ee238bebb5db96596964bc3af7e57b808c2f6be04128467a56577b40e4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343436393735393634"_hex;
                sig_r = "6a05488b75acec4718d7164ec19dcd6d351a5fb2852afc4915e9ebcd8073897a5d559dc9ec56a5aae400dd0cdeefc716";
                sig_s = "2e511d8bf60ebe468f5e045333d43d4be59b4393c8e650e3e6fabcbf10da7ae5f2318bff047413df4dc17fb372d98d8a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313539343738363431"_hex;
                sig_r = "8542c58427f1deb1dbd36227eb96fbff153edbd23ebd13e786a52e4863c888a2dd50941654e551a4fca91b5bf3519789";
                sig_s = "82b68b14b608032945bde3d7061d5f687458ede1b302af8842449788f8314b108579f6c528bdc800afe6b2c8b185fb6e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323431373932333331"_hex;
                sig_r = "58fb974bef2acaf2547cacb6f0cc934b5991c66eb7a223755209acaf5b9e4b0fed712c76606c59c1014ba2c2eb1bb322";
                sig_s = "7d9e265dc09e031014182b369e15b4a34dba3901062d627cffab561e73d38bbea907272346fbb247d3ec63564fe1cbef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313437323930323034"_hex;
                sig_r = "065ed5994d4b498af7f5ab7d4c08810cb76d242b5d8b7b5537cb8afa6ea852ab714f66b144a486d05b2a56f2056baa11";
                sig_s = "37e676a8d535d0a818dcecccaa4783db6d254925a00dcf6a035a7d9e0d677dc78195a7eccfc7beee8e8eea7456c3699a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373235363435"_hex;
                sig_r = "25c147aa99a615a34a6bd152d17184c48d28bf79fa6fba928e678ef638a064da79d5f253f7feb8915a40d6437b7bdfa5";
                sig_s = "0cf7e14c03cf67895721cc2fbdd62d6a0f89aec43dd123d51f813d9b5c82850c07d089e7aea0df2f597e6a1c8e2bfd29";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37333433333036353633"_hex;
                sig_r = "853df8d619f3aa7dd0bdd24c34d387cc59abff4a0585e2e9c82066e4d2e957b0437031bc1284ba3d39545d5e850e27a3";
                sig_s = "0435982cefe2cd1581f378c6be16ea77284a178b3f0dc14c169c9ed863cc4a8d8f78651380609df5e05b65041dd7a201";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393734343630393738"_hex;
                sig_r = "1b29b1e60895a4920d6861836faa227765404602f4bba3b4faa888a4b1693a7c8b585b59b942487122a9889f4f1454ef";
                sig_s = "7d9fcfbc2ee71fbe32a4262e4777daa38f9722b0a67500b950aae4b469bff9525ae1de389cc17ae719e24ecd19728441";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323237303836383339"_hex;
                sig_r = "8937dd05004f6e782a2c91c8d79f40795d169fab6af385f91f5cee928c2a22869f10938ee2edb3ed0e0a0e38144d5064";
                sig_s = "48c692b4b88776b0158b99e15e99de3955ab9d884477418cb740ff917a704c7707f39954186a03977cbedf34bac02715";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323332393736343130"_hex;
                sig_r = "1e42fae83460bb8f30d7d6bedf984622a55035d502fc2d7f9ce52c56515fd66d1d593094d4167f4ae051f2b12d0e67ab";
                sig_s = "284d00f98f29202f03b37971978eebf2fbfb94bef2b4d63fbed88c7d29d18b61ca409882aeeea97e30a0b156dce2bb06";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3934303437333831"_hex;
                sig_r = "2c07e185941b20628df84808ff9a010e5e112c0632cb3231266e8418ab06f6f18eb41f2f98a5a0ca1a462339228fad9a";
                sig_s = "29051e9231d68ab462ba7aaee39edef69c05f81ba7eab161454bcf4969ba293463e6de2e784677e8d2a92953400fe957";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323230353639313233"_hex;
                sig_r = "030687253ad2ccb94342d325a8ad19278ff2ac8cfe00209ab030c7997b3008d4e9588ba2922d62e75a5e6cb842324f72";
                sig_s = "752ae1bdbd94e35bc57815d2758b1fdfee706f410c0ed966be8792eeb54cae8631baa0c095e0742d6dd7d1e0419bc588";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343134303533393934"_hex;
                sig_r = "39abdc1943608ef4f5c46bac7ae1e23d2e3252e6fcc2b0ce8f41501df024b7d297362401be87b122bb9ccd98daa533ce";
                sig_s = "58f8d8088faf75fa06d76e8cc10a1d7bcfc225d58b75d8a204e6a5ce4d6d95146e853b6818746cebf7864facb44a2189";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393531353638363439"_hex;
                sig_r = "510f5602dbf3a095276e99a67a65249217c6e6c168a6caa64f5aad806b57d29002e60786c6f3ed274690583d18cde72b";
                sig_s = "687568eb41af3f5ccf7f2b16e67a1f4fbcb3bf683d86e49a61fff0c28fc03d797a722af9b02c391a49f5669c7968db1b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393539303731363335"_hex;
                sig_r = "84bedafb46873274ef91de67b20375c7698afbe37f3d5bac1bbcabcbb4aa6616b345267fc9d5285baacca6f1b694619f";
                sig_s = "89b39165949cc435503f4a6ac5754d2afddb99b55a3ba840040d51624a0985251f2c9787b5cb266a218143db5b041879";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323135333436393533"_hex;
                sig_r = "251b50b63fe1cbae210431bd1e76563f078454f7c2b2e475abc1b7758920f03b971112c62ca6132a480738768edc35d3";
                sig_s = "8b8c1646900601de4fc9c9dbea228ce9c9edbbce7c31a42d3cba580e191c92d123e11c0634b87bc094cff16e209b6954";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037313039383330"_hex;
                sig_r = "34b3c6afc0fa7a75385e3d0dbfb237b5c76afe16f0f69e44533b7ac3abf4233799201504ebec0310b2fd7e867f9fdd01";
                sig_s = "2f831f5955c2e4fa5b298bef8f09732d0b15ea7ce141a6dcdbbc60378fd9c969339e826def5681e96f0a1dbc36adaf5e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343932393339363930"_hex;
                sig_r = "335bf6b152647bdf8a3c5de8de3c69832101902679bc802612d2f4bff8c7ed7df225a080eff6deaa5dacc74016c5ce3d";
                sig_s = "7f1b116f8d27d894ffe6ab57546851baa5513d110e6960d713263afd542e97f01f4df4f7b64d49496d22c2f6c56050d1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313132333535393630"_hex;
                sig_r = "329c5d35adef357339f901657af55da7b041e8c18374c79ab44449b27a83022800f0c938503bdd85b7884a32df9057fe";
                sig_s = "74f56101c7f7b36d634c2175a0d17cec0546b6cdf18e86ef9abb6d6d0bccdd0442af1255e02a5dde707840db48543170";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323339323735373034"_hex;
                sig_r = "1ac3d463df221945adbd28a746817ba83d5957d95657c724f1ad68b98bde6bf7959f7363253ece174d7aed346410dc21";
                sig_s = "2a5a30a8191a4883babf69ba883af7f5067bc990f8dac4a35bc6ef387102fad85d268564c61246dff17510634168a1ac";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303831313838373638"_hex;
                sig_r = "5cc9a074e10c41724d55502d72430d707ba755c41d568d79987dc3cde45cf6f70341f91fa2a20e3ba5b57febde05b5c4";
                sig_s = "6d8025162af30cfab2cd16a1342b4174ae171dc3c75bc1fe994ec6c0359295f0390e65856aec5ebd894a15c68577ab0c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343534363038393633"_hex;
                sig_r = "0c13ddef4e7e83163090559fa592edba35a92d66e54a34aae2905a10b03a316ffd0c013f7b061909f3a924ac25f1c90a";
                sig_s = "40ab2d40b4007fec32a647784ae4a2d5cb4f7042cce8c374298c345180d0e38aaa5d73875eb859b082d0a17cd496d20f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837363837313131"_hex;
                sig_r = "0af74a3ea3c4121711d10f2e4d725031b1b08cf8eff22834748402453b8eaa00b1578611ee45220753bcbd20a391402e";
                sig_s = "15eb2daf4fb9321283f69157e7c747d6376759d0130e790552b4fd89577139a28daed43ba976a76bec1c7d53a49c9822";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303331333831383735"_hex;
                sig_r = "674b6ac9890dcbaba4d744ce9992e9dc698e524b0d1cf4d76d355372631d6f7dce6ff5a607273c0c1469d8e5b12ab60e";
                sig_s = "7cf8f98328f920d29475d5cb38bc35fe71ffd87f1be788d202908eb939c76b7694cecfc21dae50f433773d75e279e303";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323535333538333333"_hex;
                sig_r = "89ab51357a7db36d1c26b1e906088b9aa3e3d59658e2bed55dd03deb56908677a59a4b24cd65eae6351b03a9300ae518";
                sig_s = "395e10a6accc3c6e566844c4fac4caa2a8ceda4751df5aab5b3275f825c5940b1db60886f1395318110ca53c69328352";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34363138383431343732"_hex;
                sig_r = "5b3f30c83acaa088a372d5588229a3555dba14fbed8cbc2935f6f6eabd8077c853dbc7b2e354683d41dce5b5d4c9de58";
                sig_s = "767024280e5e131b4a46d66b35f2b304a55e6481f094b355e873a7f861029602097a4d300136ea005bf5fbc10843ba95";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303039323435383534"_hex;
                sig_r = "32e8abc36623fcb2034662105066afd71fae4d75b8300e32bef4632fac65ecbd285c4061ca64f6813edd2abfbcc213e8";
                sig_s = "0b0013e2a56c36de1ba19a9c304869f3d69806ece6f4a801c27a3d4f1c20af5eb175e95e734ef637653a6cdb2a9ecb44";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373536343636353238"_hex;
                sig_r = "45df529d2531d48cab412b680cadb532cd6225304fb742841c89545959b79e198c3b1297dc5c4bd9aa7549193e0780d1";
                sig_s = "5c8f62fc4852069d35232aab7725715e9157d1aa688050f896d690dcd4e41baa66ea6f9b34deea5a607cc391ff097d7d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313139363937313032"_hex;
                sig_r = "1020078f6e5717538fef879c5635d4d7d52721be1529585b0a77083c5f347f21b1316d0399a8bc17b367336475a6d97e";
                sig_s = "1ade87ed2e2bdb2481a027dd3fa5b93a81f4ffdc33d4a908d97b40f841821c02929b036135f419752c88d57509d17bef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323333313432313732"_hex;
                sig_r = "0d93d5c63741447fdbed17a738a41efdbb7093333797499fe70d5c54bc86b6bb650424bbd64907375ef92efd13ee25ec";
                sig_s = "66192ac1fb22db75881df7ae890da4953a74fa954e0b5e6b692eca23c3bcfd5fb3228d092d9991071baa4b6e8fa206ea";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363733343831383938"_hex;
                sig_r = "049334bf43f7d9c213443c96c4ba119b335757a3e69ba873bdc4ef642139b8687a8a5782b6a900211d6fc1ecf14c2cf9";
                sig_s = "182990bee4787267b6d63b7ea67a25852951d145cf5a39d201babe9f3f1120924e5b283eeb636a8fbbb0c2fc66ddf755";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343630313539383237"_hex;
                sig_r = "6b0c248fa39317621af5344f978bd765ec6125cce2f40cdddfa40f7e8c7f4fe9216354bdafc2067288c56794eb5d17d2";
                sig_s = "7584c077ad35b58fb29403b9c2c641271794e26b241dfc8d74d4daa7de3f076c9c4c6d3909e2c0ab9b9a702c0812eead";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38393930383539393239"_hex;
                sig_r = "8c048a8eaba1b654c3f687df01714df3b61b98e578205c804a72bde32daae87b37fd2f9f5f82b3c5f7b4a007eaa1986a";
                sig_s = "30b79f44c83bd52e537ccf9a35772fab5ba9faf0decbe34763b5ae280984ac7ff27fb8dbad57218c364b39dc2a03b5af";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333236343430393831"_hex;
                sig_r = "2ebcd94d17122442d3e7bd12c4b609dbceef69b3246092e4ad0c83d602c2516e09169b592fdf61a7e881e262bf495714";
                sig_s = "70392cd4e5e17606608c2e4ffff7a9c0e9171198915cf7e50633263d7e071954f12ebb1a4f4acc7683a160d64dda3b88";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333736343337353537"_hex;
                sig_r = "4d7191596f50b8309e1490895e62b16c415c1f7b50d2a4260904bc5b7bffde4f92687b029f326f4b48e6fd8d1f19ee50";
                sig_s = "0a54515fad47bb08e586697f28e2bbf98d7575c7bb911bd74db3d9aa848475bbddac66181efd63a24918dec2dd01a2d9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383630333937373230"_hex;
                sig_r = "6fdefa7d912cd2c30cf12bae608ab87de12d49ee084d239081e89246e4939d6071dfd11f7401894aee9c13d11013ec75";
                sig_s = "7937495dc0a3a3d66c43945d99cd98dc842ae8677f14d649b22c1e7ec14857a05639ec1fe08be228112832b5e32fcf15";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383037373733393837"_hex;
                sig_r = "05867e5f8abd704007b98c1a8f2c69f4eea14cb4a4210262b474c4eba9073374cab5dd1bb5c781df040df32bf7943187";
                sig_s = "68afdc70aaca5f1b36ef32593d889e377d3f83b329386c982acf9b401b7cd26b75a5389395c15d507d7d67023d6d07b1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353731383636383537"_hex;
                sig_r = "88d5f4069be31fc58a38fd8de9dbc7fec64065de4268d41c8db799d0a20ae10492c7e80b30034b7f321cd49b2b9c3f33";
                sig_s = "09912b63c4f88be77211ab533cf13f2b63472006aab5e70df21b87301fe5139aaed4845a421b0f076f968ae4b32490d2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38363737333039333632"_hex;
                sig_r = "750e5baeef6934b36512572dd330fa88353e321a521363bda889fd257e4ea4024fb5f92e39f265d789d2a949dd91843b";
                sig_s = "18b8467c63892514847c3b98ee279e3f41b391a47975d7f4d6669385ac0bd2e322f88608870310b635ad28256d8dcab5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343735353135303630"_hex;
                sig_r = "8bb6569737c5e01d2596d3ba5d01890f231136c69c6c9f42a944f06602296b1159f29fc1d98b68be06f3052c5fa8619b";
                sig_s = "2d1d4ccd79b00998acf03d3412888f27d274b8788742be27d798dd7db654d964fa4cde3384d88c2a50247792e8820ad3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393733313736383734"_hex;
                sig_r = "277b8fe00651998cdcf8b4f40795f454e4dca2fdc2c10dce1fff8f0c852aac0bf6183b1ac3c3826706c3e659854198a0";
                sig_s = "0d71f3f3f681fc391c3cfdb81b61eba0155cb4a8e9ce8049cdf9b459aaf264525fbb893eaa71593a9618c0f117efd90c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363938303935313438"_hex;
                sig_r = "269d14d9867ed23410caf24f5f9f171bc0e52f006d8d16c02c81f1b4edba222de7351ad72943ed09a2e7ac176a1b2156";
                sig_s = "4af93b800fbdca45ac74cfd22cba9a508739f8fcf3ce14e55c39bc770a143f809970e836447a4542d0bb367de6612c89";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373530323638353736"_hex;
                sig_r = "40731dbe64636cd5ef5d2560a23f3891accf0a530a446c6ad213b4ba7ff9cb505aba9331836ab8a98fe565e866c87979";
                sig_s = "19eb3cf6b5faf11e9717d6d0449624a509358936dd0067ffc18f22e6bcbc6aa1df3a45f15ae732197790cc6fdb92c3f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639313439353538"_hex;
                sig_r = "84335a1c93d996e36c22aee4f33ceff7c6ff088cd5604db8275098600666144607bcfac7e695f2f79a775628a1ab6f82";
                sig_s = "28ca8cdc6bd772cc9f24c14ef71332f192fefd52d03b8df99a257f315e0f6f3296e4a45fd182f06a3d2ba2779c10a40c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313734363535343335"_hex;
                sig_r = "520b74d5d33ba289ffccf5187a6000380c31304b1d6f8fb54d880c1908fbd8df5e0857ffa8ca344ff7a4fa9bb6ed5f38";
                sig_s = "03ae877bc1f0bc8e7c9039381f0b66a52047163cb78eabd7a3dbfc538b424fef31d1e0af76c0e1bed7936a88338f1bb6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363434353530373932"_hex;
                sig_r = "59492f3e58b5bad9412105b4824dbe939d7cb2864a27680620ac107285505c42ebfaeb154c4eb6d9e6783a12abaa35aa";
                sig_s = "8b4114caf3260e509658243a5f4190e40c268d012578df86866a4e9503c8490804882d0812aa105e245c8c46fb36480d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353332383138333338"_hex;
                sig_r = "421dc854479aa611887aa3689b63276fbdc16ec7d3dca449b482dd27b1403c911ef6265ad625279e9d83ce7534f4ac3f";
                sig_s = "2852e16b4276215a62ebcbcffaddbdb2358dcea7084948bc948f9b3d0f91693aba66362d4a2cec70f7952e374886211b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313932303736333832"_hex;
                sig_r = "49110e413aa3e02fc05937d100ae4db14cf3f0038b38679a4aa297b11f9c47f7df538df8cee30efda4ddab2cc51a6b0f";
                sig_s = "018a09a18e1e7983e52b8e6cc8da9c6d7155c5409082f69587420906b75cb5157d3758e992b223eb7e9c274fbff4a973";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353332383432323230"_hex;
                sig_r = "884cf64ce726d5758efb9f2f35c92dcc6063b01b7432faffd0f8186ac177e31129633a648a1a6986148384a7d1c4d3f5";
                sig_s = "01850718d7a2d41eb9892f5440ef4b9fc8b996d3b6742eaec3d40b10c5caa890b9a853e1d211f7fd1178116a9e7c5f4b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313536373137373339"_hex;
                sig_r = "0d9dbf8ebcf80f256ee2d1f4fb45cd543381f6275c4c10afa85208828e27e6fb3df3ca7491899c68307db66a505c7a90";
                sig_s = "1f0db26dc691680832b3e359905e5e632bc9eaefd1d5eb4f058a0d88f8f2df0d1a60c2f77172caf6554b2d256cce8c67";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333033303931313230"_hex;
                sig_r = "6fa1802ac4c2e79b8b5a477b0a5febf630c29c089841484c1d569daedbf13c0bdf793d0a8f6915bdc67dd1480824a1ce";
                sig_s = "28b8063258111e32aa10af0b2068c7f54f0d5e9f02ad39a415c91743d6444c20156c3592d2bcc234f265b46a35864e57";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373335393135353831"_hex;
                sig_r = "3dc1363dd0119a5054afd99484026a2692567d2fbeeb4c6d80a30d22f166b6304544246a35ba854f854601397ce45bd5";
                sig_s = "2b020a770901108ce6ddf69117a2e80734788171604a8f0571db61a4a8c3c4dae33af841afe4a9892306b4f9ecb19b49";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323433393636373430"_hex;
                sig_r = "7b984bfa807a8e9b0eef94ed28c24b04d42e0664fbfc0ee1c1b5945c8f0e97fdc515fe09edd6cdaf7fef3151ca4044df";
                sig_s = "4e878741529d7a90125deb8fa5fdab8e9f7d254b8aa48a59a2f335c7d43402f2590f1082c76b2263582c9dd98ca686cb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333237363032383233"_hex;
                sig_r = "87731525e787239a232ba3c24b9caeff3ce591c168227b8e2864140b1d7c0c50a7d5fa9f4f6468bca817458c171aa447";
                sig_s = "670598b6e5dfbaab3b622bad9b5b6ae42c9d27bd45b1b0b892af9fd9739dd50414e8eede3c6dc10fc224463b44c8c23b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32393332303032353932"_hex;
                sig_r = "1901d0d861205cc3e3f4a189b879ee246486f0cfdc481d63727384feedc46c8baddf891a6e6eab6bede4e46bbff16496";
                sig_s = "4017c9eddaea3112f26f7c6ee472ee1983d7a296a7402295794fddd9e267fe62d85b07b99e81ea513eca8d1a67e705a0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343039383737323834"_hex;
                sig_r = "04143d73f140febac8fd4d6762b9a55bc93264cc3372bf1661b35a4b11be9af7910d3aa8e4f5cb5eafe1de3a9d969577";
                sig_s = "5966b4e1e9ef78e523916dbea37e03ecc356f466441dc45b9b98fe6d09af83e7d57a861c5d2cf94bf0b87f62752b2824";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303735363930343132"_hex;
                sig_r = "5d24a6cb0a9f7f8b9f8d72da989fcbe85c9448b425a368207fce8421e5a60f029184f18611b9a5a1eb66d054d36057da";
                sig_s = "32b8a4d4aca17e8335d84f2a68d74f38d8cce5297efe9e6d0e1a8e5bed1b5759bcb73cff28062963a28bbc1c571e3e1c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333231363233313335"_hex;
                sig_r = "1d10c1ec203fa05deed62644b809150cd5e3fa15c9129156fbc0477742328d8d35b1c4ca8baa6138e2e12936a0f4c332";
                sig_s = "4a029bb52ddfb171e4b125d3326deec488cc9f6f2b36d051a35d75c1de4b7abd178c7d4390e511f14d58f49baef62dfe";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36343130313532313731"_hex;
                sig_r = "2dcda31189d8d179f7deff208aea8bdfe0cb08a6da46f663c5ca649c84d8fec9c4495921c7791d32aca42557c3bf658b";
                sig_s = "67536e336428bddfb0862bff5bf5d5b1694b82c1e1485498e14fe5c88f75a9d7f520115a35703cc30ba0ce973815189e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383337323835373438"_hex;
                sig_r = "2cb81c03c3cefc417fc60f19b740e230982e0b1c68ced12121300d533f485597d1c532d87b235d136be3a43dd85882ca";
                sig_s = "48a04c5d8d867e8849bd3b981f010691f0e7422882573bd5bfcc33d6f069a622d159ca71bd562502ec001bd2b453712f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333234373034353235"_hex;
                sig_r = "152464668cefda80dea5232d36bf240ac325e3ca279d8c8e0458306b18fb12ac1ed16586d2d07562691c3205ebb4c774";
                sig_s = "3c385567269279e9bc5a2d076ae9a09e790d1d8d08978871dfc586298f56121b4bc84f7891e91c3d7612249d320e363f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343033393636383732"_hex;
                sig_r = "052595a16d03a138d656dec75a5540b80f7efe63b193250de3bf811fb2799d7eb9a6ae274ac953a8fbee741dc1f52100";
                sig_s = "55f0594ffa8d32b91eea8bf079b8f5a9f6b60888500225016095b3e71181ff32dbabcaa5e992b43409f55467bbb65125";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323237363035313238"_hex;
                sig_r = "296f6b3851553203822d7417c176eb3ec5e556e352d24f2834bbdf7089a168e637f3e80999e7a8611466dec370590029";
                sig_s = "64f796945f53fe0b27bbfbc5b5e957d4132c24c8b462075e821bca24983e8b8f850531617a42ed3157dbe20eab31cb28";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393531343838333632"_hex;
                sig_r = "619380558cd14ac909b565e049afa224f7e720af1b22e18b59cb055fdc0f191deff46a6050d1642c5636c032e9a7b46b";
                sig_s = "3c3fd2f278f07954936c6183da8aafc0f61319d9a90b7d3dd11abe13e55e2afa81512f384c13331af1d6fb4d7c6929b3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343532313237303139"_hex;
                sig_r = "354ee949bfaca35b1934e88e036b7f376006b79886133d07ff4aea3e057eeeeec0b93f629961c9ac1ee188c1c87e2cd2";
                sig_s = "1d02624a9110f7bad63ef70e134a7ff572d772aae30b4de679494d00ba9cd835d4ec840d772af9f7c0b0dae8cad3837a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373331353530373036"_hex;
                sig_r = "881e4eaeff3d3ed173daa166223d9583ac8dd28a310765e7261b0ff52b2b3fafee805d613258add6d056157ccc40da73";
                sig_s = "53bc28cffdedab6452161e05517194e66afcc14d107d1e5ded729f661cd6630d8b6581a8c25251ed7c4b5c364129b58a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363637303639383738"_hex;
                sig_r = "1734f666ae2d87271d9ede0da53ba8fc6cc2f83edc15dd26b9349c9e4cc5380434fc37b4ffcfd9b781f07125d85dd660";
                sig_s = "531daed4b855e9117a1ebafa232f06b47f50be4386db27ffa5ceca3e247be95497565c0c97b437d32d7694974b22f2ba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343431353437363137"_hex;
                sig_r = "296917dd85475f8e7b6f858e84740bfa967996e173d63d85aa08f1b6d3683097395e4a7648d14e0bedbbe3667d3db4f5";
                sig_s = "4d3e0279e93bb192f24418a0a05bf17238dcf78dbe8343e55a663418106d7ae22845943459b2641f45ef4ed606c53437";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343233393434393938"_hex;
                sig_r = "47f3150db2f4fa598ec25dfe864e11f92bbdd5d6046aef744b794f56704e323cde1eb6eabdc3f72f8940d6a6fb30a1c8";
                sig_s = "4e41a74f6f6cd1950df41133c58608fbd8fb92b17bd3bfbeb1c1cc778489a4fcf884e8006546cb69fa9d3492652d1255";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383037363230373132"_hex;
                sig_r = "41b903c255e90cb719b74684ed9700a924362ecd1cc8ce35b44daa1d41e3ae2ad3df2d01b9100337efbab68c53c6c76b";
                sig_s = "471f451c324025ddbfbe359f1d3ac5e40f712b4e8ae0bb316f54a1ae1def08c95f53ecc51afc375de4368d03d5095964";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313634363636323839"_hex;
                sig_r = "61b9b042fd654ca9c685aaab03ed0544e39e1848370537a0d0ac42ea7453d6853795695dda8f4c349b897c2f61f95036";
                sig_s = "634d5a0a8c8571f7685c6c4b68de8b2916d8af2233693a17399acb6048a4d1416ed3b2f91b7853868def58a0eaddce51";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393432383533383635"_hex;
                sig_r = "1ac6ec442cbcea48a8c404ac27e42e2122a121ef8484bd91c04aa259438fed1ee8a80ba59464b8a4351089923bb01e92";
                sig_s = "78c0ed4eea7fedda04dad0d3f0d228bc54148b1238c63428fc39a772146947798965caf7ec9276a05a972ca1e4218f84";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323139333833353231"_hex;
                sig_r = "6df0b36456bdcf91f6657d05b93738771f183912e27b9fd888af4850b3d979c4b7cb042f27e38615f054d51759381318";
                sig_s = "6a638be5f77cbec37a9766036efbc900498ee4fc850ac983e5b602c9483038da987374d755aa089cfd50bf2cc2de3b95";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393236393333343139"_hex;
                sig_r = "31c868d4f028e318c6913a8d1af08abb1f8ad961a85338f8baed7cbd8d79e1337f35be3b03f1f62c033f1388d62b701e";
                sig_s = "77a8d63de68f69ca299aa3ebab0836d1e717285bf403683e03210bd2a333d7b61984d1e13918913c8d1e7d6a93ab7f69";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373639333836333634"_hex;
                sig_r = "7d45c7dfa59f13830e9dd79a283e2129d5829be4cb84e04369ed3bfaa08fdb38ea643cceda163fdbe5016623d3f1e41e";
                sig_s = "5b51f7b0ca780125dd6f60d3b40923fcafe6e0d49b84b3dbe508bb169459495a8420028a3e4484412048429e67ca6037";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373335393330353733"_hex;
                sig_r = "8732951e64e15ec1203332b9ca9a1dfbeddfb0d1231d0e2898c099f75efd4de9a46db9a780539bb0e28435d5b2970078";
                sig_s = "86b21184542ce50d046d49ec539d33569a5cc45c6432d965fb4c455c63d448194355771d7ddc47af74fd2827e1d72e0d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333030353634303635"_hex;
                sig_r = "2631c759a6a86914160766b94a4e4f474a0ad679b5afed8a7237eac773c6b0d67ff3ec36df3730e81adeba58d6e29517";
                sig_s = "16209dcc9237a9ae32d862b33153943f1eaf2a92146af773cf3e5bba48a8551d9c2fa12a01dff3b005426cdaff05a8c0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333037363535373338"_hex;
                sig_r = "59b12f6220b046b08f892d69baefc81c510cc25ad090616b350606084216e6c40e1d8cd96a1b315e64ce1d84986d89ac";
                sig_s = "3994a6852b2377dcc80935e2ea1eaf7889ed694cd321bbda342dbd57ede1a47c2b30de46bb05cac66a6235c4bb290c5c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39363537303138313735"_hex;
                sig_r = "4f69180fb660597f8e70334b7b6fa97e5928a6c175de912905261f3e1f4df1752d3415370e6272710c7bd4bd42edadec";
                sig_s = "445b0b78099bd99fa78a9945d7bd2058a900b94138d67abd37fdfcf2e9fab6644cb1a8c376163ecb69955e954ce8c320";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a94164dc7654fda3cd4301d3e972024c2daba71d442128c7f3faecdb9e375a85aa80c4ac28889f258e6cba886d47636", "548b3bf1b675f2318c3d8ab7a1c281a33241c121b3590bfdf703c7cd4bae8f451886d989234c1b8c589614554d429392" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000f39b6bacd3b2eb7bdd98f07a249d57614bbece10480386e8";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046562";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec4d";
                sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046562";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "73f84ab63789301e88b4cb82cb935decffb8f42b2c9784c7544615b9076ec7a7ab94702ca7f1d9aacfb90537b5d368dc", "502cb7c8c18285994c7b19fa3e2401fdc26de54ffe006bb79bdd7852c666d730bdf76a16c0792a6c6681ed6b647fc81b" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046564";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046563";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00895e8461eddbe21367a95b25cd85cd31e80ecf1f95539056fb7e10b4aa49900b2194d919b29cd9bf373a1d53ef571174", "767c02e36b935a65e5a9cbb35589a2a018482065c5e33da8ce483dc7f7fe441574f9e7ab0614bdcfc61022c780a30009" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "480eca2874aa6ba71e7fb5711339ac0a7bf84065b3c7d59c64a2c6015e6f794e7dfa2b1fec73a72adb32bdb7dd55cd04";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "618ad81912e4c31f23eab2f0c693b3ef8404074ab1dce01dc82a768151c9fa0393b4d6aeaeec6858d3f419957a5b997f", "31fa809b1b44677cc5aef1894846142c3e44bba6c471123fa14feb8f3aa9e92f769be549cef9c1d55bc6f1f4f841813d" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
                bn_t sig_s = "1629ef2d7182d67b6bd9cf6842251fe09c96bfe022b8ad9a0e546fdc8ecf5dc8636fa13059d7e9d83fde50e0d2b392c8";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "79583b4968b576811b567e1620e00b0aab8aa223c5e655b27b1ebeaf83bcd35f4205a5a0e51a2052fffe9fd23785c98f", "77357c8a1008fcb7a3579614c2ff47980fa9e44b6b5ea3f8a33c919dd2aea5dad0ca1a01a9e2106518b1642906e4f275" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0089657bac216c3ac4a3a2d5afd342ad24a4eb103d4dbe2e4461e03c7011826513fe82bd06e17e3ae8eb5811da0bec88bb", "33ee1eddd5d49dd86e785fbfebb9288661964e6fbe0c07af9a4ba3145fc4be11e5484b650c97096db82ebb0ca2bb84ed" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5876f414fa385b403a2d10da5d89b110344ad005bfaf8c759ab1e3561a39ff0db9ff91ec6040316e2fca3654a48c0e89", "0dcb77f896ea475cb97672a8400329554c941b61b4a84bde1f8c8fc5250c29161fc3ca50458a41c77a48bb336882f2ea" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "013ef807f7bd12ebf3eb449b1a780b174ac0b49f7873cc55eb96926a6759d31ad7915e1a9b32725ea35c4874148e1461", "58eb75969fd51f89ff8eea7e3d2e57f7967eadd9dd19276c6fd23ff129dbcd334710361d7b81876f298e23e82fc4f13f" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7a2017b44ccccd1feefa4e2678d0ed19b7c45c7335bbb3fde4937758a76eb6892ed537046e822d8f819e44ee15914b75", "7d1b2da972f6534262b7126031e55f618f78cabcd516ebbc9d8308385934b2c9ebb9f98c630c85b253dcb3eac81ee065" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48936d9579659b46b476999c476a0d6f2e68c902b5af2c01dcb1e8f7b2fbb06eb93f1f427e836cb07be147c596494dc9", "71c9f2de6c9ae7d343f27eb8ab54e2d1c93ad87131dc3aceac635b8d42996cb750e7e364fe4eab90d9d3e0516abd9c38" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046568";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3d2f0f89e9359b97058e9008f9aeb26aeab7b41d91438a72a3a2737f0cc91a05a0ddde54212f8a5a234838b3e9a2e0dc", "31b168cdefd0b214b8190e30be9ce4b2f9a5119355d9b2558ffe77d7177709a9ea2b76853caa265c3b40f0bcf5908938" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9173bec";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6b25f8c1629f7579e3c7ee4b029cc029b4bdbed88b9b399303e4a14352d1f3f6048ecdd062d37cba7b70bcbd587231e7", "621313f93d310f144bd3322582804639dd2960969a993a9f2a3609f856e1415a0a4dcf58a7864e41e2a8c80dfc158a30" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
                bn_t sig_s = "896621d23283b12111048d1c978e2c286d60b6ef7ce37af36cf7aa4de268d626de7ddcb356d167c7483c69455c752c93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d082cde6086f8ea6994f46e9dc06c1c1d2c3a3c2dc5c97bf137653d9b2ed21101bad843d46e4b7925b9af7034c6d021", "12c7f56e65d233104063391fb3828b3990e6893d77746e42305e6a5ba111d976d693f595af858f19fac7234f7484c489" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cc";
                bn_t sig_s = "38e8dae216c63f06b3edbd0f9ba7a5e4a332ec187251e3d627839d1baac667d7caad2ab0a1ea9fbb12dc5a71e3b49bc9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7407ca6c2a183f9ca1376609e9c78a8d080effad15a4f63cbb7a168e3c789b8b59ce4d3122ca08a86907ba487f717fbc", "3e2c56a9b3460a5136b213be8d48cb3dc9c7ad945b1dcecbf93fa6cfaaf8dbd70f1040b97ad8e3ac30f2e64fd7cc76d6" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4efc";
                bn_t sig_s = "0d2436a599b396a51c546e05d1c3d25a8f6d05935ae5031dad3cdd7cb36cf6912a433de28f8475d3b1e2e1ce77610879";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4fc32a5226820ec9c3fff2c74e0b36d7de028e59fc005f3807a3bd59892c9ad20dba7168ef9ed9bf99b25ed01bcfc6ca", "6a13da2e852777a6f99d04322a1b9fb4227684bf7c40d4d3ef92798003a3bf2da158d5686457c33d0e24be5c265fc473" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
                bn_t sig_s = "4a289adad7ceec67ae99ef5da797b6bb17d9c168428ab30ea9a68b89652c4b9e9bae876ab3d7fbdf1eb92ed422bd3b93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7350a7d00d7719a318522ef4c5e6be24b3b2cb300c596f79e8dd31a4688fe65a54b2d7497a06821eecbaf31b2fa7cdcb", "4bd72fc7f05e32457fda0cc3f321157744f1841c30bd086e6ddd5bf415eb71ecbe36f0f3fd23d3c41487fb283e0e9794" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c24";
                bn_t sig_s = "4a289adad7ceec67ae99ef5da797b6bb17d9c168428ab30ea9a68b89652c4b9e9bae876ab3d7fbdf1eb92ed422bd3b93";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "61498ad31a84eed102ba2712eb8a7bd92320bda4ac6d07b4326a30869d19eb1b96229d21efd711dcf73048bf166800e3", "0cfcc13a0914132284dbeab6fcf5d70b34ca86a681157e4874abffaeebb69b8b71f69d332306567823dde5407ce739e8" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e90464e5";
                bn_t sig_s = "5dd0bf01c2259e1ab4e8f4fee099813f6374f6069e3839ccbf64499dc802c3c534d1cf1f9cffd76027b021574602ee43";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1d21a6e6b2fc27821f0521d90ab0e38e3cc22e50654424614608f0d80fbb649bf3ce3437d8ab122d412415aaa4121bca", "67fb20763fbaef5201d4efbdb6629395d1a9cc002437a3e08a82a8a468bfb98d2323194f6d406a569f4bf0b99f440c3b" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000009c44febf31c3594e";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "24188e2bbb6e6503354d84ca83412460e6ab671c224c6ab86e841a8c8b0ed3ecac9e82ea4be74ffb46d4bcd2035255f2", "5fd9a3457d25ffa1217f1018d657b8f1eff257e4cb5bbfcda52f1ba5bb1f46c4617fd750d4c7cf4dd39ef3df599bb400" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d5b9aa39ee9abd073e78967b4f60cb9afda7dbcda0b01a9db7116bf69acec858d451d2ae4fcbe21d1ff343ed571a73b", "47e554b0231432ff94a4e1dbb689760ffdf89ec7be2f2e93327476db287b947045af522d9a836995a9d434faf2de27b6" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367b";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "033777362bf5001b883fabb5c4ab04fbe279be9a68388f34b7e6df306a14d6b8f49c11c495e29912ccc6bc439c0fe008", "22158fdd56b096056455486eca6151c353a072494a1dbb4bd7b7558ee0dd66147a7537fc34482e321a0a3858469f988e" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0be0";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "050592f34db0263df4c669b8991941be18237a1045bfd165ea4af385376564edf6654a0dff7b5d84474090f265c46b51", "1545918cd8f22260ce21a584edfa0b1644488c997d956529262aef400cc0320ed27ddcec3bde6b9fd79b374af688fa9f" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                sig_s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "082d4c490c6140642a25c7dcedcf0b12e83860e81f5d9650cbda534dff9f9835f673014f3c90a634e3b4a500fa024e2c", "132895fa8a88f37463646f211054c002763861d0b64d8fd7ee253ccd9e6c848aa85777c3dbc21fd90c8729fa0bce5017" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "27a1cd4f4d5acfdc4cbd02afc7a079a16af1bd59fc260dab35a3d3cd7387332956451814dae863a8628d608c380b852b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0089f5564e19ca83d12acf49a19b9aff7ad367ea2a1534c7c073272837c6f66aa26bc8c50d4361d240b988992ed9cae152", "6f2ef5327cd8e502cd9bf16ded0c611cf6f52ad1c2cf59b085360d14dab801cf1f691e6e4b0f5a8ba530df8ba6d20dad" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "115fe822c3e7293e84b732283c95a0446f77d1dc754c456163e7b5262ee2fac43da1b7bfbac5121fec4c276ea126c163";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3eb325acf37a882d502a70f48e7cd658827b5724454512d96206240c9844a7817bff176cd0dc0b4e3a24947d15b29669", "4d785f9663698973905519c85cde963ac3b4ddb5138827569144e975c3faa37fd41b87150f54957ae5282c7e99769957" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "38602328c4ca227ee0cfeeed354a5ece9a8c2466ab8ea87c3b67a33db109203fec4304417fa3bc0c2d8592e74a14a17e";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7a80f2993c95280658aa0ae94efa15b972f6d32052f7f53b0344f5a9d8e7505733ce6ed6cd506f80c849dce9f984765f", "00838672fcb7b1d3e28942d075555ed59b594afc6b5d450f40537acb455717f1565cf98831c1fd68ed1aa499ae4243f1bf" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0af0ef24c77a97521a957d4102ea0de4e1d16a9cad02a9a9a5ba466bd1a99e4a078772b0636fcac3caf4e3f9321b84d1";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3665e2d0bfca1937aa0ebedf3e9d8edf5f5af1880c7e2c3781b2b3d39d74bb65cf4bf259646f4940cb78e5c5f9ef2121", "18ea424f2f5a866bf459e0d8077061fa19943a218dc139cfed2291f559c0dab851466f5801bbb63e17795733ab595b15" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "2a23418cc9d5d7bc149bb47e0ecfb4f50f5f32ce49aec5c11349196bfcf0eebb49d977c76aa524c7dbc7e23adcd5cb56";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "181b9fcadceb054a95ecf3fc1d76c96a7a0db4361b6f3dd26836dc68267abaeabe8aab79f1819754050b323f192eec71", "048ac15682a2dbb66d200806fe8502027c109a73413748c9887feb7afb54e7fbfdfb83276b5490c8164d26efd26f7da3" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "360c166f35d9371b4e6acf6c87aca0876ac07ad69efa9383519ecaba2ddaab08253907c2cd41cbd56908f22ae4fe8947";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4aee626de33aaeb733246c099af23ae06da262f9e509b8f4ff3b82f905ec46baaf5789211f19874007ba2a39b6d51243", "6dc849c2728b78163f5bcee5e704113c430e65184477573382bed7acf3d97a533ff044ad20f743f5cdc7c4ca27a0af2f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "1eb43a98963c2d7bf910155abb629846e35794464a22a01f4efb44a9ca68828a1565ecd890e4676e1887eb9a7599dd9c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "07264bcbe25d2bd542e3c68d9d1c45a09a5de64615fd322a156465c4436aca922ae0afec0e40560ea0cc495a6843b8f0", "4dfceb05a023c427b9a26820fc7aab1494cbb0b6d33ed7d6da0b951799f0c17c632df483e7f0abf08ebb1068684f1f35" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0a66b016b638891819928a01f3e5b3cff629b9f0d878d7ab99e90f8206c062d11cffca73efd3a0f56fc160549b68c5c4";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b56303a979ee98272dabbf30dd74764ce9263f8a5d04df8f97f5d908a4b71f0209bea87c2e7b43d1c9920b4604eeac3", "16a6aaabf771fc49a1786d45507429b251a53b348afe08f20c7b486f257f32754673b9f3f010934bccbef91343f12f59" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "0de1b2d3fb8cb15f4ba27fd5da391dd2f833797cd4332111879448cc079658ee6b0cda88a6ef9d921b0d872013f250d8";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d939c46f1b93492b3564e9dd0e06353d1c4241327b96f2d0c7c48df50d929f2599d3d1ff4a1ee4cce767c22e6ae490d", "2337fe84a27a593e4b0e01b474d8b46735070b54fb375aa481393599c5d44b2dba4ca16d77d027f5cf0aef86efa21902" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "24f58fbede0aa2ad7cb2b26fc826925f65ca391b2b1db0edbe1270d28200ac5cefb297bc9e68d88659e82b63a925b0cf";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "253e9fc91cbf897ddb29d8176ca6b359c187e3bc77b1794c6e2f69bee613118b0987ab705d6d4eb4b87a3799ec43debe", "5a628d2e1b958138b8a562caa7a24e7a89fb60c4851d19b4ef61232228420b928c9484d82cff0715e40244b411b83a5f" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "37b69194769dff477d4f0706933b9b2f0902b117179132a1174d8848b0be2bc8f2f1b82c3ef6b802e30ddd6fb8237c71";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "37e9e758d46ac26400b63762f28e145b33eec8aa1530d1c6772db8b41f01345f3b8601487cc5bc4a54d29960376d9fd8", "39e6deab02faf4d7446b64c4334c00284c421c2da2fd234e0f1d1c7fb7a08cec2f8e31607138f166055312533d1f1d01" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "293fec2aad2e3aca83f5ec93420b651832e5b38f3aef0b5e1e028c521349935b5669b9d54d5b6e3e1c28d20d2389ea52";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4ecd7b617c0b469fcc37915aad0b77d4a975cb8acb57a269b2a9bca1495864c60462c194a8ff3ae2662c4b54dcbd4ffe", "2284cf3e91cf235130c081740e699245fca7395bfa1d37a0c097e6c4b22b73f860602575e51bba7d2871713d8d5a31f2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "37c9918695071c1429e155324c602e8d34b8d38398d02e5ae8c32c7afa49033a020484fa6f356abe10e127bf9768874b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "58834acdc90a4d5c0e4a98e8fe203dfefaac241ccd731dad8880c29c3ffabaa6e5a4f3473c10d501de00b0e746d09e73", "3d2f31b77f9a50218c98c5a1c6bb8896b9de5dcef92dda679c080f917e65e35fc66bb72b7c22ec96c7fd761c483d5cb0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "041de947891467ddb8dc3c7ec190ac4fd330cffd55c6bbbdd008362e2d818871914b6b914a9edff7acd299c2733a7397";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6384a216b7a2adc239c8f9e2af706e94c7fbfd424365cdd74a76f87232610bc242b49f6d4eeaad68d9e71b2713e4f85c", "01fd9b61298e1434e5ab112221a94749d909cadd52c0e43eba07274e06db95514a870f9ffdcf47ca453b07b2979dafa0" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "062979476086e29e3dad11eaa1ce5a2935c70bafee5ddefad188ef56d41ba9a70ea25f01a1483ad5ffae4031baee822a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4df898544c2b10dc3c4d3249fca5130e753d26e08320bd823926acb050d8b6a4feadf29bef07ecdb00e85b341f22069a", "3343695d1e0ac0a78b38490d97c1e90e4ff4ca0d2140b9101f1b63f29ca4f2bf9176e1600483916216bd35abce6741" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b2";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3e955d284589775837c9b83dbcb49186d695d6b53f5771689f6458e40a2b6dad6254cbb227de4675849d11e0fdf32114", "3c4f0ae8803367716186174f91b7035b35bf8490e49f9c46147b6d3b71d96f74abfa5e40f33c100f79d459624191cee0" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b7";
                bn_t sig_s = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "39c44873ccab023c4b366a646decb4beb5672b6d2140fa0fd200374aa01301008c0419c3392c589000816e1f18059a4c", "2b6104be5e26c657aa1f6fa4addf3ff52a45679800dd28cd628711f2d1c11153a36c6c42fba6954cd37fd252112de1a4" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b7";
                bn_t sig_s = "465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b598f8b3736560212d3e79d5b57b5bfe1881dc41901748232b3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5d77134e890ac72f9c69fcc3f181ae746fefffdafc1dfc791cf33a22fb0f8e586188cf2d5d060ddb04004baf56191c9f", "0e7401ddcc47a09b5ecf2719cc936010a9371a7f7624e63e7a00550a13d035cf586d3b522c7fd06251adbb0f0aad3dd7" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "607cd94c42f5bbfcf857a708ac163f0afc0a65c8d88725f18c4bf7eb7cf5d34aca6008a27b4e5fd9476134ed85fcd32c", "0089f248290c59b8fb963e90bab9b0b3e313d3b8e0a6c8901455a22b7b74a108152c5b814ba575de8de07cdb8d67ba2b50" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "1fc115146e521d7ea33f3e128eb01db0f653dc45852c2b50301d639b778b13380e51d9366552cf2049156605d57adffc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b4afbd91746b1a4df6d0d717afc7528fa4a9dda9a62afee19a72fc0019aa2ea89a125bea7675506230656caaff52c73", "5f5c3575bf669637efdb672477500f1fe37b45dcf879487ad6ca36c4147329fb741706ce9b928ce47bf6dc0f9e44017f" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0d8b246c623188b7455716ac189b9af441676a1c41cd575754bd02ae4d6825304b961ddf0826bb161e3d63e9bc71f1d4", "6edbeddc2d40dafdccac90ae85cd616a0ea1e4a08ae8fc3358ce7d5142eee8f3bebdc14591c4c9b15bff12b8cf08334a" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
                bn_t sig_s = "5dd0bf01c2259e1ab4e8f4fee099813f6374f6069e3839ccbf64499dc802c3c534d1cf1f9cffd76027b021574602ee44";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "04d9d4a62d6eb02073e738b1e439cecd5440031911f45190eb6062a33535fc5269bcfc25d4afc1dae0ebad948d7732d8", "029af37e89a3cea7df38b020f624906fca6d944e1486853fe8e5ba9cfba2d74a852ec587d46fe49917c364418ef7eca5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "533b0d50480a3ef07e7e8af8b1097759bc03ac9a1c7ed6075a052869f57f12b285613162d08ee7aab9fe54aaa984a39a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1a4a55c9b0ce43d7ed78a98d9bf6459ccf349466fccc457598fc15a1d6956d8ce8348b2332fffb3d516b078d28d329dd", "73f45a4ce1f5dc772f3c3283af6564e6e410f9d5064b6484065966936693f62ac9940eb28914a091d2964cd843b41028" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "70a8e817f4ea82b831ba5e671830b4312846b23da14ff7d43baf3a7ee7aa061c86422aaf27ffc5c655406868b5bf19bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "373ac98f088268a86d136de4fa0ce2c41042cd33ed2d07250f53cd4ed43fa1da425da597bd5b413d56cfff954267104f", "069e0453bbbd79280316f8c1c161a846af379a941ed286e593e7f289ba4fff42458b273a3ba499574e134e7fb4a7dc19" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "326c0872a7224e7a104087acf4c4b4e3e5aba4ffe4625fc3955ce9647bf71fb596b83971ad2b52473a2821991c808905";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7e6ab429b9e33a974f6ab9a49eb152c484575fad5d9bcddcb87edce16e79333a937276f36aec9121de450384cb20bb2e", "008595f6c2880d89198e1b625e65056d0a19a58d1d1c551bcc5dd39d281d726dad4108488c8f941ac983169cace3ecc71b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "65cf0a5bce70af078af6d5a14545ca619e47d6eb0fd0531ecc743a7685530284a83289c2d09e024384ae5e778799e414";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1fbb37f75195c3f2de3afcc88ad7eb32108144608943face3a890005ff2a3e0b558079c5842620f44adc0c38dd88aac5", "51734f8eb827df929d7317714a29cf8ba432caf689094d00eb9d63cbc908ba76ca5b1f93d229477c960842940f4224d3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
                bn_t sig_s = "2e099adfe4d9120596e8a1520399b0e249555b171e0a71967307548a3c28753fa40bbcb0a8658369dc8ca0caa05fb001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha384( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "07fa30c837c8ad029326a1d448bd27521b5d26aad4d8244b7242493df70172e6dd1daf5c7e07f4fa102f5c415a4ec61f", "0904527df877527f7d0f5a7f71b6d9c03f2de1df8804868e7337da35c9b1ffc9bf2e279c3af8a0786e6f39832cc6ed1b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "5c1335bfc9b2240b2dd142a4073361c492aab62e3c14e32ce60ea9147850ea7f4817796150cb06d3b919419540bf6002";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "61397ae7fe8e7e894bfa689e5813514293a0f1b9f1090c0d9696379b61287a752a3f7d1d2480fe4127498d0eeda84c63", "0c2fadd37ea36bfe532b5d3a0f101ddd3ac59458399648f3efaf5833dec1c8c8ece05515893553ef4d58120d37ce2ecd" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "259160b321c350f4f2299aa77c72a09248927957b6414308bf8c7fb4f2dbba5ca79198f80a150e1ceb5a9845144eee9b";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "7f166efa8d8416d922f57673a2180cfbb49e8d160d60ba5ec90ba547f3eccd22ce6afd99a0fb292cfd16b0692b9cab03", "418579e67c87b359912f6cb4158bdd7ea130b5007726df2fce319915deedc4f7e89ee23f786e25373c9937498bab81b4" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "881964e1bba9a28c7a1d84379c65bb3da72f3cc879f7f579d2f9b34a574432d6c7d1c229ee227d4ddbdd9f15df9978c0";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "77c9c2e658b004ab6840d7c33a5e7eb5f93ba3a7c5b32f7275fd75b07c1c92f5ae31576b9cbca046337e6d6ea76c145e", "67c56010dd9749e2d90b3eb57ef1c4c73741233a32a6a4355b8c4e3a24bcf5986627c7480783161db1d2a5332bd75fef" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "0e3c83bb59abc57220170152251cf010b0081fecca2c957ca7ec1a33dae3ca1d7094b1c0f71b03e008bbe64659119f09";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "64d9a317d5b41af30fdfc7389460f357fa9978304d026b312aa5ca04a19bdc0c56440cfd14a0b060c3b8f4ee8d4a5a37", "77299b2280ab4c857ed2531e8db027f8c7238028bd7f7ba59bc80547d4f10da6f2e613580553406f0427ecbd7b75916e" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "631b97da7f334dafd01e2a01f8618632372d9abcdf14ebaf7213da37b1449c4e8c8a1dfe03384f3ade8907ad94421398";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "264ba447f80d721bf1e79877f27a23ee58565e88c49f6b9cd6448c024b6ff53aebb2b08cec22eb2eb38e30fd54727f01", "00801887f9f94dce625ed1d56350a4b252e0dcfc0984928f25ad22a13135baf996bfa82809fbe79c0979670fddc9fba9e6" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "397e11325b2e2e3790dee4859fdcca85592bc46fd0d580abc5114602b68512f549d9854c9af0db658189dd583f7fc1cb";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "04918040a58dc477a7245561273df2d8bd977e5fd39c40d3011536cb2b9cfee82e2ab5f539e5908dcbf3ff24c645db4e", "5969a9d8df5cdaafe3490caa4946acf5ebe3e93aab28a8d4a6f61e2c8e5c02dc605c75806dddddebe23915631159c1f7" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "0fe08a8a37290ebf519f9f0947580ed87b29ee22c29615a8180eb1cdbbc5899c0728ec9b32a96790248ab302eabd6ffe";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "22e44ebe0a351e4c91f7bdfc0c0c3c6e1c679da84a32539c2dbb41ea31061b0825e3f34d7b0ad525261eb9e457c40819", "6089e33034731ba8e9f95f5a234bf8d3539c8381f4d95510d5e0f145fd48205e5c60218c3f84b189c8e4fd5608b49778" );
        {
            // edge case for u1
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "5f92937aa52d5dd10fcefb95a2d57b617d6d8b04e8db5b3b5a39abe893fda2aeb2f978108c558aabbad829ce02c27735";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "66ed49779ed6a7b10c812bc7ee7b47a5d11c5ea50277273da140bc1b0cf5b8210a6a737f7e9d92eee6d845137e5c44a2", "008accb8f637385cf6519bfae3ed3ae4d0acaa19a260a01bd8cb53ad24dacab1954b20d1472cf3975e87cc733f329ab6bd" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "59930a2b8bbd79b8051f252a1af76b4a5c6525adf9c6c7910a5ccf798eac0c8d4513923a792a965abe82bb564dac21cb";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "3024912041bc989a936fb4dcdd178b15e03a0aa94abafb4465b4a89d4416b7a8b029d47c17e69a25962ff3aefe862dcb", "249ee9252b5713e747a2da8aac2b961ee2b6aca157a44888748648fbcdc5661cd4a169bb92c9c1ce50a79a63735002a1" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "1449901ce4b00f0e3a5ff84cff8c134854b808e504d1b8f027ace9591234e3f62ce70c35a8aa8e60cafe1e0df3ed80e7";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "6c9393b00e9a62ce0b83674cdcca59b18d5b34246348e37c1d78898a522d813c49d08efc5f3f7ef33f3dc9dd1bc2e5c2", "0b9410ce04a64cd095ae1194bc1f514c7009a4e06871b557154cf492e7c57749487ecfcd04cb31426ab785ffa95e2f" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "89ae6f8e215bcf35c7e2afed1a6b9855171687d9edbea8af5bf8e9ddc667aac4e166f05097385fa9ea3a6245fc07b4ad";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "2c58277aaa61c400d7036183af49c99a97fea5a8d5f8608c4c6ac7a282757e4dc4b6f92d82a10272f2a19696a48fa79f", "5a8adb770740669d6010e55f6625b141be469fe1779f4adfe64eab2e4a9ac5bf1c25b3de0b74b8f9644fc216010d9659" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "3fc16256a0914ce2661a54688af4b2546b1b59b043667da6abb5b1a1e0e2e6ab862fe8bb749f7251572bc160567530a7";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "6e5f827e1aa225c4b95db52655f67d654bdc69a4bf8f49c19d1e65dcf12ca511505aa1726ca2f5cdf8ab376f94a0c5bd", "5daec6f35f1dfbc68fba024cc8c5f79ce9baa86adfd8d2ba53a798cdcc9025eb9797d3be207bc694abb338e43778ffdd" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "64c1556c5eef311a4f3ba46316adf73732d6ed47b1ba2ecd178ff89bbc5ddd6c6419f62e045ea2d35c33a250dc2fb925";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "7fe852a7612a673df351f05afeafcbb16ce4cadf85681b2b5f46cc31ef33d6b695378e7325e9cb3185d7137b2b170046", "5cbd4c810076d135316887e94b14b4b0108db1c944794c398938d42176c32575b6428b3e37b602211c574acafef0911e" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "3cc98c561aa5f50c8f19d947dc75ac8f507e6985762006e7100982caccb79530f8f935ac9d3d82967cdf129ecf5b0ce5";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "0a49dc359ed4fef683e462dfe685442cea77b733fd95633216794d9a61f7e1022d942a36e781a484a2b479a643469af4", "512ebd0966b68bfecf7a47021bcd9e6aa2703dcc556a9a443d16195aa145738fa36a4dff3d09481f4a86550a8d1f3545" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "3f2095530f36144e009019eee102b2867d83c9eb4f28bcb31b383e00c8c3746b20cc90e8efc813aefb5b6a4965204c53";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "276715087495d52c4160d15446ebb4d758291bf5bc9ca87b56c3f00adc41fa452d66684152d3e19d2fc3ad5d289787ad", "367385d3c3f5c3c2c6c3166adcfafc3d204453cab8797d56e955fbf1cf421763a6653e40efd9035df8128135546b6261" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "704afc6a72080d1728f6cc9fd023e9d2373023377f02599b6ea9fb2923dd7403fe2fd73999f65316b53f910bda4f6f10";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "5943dbd66c79fcb882936eccdd6d860c42e20727a2cdb29165c8426c9d192990b71d9a3c7f240e46acab2741b7ee9c7a", "461e5ab1db3eb9b51b3238d3ada33567d251d8fd0fbaf59aa1cfb40fe7b22e0277f166a32edb81ab6a8580f9b1fb3e39" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "46f09c4741c1afe74e32f6ff14daaf90f4486c33f5d0e978f9af24f5751988e72b374c5faeffdec309330401965f7d20";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "5285d72925c87c75b6ad9955064182bf2debcb25c88d0606f6672863de413e549688a4fcfbe6689bb23dba2b757bcda6", "4ef6b01766c95b66ff10496d5deebac4b4bf8c3bb4232c019f80b69d8ab0214ceaf5813027ecec133a5a5b971948822e" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "19930a2b8bbd79b8051f252a1af76b4a5c6525adf9c6c7910a5ccf798eac0c8d4513923a792a965abe82bb564dac21cd";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "0786afb03dd791dbfc371ab51ffa288b7cedd90d6a35a3c3a92566f895f38cb18536137e010f1cfba2fbed70568d77b8", "4eec840cca8b6f3f612304b602ffad8dcbae1786b2c2216e9a1e59a6b69628b52a408b6a083d727f3ccd0e706f9aeef8" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "33261457177af3700a3e4a5435eed694b8ca4b5bf38d8f2214b99ef31d58191a8a272474f2552cb57d0576ac9b58439a";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "46690db403904228e4f736b1344791596628e85669d4dd01374b21274280b421e42f5ba3f3f2fadad27d4469be7d9bdb", "7e883b43c27217f606e0a5ba6c9df781c145776c0e5a8993f0ed65c6ded65a43bddd0fe7611485e8e8d9e7decdf2d8b5" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "4cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046567";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "008be6928acad44c9571b5c4015fa3ffae5e639e4130a1a66b473e5dfdfe93b68a8de89583666d4d699e8885469f9b1a4d", "0083b1d5312310e445ae57c85ab1a3df8dbbb706a598fbc007efb602a14a5952fd7e7df0464d533e062ea211285c2f5c27" );
        {
            // edge case for u2
            auto m = "313233343030"_hex;
            bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
            bn_t sig_s = "8b33c708624a1e2eeba00fb5b5a8ed1a1622fc71ed897fb13d87ac253935e8365850d380015c115d12e14a2472860d09";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "1886ddd282b023084953ef7d9e853a6adc1360cef7f56df7da0ca7bdcf4f3a5d227a730f9f20f9434b565dc4fa819e85", "6a0f0ed8d7f28f916a4e727e55bf0818dcc84ed1132bd7da9f98ff95fb2aec238f4df9185b0982a6682c06c85e6a895e" );
        {
            // point duplication during verification
            auto m = "313233343030"_hex;
            bn_t sig_r = "8729cbb906f69d8d43f94cb8c4b9572c958272f5c6ff759ba9113f340b9f9aa598837aa37a4311717faf4cf66747a5b4";
            bn_t sig_s = "28a9b8c55eb6f5f1cf5c233aff640f48211cd2b9cf0593e8b9ffff67c7e69703f8a6c5382a36769d3cca57711ab63c65";
            auto r = true; // result = valid - flags: ['PointDuplication']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "1886ddd282b023084953ef7d9e853a6adc1360cef7f56df7da0ca7bdcf4f3a5d227a730f9f20f9434b565dc4fa819e85", "22aa0fa9cb45dd96a50efcfffb2739c638672238da287ed97318da83848c25001d85ae11351397cb1f1af94ad29d62f5" );
        {
            // duplication bug
            auto m = "313233343030"_hex;
            bn_t sig_r = "8729cbb906f69d8d43f94cb8c4b9572c958272f5c6ff759ba9113f340b9f9aa598837aa37a4311717faf4cf66747a5b4";
            bn_t sig_s = "28a9b8c55eb6f5f1cf5c233aff640f48211cd2b9cf0593e8b9ffff67c7e69703f8a6c5382a36769d3cca57711ab63c65";
            auto r = false; // result = invalid - flags: ['PointDuplication']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "0089dd738efcb0f79811df6bec873485169450ada18e602721e61768be0d81e5d41381f24668276f32bfe31ff1c16bcb6b", "1f7a4d2823bcd73f236d90b6ea61d892026190e14317b5d110526e9e2675f03d5ef3fce87b5827a37e0cf19b4d3988c0" );
        {
            // comparison with point at infinity
            auto m = "313233343030"_hex;
            bn_t sig_r = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
            bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
            auto r = false; // result = invalid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "795592a673e82dff3d77450194e5308d64f45f11f759f34f7c7b5b7cc6ad73f9bff8f6633cc20378cff2e53fb7a53030", "0085b5cd4621665aac8435d8ce85b26d444508b77b282e91cd5315c701d2e5b66ba4c00bf7e1eb0859a13cc351d00041a1" );
        {
            // extreme value for k and edgecase s
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "39d94ff8757dcdb67480cbc48e9679423e57de5a23232df0db1e0ff7e908614401e6cd8d615008ea8be51299d9e22de9", "438126d70d14e75ce41ea2f409be88e2806f7f73bd513731696bc59e7a2c1d44d5683d3bdc92baba1c2ada58809f8bef" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "20b1fc8e2480a973e097337343490b12ae40652e4180dd4ae56df521daa9e391777c0d466f018af55519038dead35501", "7232882bca3ccd6b375591f5b5096538ca5778355307e603148fde31f5acffeb4c6863541ad233de3f281ea0d235b6f3" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "4a391d79cfa82b943123d69ee2d1bc0e0b7e1e6f93c69123bfce0bd4f31a5e3434062dd0e1aa8b886ceba362c4d6720c", "7a2b0543a156f1934e02d31e81d5d2785a71d541cc7e1e6e6132ebee42111f52a844937260719056ae7b10f751606c41" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "7094186882938a8672b125fea71e9b18ddbf8da18aa9def5b2785856f00351530c2ef88c55ffcf402fa0280254038451";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "36854adacf83ce5f0e4422406d7b6f7db63d73d4c892a01e975ef6ee6b71a9334c9d57ce6ffcdb1a2e4174ddba799e12", "7d619672035db4fd73e5e4b4ea920b74f2e70fd24ebca49d22fdb11e96b7867fa1838ca5babcd9dd096ab85e2f97b5ae" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "789eac6ff99e146b7ae25f90d7a0cabf36baf32d14916ee2aceea7cadc95d7221f56e5baee6d82a03307064ba32856e9";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "00804e6c71e493b783ecd375a4edcf86c77b1c2df551bbc73bed8516e4d11ce51a1dd081e19aa6f51c656818b853962178", "580bd6b2c4eabcf5b3741e6b7d59b0e7f2bddb247f5f9d6751cf09e3c6c9d1f7c27c0bb8d21e77a80ebadaf90af8b0d0" );
        {
            // extreme value for k
            auto m = "313233343030"_hex;
            bn_t sig_r = "2282bc382a2f4dfcb95c3495d7b4fd590ad520b3eb6be4d6ec2f80c4e0f70df87c4ba74a09b553ebb427b58df9d59fca";
            bn_t sig_s = "64dc78d112cd6ed67d4323b302650a606ed41415bd8cfc40ec7438a70ee3d8680420e5f602aed591a324760c58140642";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "2c115772dd298612197a1c59df9c25a86ac16fa4f27adf74bcc673bb4a6a4bb5d0b5b64470d5d26e0300922ab7237324", "42f6ec209e27ce0b127d334745272643d3666bff54927419764de52322ee1696e620d15e0eea62fed0f20efe6c91e1e3" );
        {
            // extreme value for k and edgecase s
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "2ee85f80e112cf0d5a747a7f704cc09fb1ba7b034f1c1ce65fb224cee40161e29a68e78fce7febb013d810aba3017721";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "295778c9a3be2b373450f57daf10de66d32441750ac4289f6751ff61405ce0237f64e28ac5281a81d13fba81a8454e58", "4c9f3991d615512faf0dc9107193b1b6f5cd684356ca51504d15c1ca4ba00b21c7c68eb4683222a8211e4ffd56da0e06" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "65a340bc68f3fcead4f04277ee8675f9c17bc8c88426c5ba0313b8ce7da58d92ca9a0ffa32c7eee195857d860ba1eebe", "4dcd5be3a6778008b36ea19d902d93dd488f6fb65dc0719521553b39cb3c524b12681d2e07a8ef720cdc15011c23ba9d" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "1c25061a20a4e2a19cac497fa9c7a6c6376fe36862aa77bd6c9e1615bc00d454c30bbe23157ff3d00be80a009500e114";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "54a03902656bfaf4d6a54ff3429d9f9719bb61e6caf000e100992b31700e780e0f73f51614954acdddcaaa8b2311195b", "04ad3b19b01e150a39dc0cfaecc6498b18138ce612c492795687a488522644b3ddf7462c3c359bd091b7d39469571879" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "7094186882938a8672b125fea71e9b18ddbf8da18aa9def5b2785856f00351530c2ef88c55ffcf402fa0280254038451";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "46d10d749a47a4d3f25b6f28951a11f01a54c2413957a477162dabe0d08d8ae9b6a9f44b68ef341fb820b0c24c7a1c0e", "671ff166cd35d2f3cc821d58fa18e35d25e6033b9e790fce4818f9e570921c0034b381cc9ad254eeaf1b386e511b7c89" );
        {
            // extreme value for k and s^-1
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "789eac6ff99e146b7ae25f90d7a0cabf36baf32d14916ee2aceea7cadc95d7221f56e5baee6d82a03307064ba32856e9";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "008ae92de10b244ac7f0deb6b102d075951d8c13b2960c2e98d7fb42b8abe90fd07a4a21b86eb4c77efe9adb6725676d17", "36063f3407c71627acaa83be9029c7a40e8aa896cb68a9c2fa2aaa1079035a283181cd3f2723b221d5a8747ad392a0f9" );
        {
            // extreme value for k
            auto m = "313233343030"_hex;
            bn_t sig_r = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
            bn_t sig_s = "64dc78d112cd6ed67d4323b302650a606ed41415bd8cfc40ec7438a70ee3d8680420e5f602aed591a324760c58140642";
            auto r = true; // result = valid - flags: ['ArithmeticError']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e", "008abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315" );
        {
            // public key shares x-coordinate with generator
            auto m = "313233343030"_hex;
            bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
            bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            auto r = false; // result = invalid - flags: ['PointDuplication']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // public key shares x-coordinate with generator
            m = "313233343030"_hex;
            sig_r = "1fc115146e521d7ea33f3e128eb01db0f653dc45852c2b50301d639b778b13380e51d9366552cf2049156605d57adffc";
            sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            r = false; // result = invalid - flags: ['PointDuplication']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e", "01fb010d823eaa83b2ab83efbb166c8cb27865dfee67fe4f3115d4c98625e7fb9e8d6108188b996044c4fcd20acb993e" );
        {
            // public key shares x-coordinate with generator
            auto m = "313233343030"_hex;
            bn_t sig_r = "f9b127f0d81ebcd17b7ba0ea131c660d340b05ce557c82160e0f793de07d38179023942871acb7002dfafdfffc8deace";
            bn_t sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            auto r = false; // result = invalid - flags: ['PointDuplication']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // public key shares x-coordinate with generator
            m = "313233343030"_hex;
            sig_r = "1fc115146e521d7ea33f3e128eb01db0f653dc45852c2b50301d639b778b13380e51d9366552cf2049156605d57adffc";
            sig_s = "141a7212a99a58bc947b0fed7945771fde747ddcd8c2e7d07227c6a1cf6e4e85afe3d0f47d12407008812bb745dc0e7c";
            r = false; // result = invalid - flags: ['PointDuplication']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "6c9aaba343cb2faf098319cc4d15ea218786f55c8cf0a8b668091170a6422f6c2498945a8164a4b6f27cdd11e800da50", "1be961b37b09804610ce0df40dd8236c75a12d0c8014b163464a4aeba7cb18d20d3222083ec4a941852f24aa3d5d84e3" );
        {
            // pseudorandom signature
            auto m = ""_hex;
            bn_t sig_r = "65fd456814371d60883ffda5f74f36dc2d45886121770e29ed3163754716d12c1cab03a2cb6a6e3376fc96d8727bd1bf";
            bn_t sig_s = "1aa65e57932d05788413219b7ab23e5337f63fb2dcb0f89b4227d284a3fcbdf3c54c021a6c0ca42445bf802213121654";
            auto r = true; // result = valid - flags: ['ValidSignature']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // pseudorandom signature
            m = "4d7367"_hex;
            sig_r = "01057e36ad00f79e7c1cfcf4dea301e4e2350644d5eff4d4c7f23cdd2f4f236093ff27e33eb44fd804b2f0daf5c327a4";
            sig_s = "2a9b2b910dd23b994cac12f322828461094c8790481b392569c6674ac2eca74dd74957d94456548546b65bd50558f4a6";
            r = true; // result = valid - flags: ['ValidSignature']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // pseudorandom signature
            m = "313233343030"_hex;
            sig_r = "6dd9d4e98c9c388240e95c49b2100afbe0d722f8a152651c61d7ef9bf46150e3cdf9bf6330e75e4bf2c294cd66e48d06";
            sig_s = "1282d33b5b79d4eaafa03a77bb8ba2c318291f6ea09d548b7704bb00910856dd360557e609add891c6435d7a80afddfb";
            r = true; // result = valid - flags: ['ValidSignature']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // pseudorandom signature
            m = "0000000000000000000000000000000000000000"_hex;
            sig_r = "46cb43798bc06dbe788a4f4b2b98130e3aae917f1d2a005656bd70a3288caf7c37d1dee0c9108828a69d2a1eeae113c6";
            sig_s = "8180d0c5ba1bed4f2b0d4d8ed7ea17916b63400397e7b6d70e7312c5ff0f4524a49abf7071c8ba470de64fb668570380";
            r = true; // result = valid - flags: ['ValidSignature']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "462117d2e33a7db1b95c8a6a3c7982f83da96817e749718caee7b6aa9c9da4e8f2ff7951674eed2b569ab846f59002a8", "50e6606a9726a9209c9e945fbf6cbbc9a487c4a4d81c52ac3684c26c3392b9bd24f7184821be06f6448b24a8ffffffff" );
        {
            // y-coordinate of the public key has many trailing 1's
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "43a3ac2f3d2b4d3723a97930b023ee73010a7cf8d2a99372f3132bd7d9c83574de3ab86525efc4ee2c59799d5ff7efb4";
            bn_t sig_s = "34f59a3ea9f5267f8458afdaa3873e2336e0ab8a40ca1b797cbd977d192f2024f9eb8d39b37b9a238f208d66bacd27bf";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 1's
            m = "4d657373616765"_hex;
            sig_r = "3531ada25b8d9af9b87e5224cd6a6d956c17dc323ef8980f497a6e7e44c83d69b74de791d62bceacaff7378863dd725b";
            sig_s = "459d15539399409380af99d560c561217daa5c539729453067dd1aa4bd9df2b534920f0d6213261ecea16f0ed68536b1";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 1's
            m = "4d657373616765"_hex;
            sig_r = "438a0cff9fcfcf587f8c40775ad44ea4b0ed69f2d547befe295d1fb9c24ddcb97f228027df552a06bf657b4c20272615";
            sig_s = "5e157630bb744fc8e7f75901de498e5af0b5511dfeee0c4c1f2e5c4aa0129de57b87a2a13ea59d187d51cbeb6ef22407";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "008cb91e81ee5901b71a59a4f7c8174ae05fe3ba00f699dcbc3c9233265c640587b3c165593c2d76b5ffc4b8dcbcb0e655", "3a0e5d14f2d0e8efe2bd8aa260d8ace06bf964c51bab8207070a2d30410bb6b87aeecb7fff802f2d4ea3caf6e0e7e726" );
        {
            // x-coordinate of the public key is large
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "16496c08c3076773fcd841a5e25e1a87108e0ba90f9727f539034bd2cf688e01a955686a15112e0590fc91e3995ff5f8";
            bn_t sig_s = "31b1b7338f74adba33712a83a7c685e7cd5f3be84ef951ecad50facb7c6ec393a3bac52ea7b1212bd92f4f45a9f8514c";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is large
            m = "4d657373616765"_hex;
            sig_r = "87f3090292e79b722cde5aedafa4244f6eb460a280e2e050399b9d802391ad502108704a3c0bb9f9ae571c3f7dec6c0b";
            sig_s = "89ae0043de38a585a1632c7211b78303afa3f8936154a6e65a6f729c3b1ec66a1775aa465af8eed6dfeaa5ba98cedb41";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is large
            m = "4d657373616765"_hex;
            sig_r = "720822abefa91265a7b8d446ec3bc405fd192178aa1b85dd663396a896a32c119e64b1a20843f81edd43c03709b8dbc6";
            sig_s = "206ae95bb18d2d3844a39340872edba1611e3ea0e84cea7cb6cff282af414d8b5aa0be8aabc1b51b7121d426916b01b5";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "69ebf332e1eb2455324a7572a17977a4e2955108ee8bd81bd6d1f555d608687f5bbb39858ebee304985baa7d09c830bb", "672b9c96684dfc007f015e39cdada9fe16db5022bfd173348caafc528684621f97fba24f2c30e3dc728772e800000000" );
        {
            // y-coordinate of the public key has many trailing 0's
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "1e5027fcc630aa08750a4725919dd9072422a21aca9d3326bec3e6ac040ba9784951b1fda6f588e60dcb550b75793a4e";
            bn_t sig_s = "0df3224641f6804f4d1bf951051e087ce1fa7365c43bd27878626833f09190cc0a7fa29b16bc2ca0d34fd0660d24718f";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's
            m = "4d657373616765"_hex;
            sig_r = "4e61e34740a9f6db0854faf205719a3d98ef644b86241b858fa22959c04395578bef7be35036ae7a9ffeb9a2173311f4";
            sig_s = "1e967c3b6071d37560fd64a4fe0921b1d600f60d883fdec816836176c5e67ad05182aa080c7e2184c0710050d523f0e2";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's
            m = "4d657373616765"_hex;
            sig_r = "2c3090c581e575da58a8f659f74c5eee566400eb1d91de0a950e787542e6572f73b9f6d4f81f1c8e42f9e460dac3c1dc";
            sig_s = "756b1b693e7fe06686708c2a609854accd21e3195d84b72c11c873908d175dfc00c00ebbdf8e2bb6970f2f19785303cc";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "4fb5688666673f104287428b5bae6bd82a5c69b523762aa739b24594a9a81297318df613f6b7379af47979ae7fffffff", "7e2d325b41fe831a23cb694cb80a30119c196143536ee334416ba437a419054c180a945154596b83d7f7c3a6b6059645" );
        {
            // x-coordinate of the public key has many trailing 1's
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "092f0ee1feeb79c054ae36235f8717e9ee72b466b1704d4fa78addfcd13518a64db2b2fdb06439acbc4c045fb2c23c3a";
            bn_t sig_s = "2371ca6d36f4266162ee5c657c71cea35dcec3632c5b220a6f23ace1ba6562a841aeeeefe87a7998adfaf185b8558e4a";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key has many trailing 1's
            m = "4d657373616765"_hex;
            sig_r = "6c8f4be641afaf5bf91ce08974d284ece6aec74792247229fa86c6597eed3fb507b712bb77af0226e1bbb3bad632b0d8";
            sig_s = "775954fe8bf936157b7ab7a683f6dc1838a8718200621bc8bf2f32b778f6c8e8c656532b50de39ac22d22b37dccfd1f9";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key has many trailing 1's
            m = "4d657373616765"_hex;
            sig_r = "76e5c07582177400df453114fed746f40704197897b4ca21b72e5b44d4ca40cfcaa55e4446355c91ea9767f38c8172df";
            sig_s = "0c6dd73eefbb4c06e823224d8efaa3ee934e4a97eed2833513b4d735ed06eb550b2a5fa7f86613d627d9db466afa6646";
            r = true; // result = valid - flags: ['EdgeCasePublicKey']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "34770c73a7e42ce7a57d1de6e54f35f1752047f6513584c7b14bca17d7abc499f8ab037c70fd2e13a8b97b2ae2636886", "22421615ba363f1ffe9a8f2fe0f6e246fda11462a3ec000c685e09a90dbcdc2af6467f9ee69b5e7bead9b8461f4a4be0" );
        {
            // x-coordinate of the public key is large on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "0e44fdc33aed0c320e371e2a78e9f18fde83434e681afb05a5bdb0f43cac70e83ede56bf8c56acf70e054e2ffef549cf";
            bn_t sig_s = "1324b4cfe684d401eac15b0940f5835436d3a1028e27c1966dbf69fefef82748a05b4443c77c870789135755d0d184cf";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is large on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "5966acd8a7714f2015e36fd4fdb3452258ce0aaefb3972091b496bd530bbaf1ec67d7e37e50031b3eea44a8bb8f62c20";
            sig_s = "2a5f309d2fad55b93a7a3012cbda2845efaa4ea0d187d3824f4a6a9227730d3ab15246d8d0952c7ee8c0b9eb83d1c2a2";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is large on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "266eace657e1ec88a2adbb38a5afb4f750274ca614d1fde9ea39dff6f2a2aa69923e9a7489f06bf9d84c518cee57e55b";
            sig_s = "3d19027684ef221216f63a591d8e793524e4c1234a56ce415bb9ad9e2ebf25ac94a99261b9157d19daa5aa876291f308";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "0086f0fc89b7861ec3bd582161aecfc95789ae402459eb7f3015b7dd24e20fc9b005c635fc290a0e2a9ff35863b7b82e3e", "01ebba489e923dad88146077914e3ae5c575e1bececec710962a18ffd91005776c4d9e4bd952c793587a70291ce478b4" );
        {
            // x-coordinate of the public key is small on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "13de6eb532321c023092aa78c199f9ee4dce7a18df158c3e799461af9d96c2d38765a78fdb14404d199365de05bd44c5";
            bn_t sig_s = "2514a0359bcb66122bf48c186a4bb2edccf305b06414b11f470d2512cadda129366f6072de715bc2babb8a3a5f260d9b";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is small on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "1308d3d9edfe3ad07e215a975b2b067e9f0b803371b3029f4388a3471f4db23f358aea5c03db62d77115c56c4962633b";
            sig_s = "4b8b1fe44b32cc669114a1ce0ba0555446d0c96a32cb602185e8fba414d3a831cbf5b519b0f90647dc45e30a1f23ef90";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key is small on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "5da3df094155b8f8812d0c6345344e41c3b591b65b95fedbbcbd3c3a3bb1c1dbfc4d4c5b841b8f8874d59b07cf2288fc";
            sig_s = "4a1e4a8399abbdf246929b2559bb0fa404772755fc74523626aeef432fe4764df1e1f5c9b0f897ed8f1ffd7a88167f0e";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "082f7dceb585c5ba4894b0faf6604da888a311ad9f41731a1d3937168a10b0795a1fae496cb9a90739e1c0a6e531e807", "2c3b8568eaa1c6f541a665ce7a66f78ea2d5893103e6028add62356492d8b5ac6ab8901d59621c33416c33981bd594ec" );
        {
            // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "0bf6fec0a5be27cddb0e7669ae06d15dfa75837f8ee72b47443ac845ffcd427b0893e10c85c20c7aa576fb70e87761ab";
            bn_t sig_s = "7418b6f374936adca8b07dc51545ee34ed2e9f56f3267033e30ea09a0acd31b6ce83503ee7e098627f8ba8b4c584341e";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "03e306a86f6b2cb248fcb68d1d317a6042b7089e96d74c2f5b934e2e122831268a45e2185b7c21270e8b906cd372e6d7";
            sig_s = "4c82ab6de6bc0194ac1a2e3480a0c80466af7d2a329d20b03151d1806a0bc0720f55d3781a7db9febe7d8bbd0a719bfa";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // x-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "14d1df9b3db55ecc8d1e126625bdf5b6316bba1e7f4ea5ec77418c754a597563dc5dc291b7dd047782d518fe74e0be83";
            sig_s = "33ef701c440f280edf81a9632dde9dc17de5f438dcc19e9ca5919b4b73e62905e5f7e0bc9db0b14bc53327f79f70c6da";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "6afe4ea7705492bda308b789d70da49457dde825d5258960a7a366e4665af9d326392c2672165ea4bbdc33374d88e749", "008475e6937a10a6f6a50f23de9126ba04e5650a1cd06a8066ca423339fc2ce53d91482744a4cdf2f937f76f12aae3f630" );
        {
            // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "6a3a18400686635ae279c385b640d4fa080d9c44a5d421fe4be5a5ec7a8ae31b00bfa406e919e57e39c11360e670d869";
            bn_t sig_s = "729c0b9ff77f88f810548d6db1835312a448114a3bd93cf59422faa2ea026f5d47627f0c11fb859112246d879c859568";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "1ab8d6c31d4577f59ca5714c9eada979fdb9ec0cad32d8cb915dbd70492947187f5a52718e19982f7a2d4cb48b227723";
            sig_s = "872e3ce7d1fd5ae180faf1990b11937558aa44ccdab631492b8925be84fbcb452148edad5bbfe48c06b8c9908ca252fd";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 1's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "803ffc58f8150a9c4c229a7b522357f49f9a5f48f82d8bb982954395836e09eb5f8cf1f345ce284674bc369d046d5c8a";
            sig_s = "8a9feb64c410cf3ae6261ad35f7e3e8da13129daf94944f8e08e9649cd006622c3d5c91ec5b9798a1be3a31533a0a851";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "4bc65262c22d322ea89146ccb5c60c4287b65a35228743a5b9dcd15493bd8642478987c421637dd0715079ec90fb8cd4", "7a45557ef653d0773dbe2630f8e000629ed8293e1aa4a96f3b159a245aa35ad92a1019c7e09a9ab75ba43c0786928237" );
        {
            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "2ed569f12dbe30a2abf02190bb9e4de7e218e9fd705dc71cbe1480022781b2a2213c3ef2f91052e90840a18f74e375ae";
            bn_t sig_s = "8872b566f387c2bcb639df9c2d866f7631df290c5f66c264d4949e256383b1b4b2098c120f13449d9d7bff6891919c88";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "4b7e5651b035959295092e2efe548da52206c8d0e48ba43e2b8ecd98ece25dc08955b6e7b05e38c4e22829d1658711b5";
            sig_s = "44a973b75528400cef3f63f55f2154d48bb0b826214200d3f33c7bc31155242d4e24f07ed19606fdb2c8ecaeb6981eb7";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "1ecadaceaa479fa4e9aabac4210b1ab77fc1d13a9c4cb022826bb1806575115834a6ecb9dec3e668b8c91d4aca283dc9";
            sig_s = "2de8965a66d56545ad84fdaee16fffa0eb31022186a5b6be2a2475958b9ad72f483ebd4b255748a811806bcd428acfd7";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }

        pubkey = curve.make_point( "2ac393f20c110e3f97065304397eae0e23187b2b6163dc66083e82aff568426843056aff8dc23eebce297f747830e217", "34c935671391c6efa8b46c5c37b3f84a82e429a7580feb9a1383b55c83a9398e8ecc7b15d699e63962329102a1576f2b" );
        {
            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            auto m = "4d657373616765"_hex;
            bn_t sig_r = "37e256872340da9dc884fd00daa14628372b4bedc0a8a09f9d7513521d3b803a78dc0edbab3c7dc2b2014baf7a9d210e";
            bn_t sig_s = "1ba4b4087973070cca9b957650177eeb41c557731596a966b0b7f68717d8e7b554afd07c2937c95403a90c3a05fa964b";
            auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            auto d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "00128c199dc27677f23feae28a9b28813cbc3b02fca493005a67c3126a705c49b982cb5817ee2c81161e80b738bbb512";
            sig_s = "73cb6d4547771d254be74348955bee979071358aa3afd62a5838179a0965465aec79bd6cbd9b8b2aa2c79bb88ab21592";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

            // y-coordinate of the public key has many trailing 0's on brainpoolP384t1
            m = "4d657373616765"_hex;
            sig_r = "818b0fd6ca0978a59cad3fa15e84db2896f39b2aa462f0583834fa4444d153fe61e0c93071ba96c5ffa7193f77b806f3";
            sig_s = "1d2d6144172385f857db4b7e7e863962eacacdec034b4b4a9dd1af272604403f39f45a21948b30976e738e9e98fd9cee";
            r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
            d = sha384( m );
            test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
        }
    } // End of Google's Wycheproof tests ecdsa_brainpoolP384r1_sha384_p1363_test
    }
    EOSIO_TEST_END // ecdsa_brainpoolP384r1_test
}
