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
    EOSIO_TEST_BEGIN(ecdsa_brainpoolP512r1_test)
    {
        using namespace ec_curve;
        using bn_t = ec_fixed_bigint<512>;
        constexpr auto& curve = brainpoolP512r1;

        // Verify that the curve parameters are correct
        REQUIRE_EQUAL( brainpoolP512r1.p  , "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3" )
        REQUIRE_EQUAL( brainpoolP512r1.a  , "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca" )
        REQUIRE_EQUAL( brainpoolP512r1.b  , "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723" )
        REQUIRE_EQUAL( brainpoolP512r1.g.x, "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822" )
        REQUIRE_EQUAL( brainpoolP512r1.g.y, "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892" )
        REQUIRE_EQUAL( brainpoolP512r1.n  , "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069" )
        REQUIRE_EQUAL( brainpoolP512r1.h  , 1 )

        REQUIRE_EQUAL( brainpoolP512r1.a_is_minus_3, false )
        REQUIRE_EQUAL( brainpoolP512r1.a_is_zero   , false )
        REQUIRE_EQUAL( brainpoolP512r1.p_minus_n   , "1280f3ebf4f1d42296d47401166f7709f0ad02bae2524eba77322c9d3bb91488a" )
        REQUIRE_EQUAL( brainpoolP512r1.verify()    , true )

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP512r1_sha3_512_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP512r1_sha3_512_test.json'
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
        //   MissingZero - {'bugType': 'LEGACY', 'description': 'Some implementations of ECDSA and DSA incorrectly encode r and s by not including leading zeros in the ASN encoding of integers when necessary. Hence, some implementations (e.g. jdk) allow signatures with incorrect ASN encodings assuming that the signature is otherwise valid.', 'effect': 'While signatures are more malleable if such signatures are accepted, this typically leads to no vulnerability, since a badly encoded signature can be reencoded correctly.'}
        //   ModifiedInteger - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. The goal is to check for arithmetic errors.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModifiedSignature - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an invalid signature that was generated from a valid signature by modifying it.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   ModularInverse - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where computing the modular inverse of s hits an edge case.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['CVE-2019-0865']}
        //   PointDuplication - {'bugType': 'EDGE_CASE', 'description': 'Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission.', 'cves': ['2020-12607', 'CVE-2015-2730']}
        //   RangeCheck - {'bugType': 'CAN_OF_WORMS', 'description': 'The test vector contains an r and s that has been modified. By adding or subtracting the order of the group (or other values) the test vector checks whether signature verification verifies the range of r and s.', 'effect': 'Without further analysis it is unclear if the modification can be used to forge signatures.'}
        //   SmallRandS - {'bugType': 'EDGE_CASE', 'description': 'The test vectors contains a signature where both r and s are small integers. Some libraries cannot verify such signatures.', 'effect': 'While the signature in this test vector is constructed and similar cases are unlikely to occur, it is important to determine if the underlying arithmetic error can be used to forge signatures.', 'cves': ['2020-13895']}
        //   SpecialCaseHash - {'bugType': 'EDGE_CASE', 'description': 'The test vector contains a signature where the hash of the message is a special case, e.g., contains a long run of 0 or 1 bits.'}
        //   ValidSignature - {'bugType': 'BASIC', 'description': 'The test vector contains a valid signature that was generated pseudorandomly. Such signatures should not fail to verify unless some of the parameters (e.g. curve or hash function) are not supported.'}
        {
            auto pubkey = curve.make_point( "1ec7fe2275860c3bc0e4e6e459af7e16985d37adba7351ac357a7c397e07522ea41bcca8e89777fe05b8f0d9dc8c614004fcaf30a97001a5011a159f46fcd544", "3cbc1ddfc7ac89a1a2f8eef77bf9bba8ade73da2100cb6a371546b495fb5ea885eb631645e79591db659c49266d263d5cbd3403081cb407536efe9a5bec69955" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "8a7e0a277d49c29d3ed8b0dffbff6fb07644f71005a992bed255b2b5a5c10fd931f3b379cd644427a1c3311d863298b75c7cf5413e8ed8ddf11fc74be0b7e0ce";
                bn_t sig_s = "78c5950ad2b4b1b976a643cfc610dcab6bb148c473d4c186904ff30a1da1c68f6f83f6c1db5f7adcdefc1c8de931790779e236f2a504dc8b0b7c6ca4cb163f5c";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "78fafe72fd0aae1256bb241dcaacf711dfea2db4af56624a8fd950c9840b9b71e1da89683fbcc9950c5d65187657042e5f17d1036f1fa09163b4e05b7ed14b69";
                sig_s = "7175605f805b318aff1abeb65bdf142ed6fdf268193e4adcadbeb14b7901f5fec28cf19bd8eda341b925b80a73e672b53a209aa5be25fb54596e51df2bda9b85";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "5835eb9c4604e9e8be394ae80ef31a7d4dac25e50e4a196dbc3188e8deac1bb45edafa8b45bead7c0bc21eca91d20a81ea42dd64b9d9bf2c844038bb75f80b51";
                sig_s = "2d480826582a8164646a2bb13408e43bacba3f42cc3351e84a5e572d03e15bf3cdac5e263c495209e420322c7e4e6a2814921dda253d159c4e934cf0e913b92f";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "6a73585ada17fe93656e111943a67b2985faf878f82e03b4a67792cf3b320c34c1e0dd53059b5a3b3888ed301df0ac7df87c0c15c8fd73bbf11b78a924995963";
                sig_s = "319f5670210637a0831f4279571b41b5c5edc8cbf1b6edbd44e6e7d21353694bfa64ba12657a2b03267c403b40d4b27b03e46092614416127d44bae133c78417";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "67cea1bedf84cbdcba69a05bb2ce3a2d1c9d911d236c480929a16ad697b45a6ca127079fe8d7868671e28ef33bdf9319e2e51c84b190ac5c91b51baf0a980ba5", "00a7e79006194b5378f65cbe625ef2c47c64e56040d873b995b5b1ebaa4a6ce971da164391ff619af3bcfc71c5e1ad27ee0e859c2943e2de8ef7c43d3c976e9b" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                bn_t sig_s = "115b34f6baf38a5d856de4f6d07add826a4897aaaecb149a1d2226aa7c5e1d98e32adcd58d2fad01ba45a2d4c293b1432011b7aba4af043ff7243cd24461e4ff";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // valid
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = true; // result = valid - flags: ['ValidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to r
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e710000";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to r
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e710500";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of r
                m = "313233343030"_hex;
                sig_r = "4fdcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of r
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1ef1";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated r
                m = "313233343030"_hex;
                sig_r = "dcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in r
                m = "313233343030"_hex;
                sig_r = "ff4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing r with zero
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending 0's to s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a0000";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // appending null value to s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a0500";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying first byte of s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "02998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // modifying last byte of s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471bea";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // truncated s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // leading ff in s
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "ff00998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replacing s with zero
                m = "313233343030"_hex;
                sig_r = "4ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ModifiedSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "f8ba5decee6d4e9119afc13d014c31c9bc79bb449e6ac997c7170fee6c67033131050b0903e5b53a413b1d16eeab9fd2f7732a835a75470bc76bf2d63b271eda";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r - n
                m = "313233343030"_hex;
                sig_r = "a2ff227b3699c57a9a05f3e099b839ba26189fdd36d7257a1a4fd6598c00f250868852866a936907be2e5ae3ef537f44bc0f838149b991505c5cc5d101d51e08";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "ab2b7a790ffc481545aec188c2977e3d8d21d6e144b473065f54503d942f3c6b161a22f0146062a8628615d57d1b0fd6a98b94d80aaff249e3997adef0477e8771";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -r
                m = "313233343030"_hex;
                sig_r = "b2233fcbed7c75fa26252571327dca3e0eb6d26f155f08770f4c8cdc03cc053f2439513848c370df004b440291007074263ea8fdade893d1ee1ba3ac6181e18f";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "5d00dd84c9663a8565fa0c1f6647c645d9e76022c928da85e5b029a673ff0daf7977ad79956c96f841d1a51c10ac80bb43f07c7eb6466eafa3a33a2efe2ae1f8";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by -n - r
                m = "313233343030"_hex;
                sig_r = "ff0745a2131192b16ee6503ec2feb3ce36438644bb6195366838e8f0119398fccecefaf4f6fc1a4ac5bec4e2e91154602d088cd57ca58ab8f438940d29c4d8e126";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**512
                m = "313233343030"_hex;
                sig_r = "014ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**576
                m = "313233343030"_hex;
                sig_r = "0100000000000000004ddcc03412838a05d9dada8ecd8235c1f1492d90eaa0f788f0b37323fc33fac0dbc6aec7b73c8f20ffb4bbfd6eff8f8bd9c1570252176c2e11e45c539e7e1e71";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "014460067afcdffeb8fa3be86597191a8d2c1883bcb8c88f838fa512ea6407f347c751dbad0c229f30c8c71f5e3cc46f4b1b51ef566c0cb17b73eaf032f4f01bd3";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - n
                m = "313233343030"_hex;
                sig_r = "eea4cb09450c75a27a921b092f85227d95b768555134eb65e2ddd95583a1e2671cd5232a72d052fe45ba5d2b3d6c4ebcdfee48545b50fbc008dbc32dbb9e1b01";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "ab7720219e0abac56d8f4dafeb2d4b26509175a9bcced0cc4b1cde409026dd5b2cb06fc0b8689f92590da1d7c46928a621af739cddc189b45345f9dc4d0147846a";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -s
                m = "313233343030"_hex;
                sig_r = "ff667d973ddf09c5d24598fe489cb0e17a9f1809f6fb01428b46be89e00c2b15288dec8094408686e878bf41bb42e7a0fc025fe42a9c512962419ca64fa7b8e496";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by -n - s
                m = "313233343030"_hex;
                sig_r = "febb9ff9850320014705c4179a68e6e572d3e77c434737707c705aed159bf80cb838ae2452f3dd60cf3738e0a1c33b90b4e4ae10a993f34e848c150fcd0b0fe42d";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**512
                m = "313233343030"_hex;
                sig_r = "01998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s - 2**512
                m = "313233343030"_hex;
                sig_r = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**576
                m = "313233343030"_hex;
                sig_r = "010000000000000000998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                sig_s = "998268c220f63a2dba6701b7634f1e8560e7f60904febd74b941761ff3d4ead772137f6bbf7979178740be44bd185f03fda01bd563aed69dbe6359b058471b6a";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=-1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=-1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "01";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=0
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=-1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=-1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "ff";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=-1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=-1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "00";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "01";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=-1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "ff";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "3336363736"_hex;
                sig_r = "7da11e5b4bb7932135cd91accef8892c4286654a7be7c9d384b600d97900ee12a23ff1f9ae9a4fe74cca185d0dc9f59dc24be03d0223d8feb55b6dde1777475f";
                sig_s = "75905ab5d58481f78409cc2e058da26a26ce6cf4fa2725023d7aa59b8393e16c08564035599c47c3c295da467d41c5a242f0a477101ed6bcc672426eef5f2dcc";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373239373236343137"_hex;
                sig_r = "6543c55475e7f31a48bc85307455f6eb4d719eb22555ee49c508e95542fff9b7fc7e90be7e4981560bdae23079cdc53a50ca8dfcb77f119fcbae0c8fafd701c8";
                sig_s = "19b4c639be53122f727d61d4c452785a9846e979f8bf59e2038edec19de06443cee4d4152b49ba9fc84d75d3724d134e6b72702b78bc97a3831fdb92642c4d9c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343331343737363137"_hex;
                sig_r = "7bf49763f31715ccc377c07dc202a48027871f25e40b09523b7fe459e34c9d7c7763f34f5a81cf9f700c3fd99e84d491a96b78431f848313081da94b02979862";
                sig_s = "8d7b2af106d7dbc5e7cb6d15e64b5073dea52d7985051b532331553b1942908b9db61d95302be7b5aab5f13f0ef41821f0df0fdb2d0d5a425a88f95acc2f0005";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363033343338303333"_hex;
                sig_r = "9b822634932ea6d8cadc0bb3cf7155f16d89d1fd27877a54ec8e8880ef9abcf058f46bb3f90b05db2434c804eeb517cf321d45964477b6a5555e877432317bca";
                sig_s = "4c5a0ed6cdbad6205e1a0d5d2be9b43e8ab046621e409ed5ffd0cf0f0d49b4c0459b47eca8ed184f1e30f2684ed8fc3d192f02ce7beffb5930db73b9beae2968";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383239363231343535"_hex;
                sig_r = "38f372799a30218935dffc38082f4c9ba081ff688c6f46a1690e8ddcd8c311766862d01b75b959af2d6af8d361e26ecc3862c930eb896e358a6101349327de23";
                sig_s = "7d8b5462ddbd2f73980784452875b7d8726904bfcb88e94feb5088feb820d197dd9ca4cb7b392dfa2f46c8322e11de947af5a64072c766cc601891eec16279e2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333131383231373336"_hex;
                sig_r = "220f24ef6699612c80ebd8ec8c5cce625bc43d72ed42f7cfbc78ec033dc549e02b780d503ba6426cf1914cd3152c62b71dae1e59615657dc9aad30bd4efdc7a9";
                sig_s = "706834778448f4dc11a1bacfbd4834b4f6d15ab343963d2bb9e5a12b44214957f453f76535e9a0ff9f010a8fb9944b9d9e1ea8bd0b104b2bdecc14960e4e751c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131373730373734313735"_hex;
                sig_r = "4cc3d9fcc06dce19ab12a665eba4e42f09cbefb44e3e87ce73f14986f48e5b9e25773edb4c1e62421f3f4cb437bcde279c247deca659848a26a27700a55f3333";
                sig_s = "75344c9295cf201478f1a45ab81a2ed420b3b829872146d6edab62b61bba2a97c10af4e1b54060d26991960f96ed7e6181c51286034372ea0c88ecbae05bc1cd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353938353135353635"_hex;
                sig_r = "4925729610c57144b2d29743df20bfa6f67213f8c22907784d5d127fce0ec07ccf7703498b9ab9d84fac4a99683ec40e6168fc278718bf7437a749382299d83b";
                sig_s = "4b82b497aaedc2d4d7eb34b55928e72d647d93aff27ffee54a029fada7ec18921b9f4d6b7a7317bbe4f1c5fbae8c9445a807971a65dc6bc46b5a27406ddb84cf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383831313031363138"_hex;
                sig_r = "09f2dfa97a2c7e3d4ebd3e629cde0f870a3cda0153acb5ab582fc0b8db564c5a9c988eda930b579efcfe4860a1e51e9d471438907dc0f831e8c90884951d580e";
                sig_s = "3ec46f6253ab31e4c5019a0d88a751a4fcc4131e8e24602bc2b712aaca9710048fed4b5ad59c0e74e421fa7e823c597572cb2165c689a22235532fab5627a1ae";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303034373833333332"_hex;
                sig_r = "81586e05220f72bfa37681dee7d6bc0945cbae37f54be6cd0a8c479430ba6bd01ac8b92f0cbcfc715b3374d41b3da6c117f5add7b0ca1db122e7a51620239bb0";
                sig_s = "4da1fcec8de0eb6c5aa30975f2f801710648b959112ba473818461d8ee985f631a82b31eef200c3cecbd3750edda2cca49e76f2fd500927b3185e3497d47966a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39353030323437373837"_hex;
                sig_r = "a840d04b304d8831907720eba1ce85376910ed6235b42493234e17db24a184feee5cd7175d7c94403ee0f074b87e1460d3befe56f91869221f12a2f05e7f57a4";
                sig_s = "55e69e441567148b84701b542682b53ab8f8f80624609b80191bd9aa2643723d7c793fabe946374d7992d1464e6b9483b36bc9035e0a1be1309e6daa69a671cf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323039353030303630"_hex;
                sig_r = "a7b7feea03567fef7afa42fdc19124119344d4e4a5e7b6efcddc28818ef018846697d096269f45231a604b516c1bdf684ed9d98fe2535d4cf8ca6687a8b9c1cf";
                sig_s = "4784ac38fa0e83aef1679389c0b65a55f0622c9ee4666e3f09d9b631ffe8f4b97b9bdb41ffb9f78490f509471cc059fce86ce401804d771d363d680df20d2286";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38313933373839323237"_hex;
                sig_r = "9b16f1e8f609a4f60d184e0f2a4350c56e16d73cafc88871e34f5dac404e4e5d80bcb47df9e5aad8fa08d9a55bcabd02d725d5caecf3d907879f76ea7daa7667";
                sig_s = "160afdddbcc76cf7f9dd76ad230c5f6390c7c0144c952f4184b70ea0cd027e5b2a6c2e1ca50da87c2662bd79b7e9bc23640ae306f8eb748341be9794cc58dfb1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363530363033323938"_hex;
                sig_r = "1bcf663b9737d2677f618975a64934e999d600cdffcdce9c08d0b5603fe2c3eeae7368d12db3435377dde41b82e158f06f73e73848dc51d1583b0667304048c7";
                sig_s = "667c384af3eb1f704af8607bd6f76f964b076415cd855c43a94ac68db309140c50caf0790f1935fb1129ed3c89af8fb6bccd8b25f23aac21c7cf9ee3c607cef6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136333833393533353233"_hex;
                sig_r = "181b0500c4bdf3fcaec57c12c81dae84e9765ec3fab2de4c7b27c9b97cba19469b32251ddb39efb0cbbf5606a7efc866046153b791830bfaeab56f3b980aba67";
                sig_s = "81fd9814c445a6c5c76fc3c614b7665b438c7c07be299b80341ec07d9ecd22d2c2952e99dad009cfa543a3be40618f5f58afcbebed70d9db245baa92697f82a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303931373638323035"_hex;
                sig_r = "41c1fb7c47ff901a328e4e934c8a023a943d37942b6ab22198e9d8aac628f1be0d487bdc267ad9c25b1a42734b994614245722671fd5333e8c34338303348e19";
                sig_s = "31dd3d9f1715c3b63ca351b03be2b83ad66bdcd0ef85fae15953c9e9c85c1a8124b2708245b9b7496d9f2599ab808790b0b63ace37f7839e12fcc278d604eac7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39333634373032383235"_hex;
                sig_r = "82c6e55736b3670faef789b491a48f493b081ef655987c3994624e666a898f5bfe2160d0da808b83f465c05e7abb4f2ee6e43e6e935faabce2edb620ad593ea5";
                sig_s = "4cb6d243bb3f745e2988caca2b3599dd63f8e7c270435ccd34895e332a858e105bdc5e23e679769143ff5dec5f83a7e51800892ced4445fc1f94568f28b055f0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393236383638373931"_hex;
                sig_r = "257dad15a1ca0bbc3957b7c13681a977b5d42c84284321252cd30d480613add5e0e6f28efdb6cca0739f7ced876fa00f82359e339b587119ad8425c16f3ea765";
                sig_s = "5900832bc693c37aaf384da29acc2b7e4e2094517855b3bba50837440028afe42956988be59e7730c5155d737610ba42b9cea876b3c4baaa56072181a43b2a46";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313738313334383231"_hex;
                sig_r = "67730a1a6b716e027c69e3e100a63569467597a9602677c72e4c55531ff8e828bdc544b5fe6b4340ad5dc3e7033de6fd3aefaeae3ccea69c2342d7b34965d8dd";
                sig_s = "106dcb0599858bd2fcd09f501cc00a56df993ba4616e1639cf6b53d752ed2fd3e3125ee8731d8c08eeae32c3765078833576e181d25ac6bdb4965cccc115674c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373335303130373531"_hex;
                sig_r = "a9bc80413ad79361ce8c145ca7484c6a66c5ce5071002df9fc77efcea6c764b90e667f81fd271237fe87d9fa714ae4160a72a162eca02a746a539f2fa47c1caf";
                sig_s = "36ea750ce482aa21602322075803cb8c50ecfb87819ee971f53d56ef076404a1fb5738f2cc55af9a90f433efd011fdd6e9f3bf122914237a3dba9770a93ab98b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134333533393131363839"_hex;
                sig_r = "03892fdcaea7181c73950648ded96fd7c14f1ace1f2fc91ced15ca2f3b190c3b3a650478cf55097d6ba0bbfadb580fa17095eec914065f30e4eeba7d76364575";
                sig_s = "3fff250e80a64c9052387d864453a3ce0dd907f8342074a23e9d4b33b16adec7e55844f384ae85fd25bb76ed1542e35087d09ee96ae44da54769b74a30dc7e08";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333834353439323034"_hex;
                sig_r = "105e1a0a5c4f645010d86a38e8cd90e9d25a71e7f0e23d220dcc7e46d8fb5b3d81a412f1c4a95f450060aa60c01b3a5822b9d1c9081ec01f63af00a01f488f69";
                sig_s = "31d412e5c9419544f1011a3418b4e549493abe71a9bcd8cc98eab165ae6f06d9ee26f980cf1d77fac3d003667573d8ef82e3bf992c1a924ff2c5981ec6a33710";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373632313932373839"_hex;
                sig_r = "6198b7272716a6f5ebc91d6800efd4faf74536afc96889545b4c7141b590f091497872a7bfb2fd9fc209ffae6b7a3db8d7ad884d9864635d64f34e2d55aea7d6";
                sig_s = "77777ca3f1dba89403c4a006c19285f762187239cdb63c63521c0dfb798f48822248497a7576b157849fce4918513b0c840e68af1d491be126852668766353f8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383331363534333331"_hex;
                sig_r = "5e050ae52e112621686e2cf1bd698dbf6e579c6cdcb27b026f305f65b6c8053f7f3a12b411980e35130c966ecbebb4f7f6b5d5e50cefd716da433195791468a4";
                sig_s = "5e6bc53d676dd39d93bcaf26537fbb7eaad497caa1216e767160bb2b31da550eb248f0d881e19fa36c048a700b2d64a4c8dbe6a9c976a7ff2f4c73feae1c9846";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343336383939303330"_hex;
                sig_r = "908318cc1ff55eaceaa63aff859ea5d36968ee1021fa668a547793bb0b3c723b6847cff2c65b53a55e00da9fbdedea1acc8bad954d1830f5328498153c43adb0";
                sig_s = "556d3ee294395a3654b6f1f03b827bd025da19267e92d6b067c5d707d3f477fba87ed6ba8162dd089dc4f787c11c3735940d2aa039438284f032caa3c4c2e98a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323034303431323232"_hex;
                sig_r = "4f33da81b8a1e60d75f8170a8cb70c4d109cd06cca95914927e41412befe0d3f4063d4b32fa4bc6db1478b4ef3b89e397321af756da9210922c9d0441e4443f0";
                sig_s = "3249956e6f9b5c1850e937cc112e49e9dc0be14f23f52b25431b7b71a27216ff95360934ea9a5e1b2b588fcf0ba9d964f38d0bd97232bb3e0b2e306b3ec15e00";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333337313139393735"_hex;
                sig_r = "5d555e697b22abcf1fd1828365607a2f8699679648cb5b8e6ea511ae9e47ac245f6c858d5e8185b989a6ae84b196c58429dc8edd15cf2d673616225a8d2bd92f";
                sig_s = "18e0497d40515428cdccc92f4d23fe9e60e3db14256ce62a3c2eb0cfe791e39e1caf26da861c863074813e5dae61c08f264ea1c9ce0b0e7d43e2607c4cbd860b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363935363230363738"_hex;
                sig_r = "64ded6c7fde2dfcfd74bb88d8a692ae4579668a2e65d6d7cf688c96a5bfb126dc409a67414b175b3f91509d6deb8838f86e3edd7b2232802a5833f0be8820bb8";
                sig_s = "0e6e93007fa43aacac638e9b6b8db3a723f26958c8d8469fd9cb812127b831bab190fd4cba48ea2fee0f8c05e4a64270ce28a58bf278f6a2469511ffa4222837";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303933303137373437"_hex;
                sig_r = "19361ca1964ca42975f893df4a7f5f64cbcca783f2d63b3b9c4f2dc672ec8d888611e7987eb7b39e2bcbf11c6c2e70d1edde73672a609ddda3768821d81a49c4";
                sig_s = "93233eb41d2a12e25e5316a74e92ab547ef2fe083d876c9c3e8c1908887f7338a02df6316c268da4817bf266fe666c35bfb34e3a8276c0dedcba42a17f13f038";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313233343137393136"_hex;
                sig_r = "4c7650cfc8d2b3e683413878c214f9c3cc809bea391e7309d8a5e2acb9eb8a55bfaf82a0e33e8eedc7bdb7a14d74c7b9504934832aaa2c2a1426a3918357def9";
                sig_s = "475d0c318cbce351dc6e12ed1ee589f96ed6641d0eb2af72df4807c1c5491b968bcedf1559da0c6624e54f008171de73ec788691dacac81c36585f4f883a6fc7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373634333530363837"_hex;
                sig_r = "639e391dc1fa17e54872183d7a9c8369e89553c1001294c3769ec6d359c87001687903f9ddf191554d72d3100803e0777e0ba8c20d7254ffefbb67575ced2650";
                sig_s = "210b89a962de417886e8fcb4f6cbda8a329de6c65bfff8ff2bd8e5ff396049c45efc5794915fa09d99000b310a1c962468bc52f8a646a79ceaaa5ed493224739";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343137323431343431"_hex;
                sig_r = "27dceee94a53b7c8a0d074b18fe14d3a0f9a11ebd15fbce3b37e41af461b8b32d0ad33f15816192799a67a996a2acad62f59797343a44e28ce36ac8da342a394";
                sig_s = "6c034233a92eee8b4b7818682220b620542fc1cfd50a80f93df875ee205b9ec8403e6eabff588c688189d1645598b1d5fb09a6eca5ede0fd851025476d7d6625";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323638323436343933"_hex;
                sig_r = "6f0bed39c9ff5f84225388c0f7c8f7133ade442b0240bfcb6f11c7e91367596437ea03fc4b04b9d7f7f388ee29ecb2c7b7fc40521bbeea6efda69a9cd7e94c50";
                sig_s = "38bf833bc4eff745a27522fc5826474d50f69532df4c570e2346205f17f1d7f60857caba54d15da88969dabd331bc27825dbac1dab51334e99356c6daae14014";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373234373936373737"_hex;
                sig_r = "5f3d5654794645ac13d01a9f9a4d755487f68c3eeecd499297e1a33e466cb309c3384b67ab33295e31bce428d6bb52427b163fab8e2bbf7d49947bf5507ff172";
                sig_s = "092016256207b65ccfa71fad0da7c2ea8b5de277f9abd94d137131636220a2a5261df51c51b4afbefd7b8e818c6525a14ea64acff0d92ec1841dcb15b086d67b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393733333935313139"_hex;
                sig_r = "6948a7b577b8dcda98eb50eca3174d59d420e901877003e8fcbf72f1289af5e9eccd56e409be03a04c0eed47a5a68e4f1f83fd52d9532d8dfa0e743da975c113";
                sig_s = "0d13a73824ed1f50e0d15e6218869a8ec293fc38313be3bb8f08a9ec7354ad17e7a415c471c00ef4c98c41d76663758bb4160622ad23e6fb303d2bf3b4b006a2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353037303032373036"_hex;
                sig_r = "7d33b0bb04ad2b774c51f7709ca76206e1b98c719b74ea62e1f19114473e5bd93a645fb6093562cdcc21881f90cfb09705c856d90505b408fcac655fe96433ab";
                sig_s = "a5ca990853eed5ce201ccf4a8bd60167684d8dce4b50fbd2067f8de2e058c8bb2384c218db765ccc779870775f28bf2dc79e0665efa869eb60964fdbdf2b4572";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373433353638373832"_hex;
                sig_r = "3414d09e02ebee92cc74e3c0c5225aa94256aedb0e8c12edb14d28a3e001d72a0ec4413b807d5641d22af688fb8ee9a19ca79310642d42d740fe546bcad2be2f";
                sig_s = "575a6c0a321c9e52cd0434b12bf20adcd39cb9acb0849b5dada6226a6384f816680a3e1a04315f1a3228ddcdfbe61d814548cd4f93c006f02fcaf3c02d3f305c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393437363731323438"_hex;
                sig_r = "4c5e268a8c22b7093f73a88b31cb6ac30530dddfeca6ef8600d53267dc9517d2f9a7836e05f6897c1a244d1788a81f6b53bd0a1beb60d13ef99c2bf6b491e297";
                sig_s = "136e0cfaaa1c3a1b234d8b32d7f9066d9c629b580f23b70726d816e8d75ab3d19c344b2ae1f3d4bdc589f2305d480ff007ff57be19222879694c160249fc9431";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373235343434333234"_hex;
                sig_r = "4089725aa3c3f316dc89ae22df53a92e2056de7285f5766dd4a9c08656b13df5591f8ac64e1154bb344e2ab7a08a2c5604095a1a564b98a0dd1f4b591614de2b";
                sig_s = "2b14d5b412a7f665d6212c06b7c05a694d856d986e6b1b9bab4829a7e9740e1dbd4d91e7533f1227f24141664fb4adad6f9b8f9803252fc2f16f980c2dbfa36b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35353334303231323139"_hex;
                sig_r = "478224ff8d3206d8c8bd4b1e2633a236e2b2230aa3fd22d0de3dd2bf2d0807f37cae4f45dcd14b99ec6696a163c295e14a56b484282821d65fa128c7f09beac7";
                sig_s = "0bba71255496bb865614d9170147a4104f1d0f77165433c44eadd892d3aff323855b46ce99d2e08fa620ffe76bec727556059abcd7f6adaea307edb07c2f88d0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132333031383133373933"_hex;
                sig_r = "a8e0c11cec76806101ec44e52a1f837669758a66202cc70648e9062b2cd667d93e04195f81c5c9c47b38ff324d5f61e3e7ecc328c9fafd74152cd3ca73f7fe29";
                sig_s = "558a4433498f936786d00287d0998e006c3221552f80847982199650a36b1dea273019615004ee49f9d9ba7c9b9271e392dc071a180e3be7c611395434388b3b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39313135333137363130"_hex;
                sig_r = "925f403dea9109e189a10a4ed0d41a974bf38cf7ac35a2750a260467874df610d05c0a4c0a69085ef554a6f369a7f4ae4fec7ff5294a1dd8ff72c20587fd4a5f";
                sig_s = "53c13377bde12fa7138cc584b386d8aff4a63929e99bf7aea3d29f23afdfc69abfb77ce4c542156e66e4b884b692d185ffccfae6721344ff194821771aba77a0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383934333937393632"_hex;
                sig_r = "92f405102447f52fc4afb12e3661e5b211c96fce5bdaa3f3e29ea121233653400f15b5d5aec2c6e7986c42f90be637e2d508c3718c7e082bc6304b7c93b696e6";
                sig_s = "47cff632ee7f634691d346e1fd230374e947890029ef3ba7546a6b7a3c8cf9abeba54af97dd74a88caebdc09b3a684ed690c690adde762a59f6846a3789ace11";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323333353833303333"_hex;
                sig_r = "69b000358874fb1e99138e7b709441ef24504d788525f1dd888dc3c6489dbbc8a25f650c6e0f783ec7aa55e1c0105a41a20842647a57a30e040f48016b15038d";
                sig_s = "1c49b84d4cccf874682804869021a4c0eeb180828889f35dd9cf2e7b7a8eadee26a7237ab0ef39ff11690478ec861b28cfb00e911249a00ce24648bf04755aaf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323131323639323536"_hex;
                sig_r = "1871a430b8433a5bc53b0f8f6ce585d6373277750a994c795a5cdbad1e2ada6c4781ca673e2a3d938e3108421178bc8f65a1c28f6981f20d252e15b1f6e07ca8";
                sig_s = "a8e972c210a42fa8612a319e3d1d9da87767d5a128929bec7fbceb996de8704e8274bd9400315b750501fcf5ece4a33269669466834d5a530036a88d6ee26bc1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303035343833383634"_hex;
                sig_r = "95f5150811a220a7970cb2463a1ea661f7459f42119520d73a5412d9fe7247a52ab077281d24eb0aa17360db6745b606401c296ed966936c7c43856cf060b046";
                sig_s = "59bde00870335387d826de70cd7ff00cacc623b6042add4e60d727cf73733c0de3d2ec8d568e3785c7841b69f06420dffd21087b4fbc851e5836e90e8ac114cf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333536373632373235"_hex;
                sig_r = "0386171edeaf1c804722df57a0464af45d1a1012d4f559aef1d465e3363f45de96600561eb8225d10273c7c34ac81cb47b658cc93bdf0ad25172fdde2f4be4d4";
                sig_s = "3f645be06aa634b095fcf01b67da9e638d6c8870a81e04607b702177012c46141bb42b65bfdd609527a9ed1b76edb3cd0d703483c161e069b628c2c16ff6c07b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333239353030373630"_hex;
                sig_r = "59dc66313bff1cd3d13c329693d3a235676bd81bf4e15c6e8dc2f9b57f5c5ef56e9007ff9375b8a3cd3ae523cafa374f3e7b26fdfb9f9ee08f0e9d679c3d083b";
                sig_s = "53e514328ac494bc67c2dce32ec519fe4675f642f0409573a03ae3e9c969cc88820e7bea9f9cc3876c63e01e2591103fea81b6ee1f46ce787b36631c9377be2c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393237303834313635"_hex;
                sig_r = "2fc100287074d86b8a096a7bdeac4cec9caf6e61d8b7baed7d5bcd8d4b9fd17027b5c70b401cd3ccf1297655be6e085ddc717e0bad17af8e9fcdcf5e7a312717";
                sig_s = "7719372ee3b96eec0e08be76aa980055e90a7dcd10b671e88748fe53bd143f9a352f017a87d366a73f8502d2a56307944a2eb68d8bca40c9d5551922d40d251a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37333032333538323838"_hex;
                sig_r = "90f645aa5c874c66df2b5f8d72e03cd5b1012ec845b30a06e4ff1921c00384dabebf165d14f03bd41bef4734913a9e0ead7855f3816cdc23127061134187fb3b";
                sig_s = "2439cbb3dc7c1584b09368999a159e00a33abd11bf29ef659659c2463d7e3902fe7a50b475399a2962e38e839f3988872577b3d225eace837b2d3176d52acdf3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133343733373337333833"_hex;
                sig_r = "99fd8fd33d70fd5bbbd3fa86ed71995bfca1630eeb12e19a56d0c57999adfa0331e626b06d628e678adb8cc8ca72d167bedefe71cb98d836f6ffb5ac674fed4f";
                sig_s = "9054653e461e5871226f4ffdc996cff07dd548db54884d7cc7a416bb39f36a506b4d83ff375cb9be69ec2f8b3c7d1e91ea85f532ee7d09cb04d96abdc3cad5ad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353031353533363839"_hex;
                sig_r = "a99e95dfe8c3aba5bbf5dd6bd6da28d20cbae081661f7be72794f6aaa004ae56f7e1ce3af4b1b56b8e57cf5ae17260ddd0e957cdcdb81e438ff5a53bae86c84a";
                sig_s = "a194b8ffceead68598336fc5dd99c15a1e68bf9586039bef873680fabbb7db4c48cf156beca5586c89e67deb722704c779863f6c3a6048f9bfa793dc605f231d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353335303430303239"_hex;
                sig_r = "6f2f644a718b7f4d02d75be23766b36590e06a9951c43b01e6b99013f640fc746a1ee1d7a5e104dbdf3cc949ecc7382f28ce31bd39a4430a9a0030b693cfca08";
                sig_s = "33aeb68367627ed6dbfb62a22864b438049c8fb52e55f6338de4d366e7668280b1fa77eaad1bd35a1463990f1b734b5c11ebb0fc47de9b2ffa8272f58f2d82c5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343230333537323930"_hex;
                sig_r = "a86511118e902f3833c05d6f54e9243c4128ae271e7408bf464a754cb770d870b3f4d854806aacc3ad3c282c79e2f65a6cb684cc6787d1adeb4ce13c5c6abd1b";
                sig_s = "a6a1fe0890d953a391b96bd2162930a7a4d553fbdc8c42aed23610e2d3aebf23a2d694a1d0427b10af3d8ed7a57d9086e7478dc9ad9e0a6a0b09a6cc659363e3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393035313735303638"_hex;
                sig_r = "7fd35d0452fd4db353d7452e3514c2890d74c7b76e577d07d44d69e3f8d445089d5a24487d1ae8471aa861448f77efb8af46fecb3b33c26129e2f4cdd4da3198";
                sig_s = "36868ad62feae1c62dc557b6517fe1e5b4510976bf26306afa3d95a4dff52fed0569e7773a8bf313c9e98981901fdc2654daecf225d3558c5b2ec1af348a978b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363133373734323935"_hex;
                sig_r = "42f5dee83215e7d426355fc1d349ff9fb3590a0dc0062afe829396bbe697788b70b5bc599811591dfa5f4fb295b543b16a86a76eb86019f4acdda1daa2b1e0d4";
                sig_s = "57b4bc551e01f1d5c22e60bbd653218879e06cdf9e857ac541beddd416b1cd7b492e162495aa93c65f3bf92a77c9e6525f1567ca72d5fd161c7c36dd3b5ec176";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383733363733343931"_hex;
                sig_r = "1423de24b2a7fa75474fb5eb174701f3b08b986cd83e08beba885745eba82775404a2fe230c9ab85d7c6aeefca65d0cf80c89dad47c521c19cb19a5eec400237";
                sig_s = "9a8b969db7c8d0e66c93fd8f3b809bcf09a2afb1f11b48f0d498e62fa92fc86ef121226c953561898de67d51f8507731602b30ea6f164467c5c37d67981dd553";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34333535313036343035"_hex;
                sig_r = "4c3dcdbc5f9972986c4aa842be234ae7ab9793445937f2192de60eb909d7540dcbc289b9251bd35828c2cd8a765c5df8afff813db43871bbc5c1d4846a147257";
                sig_s = "7887055add325c29a1db3b258c0b8bbb3cac125c201ac0318fab499206b885d64353ab8179581aa6a901e1c42ac8ed6b34dd7d947033560f6cede9549ee08c59";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34353339353735383736"_hex;
                sig_r = "711729545a60fee17a795dc047a3b6b0755a804ee4b444e57e368c19d5477b1a9b57b241fe66b51d6b9d7499124a66d5f09c78905cfb742ba30ccaed29e4d80e";
                sig_s = "78b5ec11259d715c91febc2edf5d12c5062bc7f1e282ce6c40193fa93ab88bb71f837c45b9dd63298169e4ca77e8af9b10ca2e33dc3ff4140be90ce73b2efbe9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383933363633323031"_hex;
                sig_r = "4393f2368994ddf6d40f2030a31b17ecfc4636249288867b1df09f86da0555128fde2e5fb62a3473b686f90689056e10cc707f0a8af0a4db0cd92c1f9c934599";
                sig_s = "2484e7017105a177cc864a0fa6852ce361a8564265c46de8f5f114b9cd4e27cebf9aaefce44f29b111107e1724a35344a476ea6855bdafff2fe4c0a08edd51f1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383036303638303338"_hex;
                sig_r = "697464e7bdec15d4a51d463998c44cb876feac1658006e0728218a4a96b8df74f2e4575546c76f0563735a84a26b88d53bc1304244f70205406eef42c1547d0b";
                sig_s = "131d28825c45f6e84bc3a4f944d57512d187af058d22169ab9feea9f7cf37fd332a132bffacc496e0ec293ae95f944c6f311dc39be22e70de002c371545db133";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323332383137343937"_hex;
                sig_r = "4f102958c48d32805c03459f4350089aba9525e721d2a6e182c6fae709e263f1480a62baa82cc3a1f26f733ad1c3d8662c4245f49d70b1ee29ceb283440694ae";
                sig_s = "53de14ecd131d0226993dd09b0daa6759a9ff38a584c1f03d0aa7c3f62187cdcd18cd24fb8bb52709c6e85c850c04bebc63ec4f729a42a344f8a19dbc261ae38";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303734333232353538"_hex;
                sig_r = "6b8c7245933682bfacb7469a4aee6e8672915fe0e50489e9417dc4e937a67d8b49cd6da38101b5c2dec81494bb8df74cb43345144552794aa975776b0820aec4";
                sig_s = "039b894036546b9c0ebc6483dc2a15b648adebc8187888fd0478cfb626bbd35973403607c7c3a8687bc80faf6e4e269e4fb66d9542a4228121305ed673045ca6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363130363735383237"_hex;
                sig_r = "3c72f66f702987c3160b83b119e1b03ceacfaa800e76eec2c1c0de0461dd662863f533ba13277b5bf6572fb20e3310af04f303dc58f5cf5d4d366a171785a226";
                sig_s = "90101e8f6c5f04fa69751622f09ecb453d6c77d6a3f48057fb01654453a3173768360103067e5609b3aa976dd1e81191fb6218726a397f45a824ed9e32d7457e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3137343138373339323133"_hex;
                sig_r = "0aa50ed2216248d21a03bfd9f5ebd39e7b00bf628ae4e0ece361e322f6fab02a7faae7a06188535914932fe570e114dc90567b687e39eb7ec79b92b34567bbfb";
                sig_s = "5ceaf012eb60a5d6c99b381f14f15ed926574d8ffd3373aa30dbd7bc0f6034fec60966bd0a451c0272ba2a891fcd333f10a5aaf88f9af55f072777c260a5d7c5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35313237383432323837"_hex;
                sig_r = "33649f9c6bbade86585268e8392e4f0cf8fd52cb51a9b15ce5fa5d83e3bb68aa83d2d715ff73a30621c5253aedb6aac9ac446fd04faf5fdbb7c0ee9eec80c128";
                sig_s = "5a7bc3f5ceba177ee3176fbd7ea0aba42f44f3108ec48b3a7ca715cdb41e88c4ab38d33a98d46b8d291ac2746dd065c63db5268b69e9894bda797d5b0f828c7e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303338363930383739"_hex;
                sig_r = "31ed3b0831e299c63e18e272b6e7739f83affa911560a9c25ecb069dfa01d1846f9be452faf01eaab285f89bb0c152559c44da75cfe7994d9f30ca44ba964d9e";
                sig_s = "02b900005d29e41d69b93559591a0c745057f53127177ae9a092bdf71661ea04e5474b2ea0eed255bf8ddd3b80c40b59ee79128b15387a3ba84f6feb03085d88";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383737303432333937"_hex;
                sig_r = "3ad7cc06c3f0a2a9221e75add5fa5ebbe28746cacb21ca744be3924e5bd94fda75bd1a3768063738a55564f70a35d8386e4db71d63c47a240046cb9858f2abeb";
                sig_s = "997dde151505519f7fb33b234b6c4d24011c84c4c72d0ca54e6c2ae7e54c2797df8c3d318444f607fd0b9ef2721fe37d9223330cccf910a090836de0eac1feae";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333231373038313738"_hex;
                sig_r = "071f1358c5d58cab0a6732d681d63495679aad04a662ed82ec44d62bb48d4781217d570fff00908dbce8aec0d5f595999ffa8419af470b56303bcbc4bdbf3a4f";
                sig_s = "2b06d900b16bcda3094217ae455cda6fc68aa9deee9adb389817aa2f8f9a90be35991bfbb0fc08eeb0ff3b55a5bb05ae82c68e57e29109d6d9c23f0e7c61b00d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37363637303434323730"_hex;
                sig_r = "5d7bc4cf2f4b9bc4031470eccad3b8e16d57bccf22dd613b135e9e1becb9e1326200196c6bdd96807a16d451c46b4f4a7a5f1f011d3ba18c91d3100d18c58f0b";
                sig_s = "41e27ac0793a27e46ec597157521b52c24948dc16a670450a7f7ac657f36012c539e11fc79ccd04b270eb274f51741cc0d42f686801acf89dd7acd35322f8d74";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313034373435303432"_hex;
                sig_r = "a33b9ea0acbf392e5626aa6cb7be147b1a70b66dc7579de7b4700395e1ab43059cb1002aeeb7ebb558037cc72443f33c98c33eb1b1ba209e1f46ba9b9d97c596";
                sig_s = "908e62c1e27b0ec685209d4e3a92055c37133a19af496dc162357174c030b3f5a8081d31621e7ad17deb7d57efc95cef0b6d27017ace11e94cad00afe92cb1ba";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313533383730313534"_hex;
                sig_r = "0f390233f19df19f75c0adc8daeb8f45c3b040111eb74e0b09c077877803f64d556b1e0d37708e288677900e54b8120fd98bd966c9225679b7d3f66c38803338";
                sig_s = "928675b66a532d5f73ea9e9f3633c6c4f8f510c175a7889460d2bfdaa0d5479eff306044a32777d684750c83f5d9b9855589c9d56b82910db6445f424e0bd0e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323631333835303439"_hex;
                sig_r = "259e802c033de3db978e920c53b05cbcb9ede5a06d4df635fe0084ef72391692ab59bea2b9c451206df0a4cda921de1d04e8d65cf8cf47963ca797c80f5c3007";
                sig_s = "73b4b437c47a4902d449a52dd6f994477d19a20f1356effbfd5d0f1bb077f6c13eb47ce9274a58b34f760c0e35774f70f66c5753838ccf8b0d8413b0afd3d562";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353538373437363632"_hex;
                sig_r = "9b2e41d7c510ca0cec4b6e4f9198ef049f76ae2391e4b32e1777f12055fe1de7073afbbceee7c38d32492b01b2d8aadb298988bd57a573b1d924888dde9e76eb";
                sig_s = "8ada489f25864c205218194c5e5f36916f3b7178183e154a3d8ec651f219e7c333f526184a73696faa69b3a1fa726874a8623435c9c8c50862ae14d49fdcde59";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343939333634313832"_hex;
                sig_r = "1c9ea493bc021cb92cdfbca8b41353c70ccef8dd7c59d0ca38dcaf92d59aad4bcc4d851bacd8efe03e948f51f41ded9f4a728b5205de6eaa82d2a0e13fa8fc39";
                sig_s = "01c873d4aed3b574f5eeec39c16edd14226ea7a303b7d9bae24a5e13b58e27fe7f67b500b15437d37566c2b7e9468f60baf02b19ac4bfb9d5b5bb1dc0612497a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333639323733393835"_hex;
                sig_r = "49f3d76bbfc43b6ec24bb54f13ad477820ced9d2681f59ad2f50cf0e901aac9788300fd2324303b5d432a6eb57e3aeed96c68332571f83fedbd0edfb5da8f092";
                sig_s = "40e04951d68241d5cb73c1ebe9373d01232613c421de6961c92a7fd41ebd9a6a4798bc9a9ffb70c57f81eb4f9c1ff3f336020fb84a529e096257775ca36e31d1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343933383339353635"_hex;
                sig_r = "a6a0fe70d503a0c9a2b7e466471205e76faa4e1387475b0dca056d84e5d8564ee4f533754ab1465b458ac156487894ae34f68e93eb70e8a80bc81859003a054a";
                sig_s = "39229289b5ef627260306a06cd53ab63f2fec2e7eb0724f5b312e3201d83274ca69282ed8391cae0561074952681754165a3a919ed0b1130e93f1ef80d83052f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353334333739393337"_hex;
                sig_r = "68e00a1828309d5abcf4d433fbeabe38346e9859360fc1ffb07cf92f72369750673425de56bbc5ec9bd394d0f826cae051c724c6e9170ed0e1fbd9460fcbe3b9";
                sig_s = "016564c09e979ec09814dd9d90cd5c13612c8227c1aff12137e090da41d562c4296139769e29193a2a667fc0de95ad933f953979a6293510376ee9b53947e6a4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383334383031353938"_hex;
                sig_r = "1c46fb86c1dbb53d2ad4f1b7cb1df8590b822ab0f04b2199481ad09b4025f8f5df433a370fe186885abd55327930432fe0db49ee4817a1596f405060ad2e010c";
                sig_s = "8498f297efa036dff7816d5a57873a381fb4056f440328775356e4a77d472e8cab84ef113e4091f61dfd2d76c9c168296ef8462412cfe5d2a7cc83f6b5b000ef";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343131303537343836"_hex;
                sig_r = "221897c0b6f413236bc039209cda3e8e1d1b33d72cabce5e7b38b515705b91cd4d16c16653889bc07b2374a3011d61246fb5c123c6068aaeab5c3e851471d745";
                sig_s = "89a74e94702c0235e39a60a106e0703d58db95f0f0fa5c7376c4dc9f85f5a6837e3371d7815e057e297f74950c7b073cc4bd15b4eaf5428af99f3805b4e080db";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373836343638363335"_hex;
                sig_r = "a9aa42718d6491365c1c533e87501debfec3a139fd96f0986f8b76915df7996d83a06311e899519db64b032d989601cba8cfb1afe7bcb65895299b67f2ec8163";
                sig_s = "48eb1328388afda742e5da8ef86e52489c2483d3f1803cae4110f1f0c2f0a1438138d8c174a6a503af626f5e389cd0b6d477829115338cd5a72063de295c2c0d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303534373733373638"_hex;
                sig_r = "aaac0e6f13c2690275b06a11cf9181de50a262a343fea94db5caf693624e95b015c13bd2c4604bc1143538c063c2ba0cc09da764433c5f65e6f7f6d35a29bc42";
                sig_s = "0a5e64034848e86cc360f2c036dbe6f3e2445b488e7288cd03400cb51b0819e42aa3e50fbedf149d975723255cc2f3c819fde8387656e1c0d5e03817ea74026b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393237303137373338"_hex;
                sig_r = "3c96b46e7f61415e992b642e601f06aff778e7ff0acc196f967f8432036cdb34e4d1eec1a195448a60d4f331fb1850f83b597a3d22551d1327d57eea4b5a725e";
                sig_s = "a819d0c8b2537762be4eeec1d34d51af4e04e35933a87eb8584a189774135d216a99d32c53c0218c273afc8bb91ba4f7b2c64177fb38f05b2285f6be0e21a8fd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303531333235363334"_hex;
                sig_r = "3ae326ab21773a92bbdede99eb07cfe23d8fb1c5ef22ed281b3de504e86e084ef09212f7bdadc28ca45566d2b22b5359b404d49495d03dab14d87949bcee46fe";
                sig_s = "8e8fd0bb62f8b9834e714db306fecf14d7029bb2a9793786d144ec53960f4a653fc0b917693f69737213f31c5eca194465c68b1531bf662d34ee2b1152422f7d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303139383636363832"_hex;
                sig_r = "6f267dd8ee31eaf9ccb9cef5e7ca5556ca41d057b28e668ed25e265163c21a7d2a3bb2812b73c085c00881c04c91e6c072be8302922c0d2a23eba50b8c6055b9";
                sig_s = "9052a0af6159b11715ecf901a6684be3e5f21e797c97fa66982c7402869c05393278ee4558ba0c66c699234fb675a88a7965a18bb5afa6950fd44b6232cde80b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130343530323537333530"_hex;
                sig_r = "4ecb0a5c194ff50b1d4b69a7a645a60271e1adc8d686989162686fb18de0396409478fe6a848156d0c31272c833f2685396a5079352765306e3ddf15996382a7";
                sig_s = "6751ee84f6f7b4b5707d23bf0152e5b6ffb1720d29e55539504d7d90b13616e4874bf234840276a945639f4bda6a552f552654afc54760fa0a9f399be54441eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333236393538353830"_hex;
                sig_r = "1ea0614c7fbc25815fb6233a7ef5775cb879bb6f61684443e5ab498656440a7df1d3d61118be2d1a38aecfe6074d66c2307c7c4cdf198273a8db1e5e9f5fb648";
                sig_s = "078ecea82a430eee83b0757bb5ed65906de2c649b64cc64c4520484ccc7ede13ed12b57fef6576e872441511f18b000cab52ee44eb931aaa76f9b8e293225990";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303734363533323431"_hex;
                sig_r = "991c3902006721918ac93247b1df2bcb9eac4a709c62df6d9fb47e04f47d3efefa4a1ebd628baf257963379522271eba69c3b57abab1add6221020e5d6554d92";
                sig_s = "104fb2ff081ac705615617c8808c59b7fcf8e7e50478a3dda2e4dd7a7eabac027ac95ffe3dccb26268d6deaf0e63cb4e2e21914eaf027040d5d38a4ef636a60d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373134363833343830"_hex;
                sig_r = "1704da5236cea16d8d71e654c46ee1a7305353edcf50f2747c38688149bbfb6eaac20032bc7ce8f89e06b41be5f3f896fc718b7dd9375063eff4393d2dad2fd1";
                sig_s = "426d4c908e3dac55b1b1db5a78e87cd467a53856abbf3f97000f69f106966ed24667b0cc09abfd7d79386a70f63a9b187a543ee68d8a5def7c2f79afcecaadc7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373933333831333230"_hex;
                sig_r = "7b69fff374f1028804d430c5667df5d154ccf6db0d1ca0a43bc07f274f0f2c2a37eff61cb99ec918d9656463c6e519cbbf75c3cbde5105a8a025d853152e7ef3";
                sig_s = "4142e98c6bb45a786db4edc5dc36a28cac4f4074644bac6a39bc54ffac87f779ec23b566dd349bc24a6924db6e7411dace54349dfc12973303cbd0679782e5f6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34383830363235353636"_hex;
                sig_r = "9f812984090ef818fe92406009ed483d98e74c67865ea549f220992f6a1537c59d806d9e8c510b6e80d35cfc005c3637b3649fe4ba0d60717c3e10617067df75";
                sig_s = "47c425895cbe2bd638a7e12742f7436adb0ea1c8e23622341c1f31186b6501af7cf794105ecb49469c78da58f0f1b4b2b257d6f6db649fec89bb44d6394edfc4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3439343337363438383537"_hex;
                sig_r = "3e06912e9e08d150cb4c528f351889efe2213d9b26b33fa399da60592fc357daea73405265a68a17ca25dbae3fb40501a99d8d5185f6d388f1e1ecda8b6b7cbd";
                sig_s = "8bb2c7a8f3d6b2ac9b923ebec1095d6f1768ddae6371fd29240892517287bf1fdf195220297e6d63fbe725bd655a4092b0a6e05750604e637d9b3279b648c97f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373038363839373836"_hex;
                sig_r = "5add361ac75b46b2fb77d8c027be1e6292b0e344a900270a53114487ae96e5d1783f55c8ea2773f6c8104a1899b0c8a4a6a6f0a21dd835d28af5f5602bc656a4";
                sig_s = "41aae6d2318a156f0e923aa569aa5fd744133069ceff39f49ba67cf0dea7ee594d3b02a4a6cf92b817d1eb682c18bf5edfaf2c7d383607458de33358218932fa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303239383732393531"_hex;
                sig_r = "8b5c49176c301683c590435ff5a66fda99544c3047aca25653fc50f3f2b01147d8b4169334cb1f8fab3fdcd02434b75507d52b4bf807d9978b48bba11ac562a0";
                sig_s = "47e4f24e671876468847fe1e5ded1adf3194d2cd7fb4915b77ada7062454c0505af6c8558cdc6cc578f10cb7e084eab8c68b65133f0ad4cbe33b2dbc684137eb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303137313930333835"_hex;
                sig_r = "08389bb3a37f6158449ddcff6daf46d9753a7e16d4460bdeb229606d0c70bb3985ddd2b3bc867553b957ae8f346a8e0d4665748eb04f2a325bb7b49e71d8a70b";
                sig_s = "2178a553c82fd84a556828a5a35f9c2ce4b6cb1ad38f8a0d362e16b80830dc320a04748b151d748e7c4670e44f4db290ccc95cc4c9098944128513b77c2be5b4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393536333633393339"_hex;
                sig_r = "41d006969dc0c85187b2b1b6e127adb40662121b4899b51f5942b702f994009bcaddb90b9a848ba40b06ea32f7ec2ac49627804d2b67c90d6ca569eee03be432";
                sig_s = "5f7daf99c264e8a12cadab73bdb7b01cc838be96f073daa1ad044d21b20da65f028ee65903ad8e521fb120164636212d205f30be488075a6cab0be50c936dcb4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333030373634333530"_hex;
                sig_r = "3e07ee970d8466a23d3132800fb7134dfd896a3b96749abcd6f07c23a61f871fc7b1cbf94d442f15dd164fe9b8403536d8bbc4fdcc71836c4053d8e21b38e788";
                sig_s = "1b9c3b6d5d7b5e9023c1768f91818cfefbc11ba6e1bb9f8758d22427aeeb04188f5bbb41beb625ead1628d30def6f23ea1ddd09885ae6cc2e4e6d06d21b40f2f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393334363634383434"_hex;
                sig_r = "3fb13f969dda8f26c109eb64ac4ad888654dae726de4bc3a07e73b7a3a73b4305d6b0adfb8305db07d3060518ea26d5b41788fef4e1d45a1244629a8989a78b0";
                sig_s = "5b15d726cb4d5ca3aec41116fdb6f376ea1469efac865b4255922f7df2a642048458207cd374b804829de014a5ceb37a814a770f188b15fad32c5b4ac4c3f6cc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3335353435303535393632"_hex;
                sig_r = "7b19281caf8a1eb559409652648fb93ee7b3f504ad963ace9b9b2bc72e456bd88b56935020f3e80e0cff3e4c4a8aca647d21794579a9fb10ec5160b4a44a91e0";
                sig_s = "0983be13a752043e3fa8de11af2adc822f5264570dce9b1c7bd8d1922cf8c0b0c0923cae4d2c1edb2b360484b1838db6a74461f41bc8d8b3d4f974c076f203d4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333031373232313038"_hex;
                sig_r = "925ebc4d18aa8ac199bd98905d369781e5481d82da26c83c2556aa0c1dd56646d628518aa08bc5cdf0d44de09371ccde920e9fec19170c91b9ba6257f5376648";
                sig_s = "89c444144990a830025965c64f711db2e10c650c5c09d7ec8f1932b0ea984daf3592cfc568ebd511446d53c93daf6483af6775265b35884c6f5d23eaf038d40a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363137363931363932"_hex;
                sig_r = "67cb23656f0ffdd0008bc69984e6aebb2d33d98f13c6745492559d420e51dcf516e368a43751be8b4cc9ca24f69969dff8b1f340954bfc350846791ef6cdb131";
                sig_s = "2253a72365c3c31d0fe7d5935ebd16014dc67b6c1edd6a5650f60ac150709f1b7495b3012e490a8b3a8285d0348e563b6ccb8978152d18d7b421f0ebccdd49bf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33353831393332353334"_hex;
                sig_r = "47c73085f8761b44bff7ef6537aa61d838a71147c2335efa44c2895a3559056e30080c280be059be54ed25fa5675cbdacc657f86ba0399f37812fc039fdcc260";
                sig_s = "0b195ff29310607fa423ef63086c9a4a3e8f0ada29b9395db99a997dfd7203513993e13df10a02bfb9274651d95a4937f5cf85df252af2f3ed261851a023962d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3135373136363738373434"_hex;
                sig_r = "79ed877afa1dd09ac2381513278c0aae49441fd37a2ac61798ea563d8ff676844b4b1b3a85687f0ab2f5df604b8ba0d560de79b94178370532e17c93843c666f";
                sig_s = "370caafae78c97d5b9854e0b21a88bb4bedec86be8e293e2f39239e8e0c06c02524f8732ff4a3ff1f180c6e33f507636342649a1bf14f1f8ee2e712a57a89129";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313939373833333630"_hex;
                sig_r = "5872398adad292594e5e749c8a90143971c0d648a900c7e247924e1d01cf2b5908517e8c5b7fd508baebe2647a48c0702c2804a9f436307b9cd00a916276fab8";
                sig_s = "2b9f56244a8a3e6c6e03f6f740f3a1f8c4a194f07ac95f59dd68196a547ee00f2e91452e869aef9eb656f17c28f9c29b6e7297b46b7fe38067a14f3beed83468";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373430343735303832"_hex;
                sig_r = "122bddf0421aa327a9016724fe93a52d818b3bfb4898832fa6c048e2652c24c31fa179f6205a726799e475253bbdda17f538a4069f4de789ce70635074f32e0b";
                sig_s = "2cc5f68f5be6e0939556ce02bda6719c1cc75294fff5c0a3d31d85b495d2471ff88a715c5b335128faabfc1590c2b7a5bd865703349d9df9dd154aeda12d65e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343137343336353339"_hex;
                sig_r = "87c3c301d8e8dd07f8e560ca40763931e9518be8f45bba3fa100de58d3dbf31d813520f7e6e2b7562086c9f1668bbafcc2a039eb0800a7d6e39e2c917e87cfc1";
                sig_s = "38bd9c0c778899833f933a739829da50ec8fc95e69e37b87c595eb9066dfcd5cd163fd19a971bfa0f47c8ceee11c8b239e4ff532620dc806c85a884fc3172355";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323335363538383839"_hex;
                sig_r = "73509ef73de8f3acac4e8d019e6a4533e4ff024ba9f17c3972452342ffc7d0e479ab591466df9f2be22acb5ff9ff78a6fb2aadd8f3784fc13bcee62199cb6e56";
                sig_s = "4c9a60583eaf84841df61b8239088f65776a0a9cddae783f2436722a0e6f130a8dfefd0ff9fa7f367c3f1165da40662070c1d17355a6adf671e6fd9c567a200a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343239323535343034"_hex;
                sig_r = "110a23df6e8eeb3862d0c6e62ec518557617357ab8da7f8c9562ca31f6142f8f4385dc1ee777c4247ac6324df64063ef6e7b78da1d678b308e8bc4102e02c69c";
                sig_s = "4c5bca78a31ab9c348857e4c5f4f72038bcb54bfb8c37da8a5a13843659d367f6587d8bb8cd6302096804d2216f25c74eb63f2a10d90128973e8c5d607ffaa0a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3531383033303235343636"_hex;
                sig_r = "19347da02c5745304af47cfc7613deb48a00126fbb3adaacefd58028ed07593e6344b706fe2e31224e1312bfa63c51d707cff11e53a143d6ac5436cc8d445845";
                sig_s = "635e7bab82e221872d8cfc4bb2879015ecc09d64a9899759887baffdaef6291fa5af76564479910863a924f540ead7abc29ecb97e667584febe0b686eecda4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343736333938323030"_hex;
                sig_r = "92663d7cd343448a9e019df35e9632d00406d0b9cb86ba03136154ff0bbcdc7280d4edf361629ad00e9f78b0c6c5a2732f64e909556f97b15746978cf4c81bba";
                sig_s = "95c6f8cdc5e2020e113750fc2794255b2c74fe404b9f543f8b3fd96b465f7bcc6964a16fa1584bf03f779b479ca3bda8e3b5d0ef6eda380ee78bcce5a6cb0d73";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39303630303335323132"_hex;
                sig_r = "59dfbd5e8d199d331d232b76fcbf4796dcab19cfe9ed9527e5637e9fa0bc3096814a32ec4507315876f0e317e3ec8b8fd79dab7914a0b1d84f214b820230d983";
                sig_s = "9059c19e13d6f532d221a422edee2619ec6e2f140e210a8aa0b10927ca37db944f3cf79e3bc98d4b88f332a22151b9c95619fd923e54264ffa0ae6c4fb6d7343";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373536303533303938"_hex;
                sig_r = "a102e38d4c7cb15c582a512c56ec2ce4e4ba49b2682080865ff831621dbbd2bdcc9e1f3891bcfa9a08816bb2fc78d55a161a39a2c9be559e0c54088763f73d82";
                sig_s = "192672c0825a7d492c217547cbf4e02bb784911ba2115868011e0c46e6127f45b1a17f1a6076c496a99c5b3ed269d46fb02a8124600b8ae68f11c0fb4acc337f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34393830383630303338"_hex;
                sig_r = "67646900e6061f8808ecb259f561f85a6fd24c0d3f6f7add2c4e535fe72fb9909d1845c3d36e4b7865fe0376cf877bcfcbea58cd775c73561ef00fcfd96f6dea";
                sig_s = "35bdb8e915cb601489f0002d25f967b0cf5b5adf9cba8c16ae877a35da85bf393f0324bf78c0d16a08d9bcef35d84048fea66660160a985bf866d770a7010171";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33363231383735333335"_hex;
                sig_r = "35932a4f6dc2891f492c54de54a5462d861dfa09388bb10f0cbcfb231a47c722a80c77045491dbd8cbf2e2870938f5cfd44c56b92fb862b17e7972fc94efb40a";
                sig_s = "79cb49b84ad5be859f019aa803c15c9a14a63d549cce14a37e4ceb1d4f7f1cda9f8ed09b5bcaec4d96ffc76390092e62e443db6b7282fe4efb823a4ae0442e9a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36363433333334373231"_hex;
                sig_r = "4e585880bb6517f01520c08e76ac3c389db6140e03fef64ca1703f56866bdbee1bbddc7a810d9de3d1af1d60fd099baa1804abd13d3269b19c03c8f042ab64ab";
                sig_s = "89b5bf23f8bd4a0fbc02c49107d39c5da26d933b94b2b402da9b2dd635823612efdf4ba3daab725a25b7d64b64774d287badcbb91203a26dc1ed016981be70a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343534393432373832"_hex;
                sig_r = "1b488f1af30766ed1b950fe9fe438d94d912b705aa7653185507fa22cd984769b9e340b47495621ed7f14bb222a5ab4f058078ed455915e42202096bbee6719b";
                sig_s = "a53d35fdab6cdde5423ceee7442cdb33a81e9df85b97e19145c5c86cac7287c4cce52e2fb47dc26e8648a4206f6348d864abc07332849e1a69d3a157d7d0c21f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3230313834343032"_hex;
                sig_r = "162e53404c99e7b99b139f7ca09424803b918cb7540fa7b2c30875199a978cdaee9a165e31776f720f36c7a70eef6f956fd1a7b715eb136bb7def6afc0c62571";
                sig_s = "4e37328eb243f4354469afa7dd2efbff3af39074b366ce766e61f698fcf26a33d26bb240c865c321dce6207e0916fb16a35484737e8dfbd9b3a3df83503a3244";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3538313332313733"_hex;
                sig_r = "71704d8ddf91aa58bed5446fb1c540248b980bb846f71f4f3f3521a49ff9fc77a09a2984e519692a1de00fd59a4e966c49c5a94ce7d884a41ed98f81b9cc0741";
                sig_s = "2007f502697ed732e3ca751f2794b046d55189e238f92fa639b7c09d5bc5c78f1ad07e8c70045e8e25b963ceab3c6041e5846f1e08a2a63a2c1757db0c06894f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31313833383631383131"_hex;
                sig_r = "a14b98c3d29abc78a619e937c720436c5fc74fbdbe4a5b9fda848d809c73a2a1893be5a69f6ec25b820299ee072113ed3764b57ed60f590b594bf5f73449621c";
                sig_s = "0c38969e7b6e96fcef416491b66d9b0264fb264a2f043e16a0226062d2ce25b25c5d80c4cd02460f826caaebb5c2bf5b8320f3a133edaa97a08b0952648343ad";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393232363032393036"_hex;
                sig_r = "4c4defbd1293035c96ecbf4a6dd554c4869dd7890b3d76efb63d14330e5f2fcb40b8e9be83580b78e40b6fde3ec4cede3c7d8b6d2841ae7b7e65ed2828fdcfae";
                sig_s = "a5b7e18bc8f9f94d77cac1f6d1dc9983be56b1e7d6aa885a1a0ecd039711ec7e1c7ecf1d6d390c49b3394744dccffd755e3f8aca0303bca2855442021aaba648";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393735313433323037"_hex;
                sig_r = "0200aec7d8b87fd66b236c1fdeb22d87c467c8848c13b5d3de5a5471f6418b9551496db6f3256d538b54e30a32b61f0203f434a5438b5bfb64dea4e78eaa78d8";
                sig_s = "27b8bf396047472550a06672e898c2774ead277f8086c8db97a936882087f7a523b55a52029c164619ca55494506a6d5f6d8777bb01cc9340da64ce24af07d5b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333135313136333833"_hex;
                sig_r = "1defd83e9be1ce72f4cd3cb566e8430bdf75d43de90d380ea01b6f531d570bf9843e34a7678170d7eb334634ce32fd6e7dcfe2cfee91c4dd50739d1ffc68d2fb";
                sig_s = "16890f9c3b4855f28fd103c6a1a7aee24f4fb9bf423e9316ae6b84cdf83650e64ed2c1351551149538c4f9c2ccf35ea5e6ae5a8df75e5575e6f0ff8b0d45127e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333236333136383132"_hex;
                sig_r = "4e3f1e9dd66378597808d03daa3979f7c3040ea6f5e8a25d400cd7af60d0886bca30094761f737b0e0685672642552939dd1476db7b2c00fcefd5d2263a999c5";
                sig_s = "9c07c7e2582d880e4a70e983c0bce74362051aa1b00838fcd3af95405f648039ded05a1a7e1509ce225f0b2e32d7e08d02a3b4743fecdaed0664e1b3515339dc";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34303239363837313336"_hex;
                sig_r = "8eb49909880db8cbcf26a3c669e1c643217736a14b13b1cacbbcbc2c2695d5e3148fb57b3b212aa71a5611b8a4a66a2f5a615666eee48955a359679e142a65ec";
                sig_s = "0d53fd6be4ed3d925f83c74b9ed28ebd1f2c8ffc2990b36c2203f92efa39882c1ed6e3c9fdad2cec4ce872d50abe22c4f87c8e4dd660e9c36d2f106a17c9d8b2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36333230383831313931"_hex;
                sig_r = "9e9e08b0c45891b3e3ee0b8b658c93bcc10ec8c48f79230c95076b272d184364d14e0e493d47d0a76f7fd4b90d666d954f442a33fa644019270f3d7bc1a2fb62";
                sig_s = "0c0973596b90e186765b1fd8cb8dbb425e7df694449c01b0d7e81ee5fdc713a1c25dee1bbca37358debf8df5994c8d17a074b53007c35abd640eeef363f579f9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35323235333930373830"_hex;
                sig_r = "0f7c6749c2e7af5228507638ffa97bc92a9bab2f5795df309002245f3374499f21aa8ea67d023ac3ab866bf755f2340f434ed9f36e2bb56c379b4cae81a9d13f";
                sig_s = "619061ffeb95a0a9a0a91672a1d11342eea50ce6f671d2265cd3aed241c67198977448eb1d637fa4f43c57b87e9b94d4333b3432b95106baa3327e839a37ecac";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333439333933363934"_hex;
                sig_r = "5a3eecda5efc81c1b5c7c6210f8a832285e80df795b3296b0339b8b7a18dece0567fd10b061fde2cfe154ab27bb7ec788eb9eec02a8c329fa369c178d7305135";
                sig_s = "5bfb901ee7124e3bc0595c85860df76306790c2772499156942a1e303d055b760a6e0e0d770a46335c844c37a63189e49f79970e29e7458ca7409d5966a57381";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130333937393630373631"_hex;
                sig_r = "a2a416d5881c8368547184e6721687d6ee69433d4e40293eafc517fba3a5493d32ce500cb6d897ea47eb8261f022ab9614b0ca913f818d880c5f8047136444a4";
                sig_s = "a4e9b0baef4a3f290a1e85f0bdad9abf2a5ad2276d311745a15b0a7426cb5945801d911726effdafba7605ce0048a8f23d7ef16fd95712144f7d24ceae2e0bb9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7c3c4f31ba418f1eff00d64e1644467ecce8c01123b4202bfe27d008285d35a7052704fd7e2e39aa6c3745512e3a78543a23a1ddb416d6d4b3a02b6b4cb85d80", "69e6232d7de205e47b29b967be3508c7199f78191f8cf289af61ad00410aa694f1d291cf0f86ce52794ea814c9195cdeec744c0d48d97993bb4736b79cb6ce9a" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "01280f3ebf4f1d42296d47401166f7709f0ad02bae2524eba77322c9d3bb914889";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90066";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f2";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90066";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4e3f0eaabfad60ffaa8b9e1864e8af296a3d415f0bb7d18c3cfea5e605b86990b970f8488d37c08844dffadd4d1db721a38f3302db06e345a07a6c7329fa62da", "0171eb90881d70b136a6ca03392b27df6f8dd2ee2cd1ebe7cffa9f3b1088df4edc1210400837b12160b56b6c9519dabd747750b1103ee3a6a7b263941fa7896a" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90065";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90064";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "349ba105dc50907a6c37534ccc9edab46376ed1843b5f666a56fb57ee1bbc123f69461e3e765b4d87f32e8f98a2d551d09c88db48b3eb53f5695c7aaefa5f66f", "5beab7a524adf349907926211853359e03ab05a646824de19f5e62df7b48ae0c1b514a5fb7e1fecdcd036dde0faa2535fd697e0e719e363306f64d42f249b745" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "4338ed95ac0d09c51d7044d59f1bc26f8f3f11fc7bf2f81bdf0b21b5c0b9c89bea3cc6dd8b3692c8310b98117b508d130073e74b02b3ba482fb0a5ef1036a3fd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "48f989b8f80bc1ce74cbeeab0841c5bce3f0eb5b2feffa315ef54219c13e7ef71c22a8412637b8656412251663d219e44a5408fe9c67de990acb78e1f5d7ee5e", "6124fc5eb3294b2e7df1dc5d782b8d32abd9eea95960bf0ae1c7ffc69dfb7b43114cbdd53faf3fa6c7ee94985ff8850ed8b5d97032f244e7b7ef0a93fb96b2e6" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "39c982e2a4f560c509055888f60317e6b5bb61d594d7bd4f5897396bf3e81a09cf703d319f9b4a092d46d5f202ff5ddb776c57e8ede8454def7037b541c97436";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8a4332448ab5412acd653dfe8ee86f62aef84e35ba943c10fbd48b5f742e967e6f87c3368fafc98b91c9666325beea447e3e183663c120357bcc7995872692b", "2eb3bda980cc49dd43dee93c36207a1c5a4f175bb68894c8580309dd53c52be93f83d8773021cbcc3997bed9bea31d59cff289a2eccd91d77729088a576df68e" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2108b578e269291f18e0ad4ffbf46b5fb70180cff3f8f1379dac8e0c5975c2f39df6d2a171c2fb0e74f9d901238f24ae49d10701c2b74aa9eb962f828b0041be", "33fb21fe717a0cfe6383cf1fe8ff97364a6d7c9bb3818c53b2ddee281f426e75209f5a383b94270c5a1b048ed0261d05a1e9588444aa67f2a673e79662b082a4" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "68f0f8e122502dffbf6771bcb0591608588bfecea43dc1a58b261d30a8270ad9d499600fdbb70c952f677dbef8c2be99edf623e72e361494a9b2bc82e5af390a", "39891d25ad7ef71f2fc3a988e12a062ec4cb46cb1e531aa088c59e0d67f1288182dfb36827875e313bbe55928711be4973a6b5679d84534def18174e8de73a6b" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "03";
                bn_t sig_s = "04";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009fcd237d81896bd8420c064174be7a7deea1cfd721b41e488cbc5f7e32f51dc6d21b12843dbdf617f71d7cd6b40ba95321abc51b527327fd2ba3ab51a820061f", "5dfc710e4f441ae605d43727552e61911f931c476e1f8cdb98838e5af15050c8831c756033da9054b1e7f9080642f931065d37d92960127dabc2331e19efa41a" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "04";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "431b9ded11b338dd6d7e3e3fc88296a528c4e8d4a1ec1855a17a343dc5e8741c96cd38d1335b345cb1c1927c314c74e6eb8ffcdb81eed1773addbbb78cf41192", "797ac0a765da003f24c6918121a94cf1df015e85db3013d1c966d135ee9ec6d971e21c528bee4d933628d2af1e5b00463829304c2dae6de3bf0629026691ccee" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "04";
                bn_t sig_s = "03";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "42563536538029a5a081c170e02eaf83947fe2ea40faf05c3a23d93f9b98da5bffaca67ca826ca3617a0d5f2357c5f60b4afc2ef6b4c8b9039aabb70b0860244", "1903cd547bfcdd0396b07231511bd91e610ae6874a424d3b3a3cde32bc758f675105d8dd1bbf9546c62ef8fd0a113e76c0bb8b7880a4bd96b5f173d3e5628094" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "04";
                bn_t sig_s = "04";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008a709f6146e9de549c4d59133a453ccde6679bb6c6a291758db4ee83fc89f315ac32dcfc3ae77cb39287511aa831ddcf664f1577dcde4f12d2556b4f7698beeb", "1d8aabf91a21a9ee025ba85f3a89a41067f4b1d0e09dc1b7844c9721dac810bc4beec1c4d0258946a6437cdf99fc383bb352414e468289137805f7a6022332ab" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "04";
                bn_t sig_s = "05";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006d";
                sig_s = "05";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "715b337b1812fa6b5a3173f964ac70a06e302424367213595eeea9d64c2e9811bc8b40c8477c663a3d12bf59af7a9ce93982cd1d97f483c70568fdda61e512e6", "27a24ef8671ec0744adac64d255292b94e1e3f92bef51746ca3aeefe2e6845054cd9a55ba09f4288073982eb5fc15c4ee43062a5445bfb542d554812447f40c4" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "04";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829cbbd6f0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "16836b70746ba1c6d721e75d530828adada3886af4fb3c798a982752d1118aadcbeeea6a5c90279feb69baf6680ce9027321007fb1939533d2dd1e896085047e", "1288d237ec4ac4f3585dfd3776bcccfde8590f885656f163e020fc757bb5ffab942e3d3a616c4f70f8ab6fa8fea479af87c53619e5209aabc0f0e8141b870d2c" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "12d5e9125cc71fbeb86c217e09bd92b646c6dd3a1be1d6a6ed4d80267127e4b5b4bc4aac7d5d3aa0033114c85aac2a1bff3def001d248d0a5483dc2ea66f5ac1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "391646a800d428f10082788537ba86d9647ed70ce01ca4c09b5de354d6a943750dd6a26e2eeb0e31f6506ef6fdafd4b79cc0da7f56c5be05175e7e3174aa2795", "34d3826c56a357373935a261655859b1046c871d96aecf713f4b141b6bd12501b4d1cfd7272d41e80a9f10ac77489afdc3cdc777f2d7025108128e79e3192499" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "2d9b4d347952cc";
                bn_t sig_s = "76752ce289c38f22de7f75d0fa6da056f473c77194de931d97efd65421ff3ec82c57a6393a42702e14a2d831768865ab933281abf1bcf52a7ef6b73f2373c9ee";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "07ba599b5247925c0e5e15dc7c838202342587960050ab9d8d112571e6e711f3c1ba9f83d539cc686dac9b20b08a4321ee1d08ae63728ab2d409aefff0664344", "72fe2c52f57be9f02a0d22f1e94be05dce87c142d2f12967e6f9788076bb21dc22470c25c32a67fe9da038af50f40c8c4fd1f9d07618707e247820629d385d74" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "1033e67e37b32b445580bf4efd";
                bn_t sig_s = "9ce766006a5130005e79caddba04302708487a27823bd1d3d9ca0a801f4fbc0b83126aa1911ad44afd6a770c753d619fef707e7c773f467de5738b35333893cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a0eb47a9c20d71c61da673163ed0223a0e096b66f6763d7b42585656523a832e930d0be222f816f1da71ceace27b1d36ca7c249fea61a47e457ccddfd3f0965a", "68987433391a708a51b7c78d892cb0bc7e705343ac177d47399068abeb84dafb730a19bfe13f7e574daceb19332263654cf5fb4ce5770b46b7642dd8b0327216" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0100";
                bn_t sig_s = "029c0de2216bab72af9ec823411e7ee444482bc268ae1ba9064e04019609757d95b2e0c5a3fde377a87fcd38b32f8061bd3dc81cbbdb96ca626e6582ba61dc31";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "732aa5b5f14cbd50406f6982a1eb8cbabd0581260425d2cd969af633cb8560b6299c495ab6fa1dafeafe00689c12aabdacb963f36068cb3fa40ac35faea90e6b", "008ae1563457bfde7d84aaf4f084e7058bd085c6063e5b6b99aa599f3e6a11dc431c0f5485561d4a94dd852b102b4ff11fe2d02f6b6fa4b9807427ab495727d4d8" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "062522bbd3ecbe7c39e93e7c25";
                bn_t sig_s = "029c0de2216bab72af9ec823411e7ee444482bc268ae1ba9064e04019609757d95b2e0c5a3fde377a87fcd38b32f8061bd3dc81cbbdb96ca626e6582ba61dc31";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6ca94d867e1b94d0f30319dc9405106115c88af86d0d72dd9023b28c1ae76b69772c8302abef68064eb2c4789a6b5df92dcee1b34486b739d79dc8882a0d46ca", "1b96058d8e1cd1d3cf66ba127643ed4a47417ad6428d7288a04c02aa64930221b509ce4ab53d98161c95b0d761107301c78122c3b8cc2accc683aaba840229de" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca8ffe9";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "499a272982a1edbefaea51d0ecce321c2ca7474e27360b2d03b8a2c0269eb368b7363f99390e106e9a5eb1ff9c641286fb3d2cccb043b24cf3cff96520c816e4", "17ce9c494a47550d32b6e474aa0879c6b3cc2d32cdc122d1651d979e2675d894c8fcc2b55a0a5e3b12b17867deb2528152cafec20957355419b539d7c984f5f0" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "9c44febf31c3594e";
                bn_t sig_s = "839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "75ca0c0a729212101eef9cc65fed0cf69d0f7d37cacf824c9417c2cb771814b6d73130f7430466de398cc8b0c94f4e5d03b7124e0ca963f54bdeea0161e7b5eb", "75c61b3e7945df56aeecf4676a9f5c45e666101f95dd4a5aa7828da1824b18f64d1285a97cc6a3f3573387fd4933ef16284f0225e215d2c889491b92f33bca2e" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "09df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "32b4b24f4dbcad98a942be6e8467a5a5dcf9fd85a8e8f8437c542a3246d9eda2f8e49a777bcdaa7eb5ec899d120023db9105b17b4c5f0c21a9203e5adb794c13", "00976116e1d5bae1d444121504c15f45019d58a20ad30ae1e9a01ff68fc18dd4591dcd6b308623a492f68855692204452a70d54a46e64de0795342796969aa2e8c" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "8a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "84f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6d47c37b043570c2fea59820a1e2d0419494786296c8bd64984834684abeb9b56813fd621888591cbb8781d047e8316c5bf8290537a0afa20201993b55e8855a", "00962bced333bafe282dbdf34a58ae77a53c8d84b9a2c320d5561c234295726fb2702ff4864e0b7c9e801eda146f29b5f49bf896f4672818ab84dbf8214bef50fc" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "aa6eeb5823f7fa31b466bb473797f0d0314c0be2";
                bn_t sig_s = "e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0090e3ae71e1b2358fe478d0cb55b8e54b210af34ab028176b7797ab63e579b951d5f9a4e581c0f77971b7d9059a04a2cb03e7fc49913de3ba3a923c7d29455829", "2692ecfe7803347a9fe8d4eeca571f612607ec57964dd537c8239b77d2c74cc33ec7656a85a5000af9ce8b0083090dff7cb45095e99286072410feed32ea86ba" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "01";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                sig_s = "00";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0a12e44f907e383609d8be931c5f6035ed981a082551fb5def65fa6181e7c662ddfb7a5ada64659e07c5f600ce627681125610f815a54e5aec51f68a66e8d2dd", "693a63ec1662f9feca7febcb36debe96a4d287dab703ab7946dc88b235c941dddde87df28c13fc79788965b6b781ffe7803d228937716f8636f9102b1a74a99b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "0cc5750ba98b8e7fe373e57797c29f424322828b5dc9a2f78ef8150cdf0266254ce9967b1197bac6caafdabaf5eb81635809ddad42495d1fcb934cc443dc941f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "15ccb7ee9d1d18384ac0d7b707bdc8df6016e4401623a29f46648bce2482edfb52ae48d635e7d68edc28bba0301e1c422ccf8184d0010cae0cc1ff579d3f90e6", "252cbc1d76126f524c2837fe138747ae9cc55b887e51c0b92caebe0be60ca11b8139fb2d93ea49b7c6c3d9f3b12d5045aab4efac21b7fb24b9ff0aef59de85da" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "296bc6cef75ce87d064db7522f1a440b4df4a71e233cb176ad7b0514958b3cf97d3eb29930a87701e4ed00e96de9f0d5e4fc134995b44f08c4c30e667778865c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5ec8bcbc925020376b025fdd739d5e299d38bec3703f68e213c29a7039d6b4fcbaa8a3fa40e5c645b61b1c757ac2ead75b78b5a64a520a5a14cb1075fb4ed316", "4f0b4b4250cd82ec2a0f7427a2ada3036ba4889e58e2cf9b074c5f75d78a4279672e3a8ac27bb1c7c462590cfe1338712263392095a72bf75f2ec48aab7b15e9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "189799adf4d3362bc1ea2f7e331b2d80720506236ff2c692edf712dbd287712420afca0e56d43da8ae915767fd24836eb92730845ea132514d924daf2faa3139";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a128b6338e2802ff871139bcfad8b4f7fc20fe0a550cb42f7f32160fc8e6aa6200cea796497e8fe201a1b472d5d2e86eba2be0f5c73c06d29ff843817d69cd26", "3383dabdddf8cfc448b8b5ed8664b8b5b9ac08615b6b7b41564805e8f4145b35bff3bda870400f1a919249480c4b1236bab57cfb6646207b3ac944cd57a60cb9" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "392843478a101a81338d7d41071f557c9d4ec593a0698af9842c1cfb17ce21d7534a7c34c40217fe9271983a9f6304d906299055a791feea1c579ff1ca499b3d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3d7dabaaf4230212287cb854f8c95c12b86ba1aef6d44745e832709b54c333f10128a17f4989c36f41685ed329f229312e9a7fbc90fe35c87f0dd950b6d1170", "009bb32413f77bb23fb7fd2f5e9e51bafd7fb351c3e03ad1dbb30760de7eb3549593f027d7f1e116797a6f5f834b75da1fe70d995e6383a8442d18625de5dcadce" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "2887c685af0b7e900a0cf73e59ea4da1198f03f9d6bb8eab7419ab57913db4613af4f5a0fe2f56f2fe971a684051830cf86c1dc80811ccc9ac725847968dcc73";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6069fcc18df17fb063bab2e3e2ed1809da0b29cfc5c0a98f2154be0944a0c1adf8322ad0b8ff328f3ed72e02ac4c270517c135e57613110f1d4e58787b1e40f7", "164705c5af14057d78388f8d5e9ce90c6b08f34283e11af1dbed7eded88852b4a20082d2ae630ead02c5cd03c2836aabaee0a9f66c6a0f8f79b7c50bcd3cfcf6" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "4dbf43f5bd4ec65b0a2ed08d57a895af3f3256999cd1fa3590e01b525268a1d73a6d8e9b005f0dd1ba30696543e50ad6881e2ec16a90a3fb330799c0d33c309b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7df10fbd9bc07e3cbfa48ea84f1d774edafa270515dd51420ee755c6904f249b11fa05600c44139085fb625e4bfe786123ea598aaec7c74109b0e883e9820fe7", "197892d40e00a23ca5e317af480c3cc7ddaadb48a15981dce7ad3ec098fa03f63b00f8002fff3655a655a6e95132b88f133755e0e2791f412619a9fb98efae27" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "2f11c89465684e0fa7be9442d3fbb654f576d4007760ca2e01fc1292896fe32b859cc1c4ae229ada8d7a3a97714f71cddda1d6df6aaea3588cafb4d7fa2aa775";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2046c778a6cab5188f57ea5cd74977eaea31811f7865b13082bb4f8a4da7abb22de6c4ebfd8decbf0f1832e5a515ab8b2aec5947f19aea49f346e5e55f17fd21", "0098a63af50c03e693fd5cc9ed766731f1f85c3163fcbb34cfe9e0956031d9fbf9467c9b57b376c4b44699ceb0ea4fc38be3050b1b56338315bfcb5252a3716645" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "23454a8b6947300e1ec258c437e73c99a311842343a3adedf78c7c07e1a78940d9d384b3578e3a81f1e3b10c6497ac1678eb2b3d0f488eb633909befcd6a654c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0790612b51d1a1a77eb739c6019db6dc3aabbaefd638f1668eb4ca4dcb20851e5b02e2f5ee0f032bdebe3d6da913e27d78e3f964fa2101cacabe41726189b4f0", "095ce7691c6e53ed25c0db4254638e2898638e070c9fc1d20ffae0f647e35c4dccb44b215d214d00332d10456e653b7f102f3c89643cb5a74d8c84b18fefd76a" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "240fe194ded1b3052326c2d494cdc1e188a0976b58469466db614fac8332c5a5969de23cc01d8a06adff67b70e53fc6321ec787688d6f4371fdd7a24ccc37472";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1d13c0bc4d1d0af5e1f604add1dd6c2338befa19caff0124f88a69dd7c1990172e144ac622008fcfd45f65379eb7f45da261de185e586fba8271406e5ecc8f37", "68f88b85d9b6cb67d4af8014bf17a8e7aaad3bea355850a5362176eba46da028e6487bdabc91e508b4fde4c53d8bc00b7ebf6a6e285b96798a186d2c4fc521fd" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "5398eff2db5e32e09b0a36e53c02cf2b859073e665ebb0dadb4d3af22e87dc2987f4ee0acccc174aaa057e3f48e67fa2d059b04f310c788bdd0b8992bb7eec8b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7968ad6f3e87af91a0f53b63f9b6c4b395bb798147e24ff9a84e597d906eca5906716ee773b5da79ebf2067779b1408dc2445ab39bd88763bd436a5483578bf3", "3834dce5407bbcf4ea5280824b5922f113aee634cd0d92e0c78b8bba62877a2d98fb370b62228824f1be16f1c2c9691597cdf92db2aa49725f8a0b00dbc6b21e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "53cd7557416ef209fbc9ee0a01e16e6c99b6e49373d5d12d475db5f87729506b6fceac8998666c4f6d42f3da0127ed210e6c09da38f55c4a87cdd758ae1cc07a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "415d75450016b370b90c69275ac6d7a758a23d93f5ea3fbdded5cd9044414d4938ab61fdfc6976d979d5ff7ee436453a7d70cde4ec0bf7917a6434999dba657d", "3e49c72e842ccbf3059f070b5904b1c0d9f467463f26ea4377b377e86786503e492d97a5f719e5d70c84c9e02898b56c6f6402f807e3f5fa22b053c2009d096b" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "431d863b08aebdbd2e7391372d74d61960e3e52c2c415d51a92875511e1b1abcb4283104f0cd5cc00c15d8ea8d61f155452de73032288972f24566f16707498f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b5a565fdb5a88d7d08fb42830ac143823bf3d99d16911ab4326b5d03150381b6fe110f38926e4f7005c548191235bd4058c0621a55643b945f56eeb5a3dea96", "26efaaa17a123b17daddbe540c28aaa0ece9fce58601a0f68996ec2c51928285ad261271212f55d66a2cfeb8367ed7ef252af69a66a8fddd7b1dbd857ead222c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "258b4b91502c1ebed15fa6c5ea6159c8310fb182c42881f5ca0e402a62e2496e2a2e8cf25f3c6afaacfbf45264fe00531dcff0f09818a23f7162c1d1dc01e322";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5c1c7ee732cfed7f4e2fa6172c88ef8e5572b078d21cb556186f3d685c6259a46bfd057f54070b36ab10d91aa5cea5be8ec2e53f44dfd7cc5a2d528765c4d125", "41dc191acd2790993a02556f20305e90d6867967f48d97fa58b750cb6c964c0144a863026851ddccf903345eca4028c70cc0392ff8dfb70d72a85db16861f411" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "1a4332df67419f9d37cf337de521727b50ef133c0263aaf2b9e34cd2fc01b446930d4b8b4b3d5f626c5c14c5592b564bc8c2d8b93043022290ae36505b4f774c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "294f046c3ad6b9db41cb578de051becda0458c4fc06bd5a44a8365b2b0ae55d6d1ee96e21361cb9f1b531cfada723781d669073aca667f557c30722f6810c2d5", "5dc5d4ed742c719bf006b04305081c0deb2464caf2c2d35f87ad7d6d243e94d4efac81b3f3ee88130246b36fe65cd390bcb03ae13cf9a4fe7f28065a22e01e84" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "0da99c942e117eaee5c4109d7dfbc571cfc4722696bb5a1b36dfd53f1b70ee797d895a2f7da21aef675f6cb366472f400061a2aaac587be49d1b1df49e79e786";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "43161d4ca58c37678adac8fb5db52f039483b8889fae0b9bbc4aac1968fe263a159c1bc41905e40fb2c232c39258579e5d4ef5746f7871d1b9b61cb6f4325082", "33b0355ae7186ad8adf060bfe3f77b8ed66161a552f6b3f92b92e8c7f44216bbe445fe159a529cefb870f6a1a0a18d1bcb4d9bfd83ee5e0ad27d6a07d79a564b" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3488b8706760ec990c2572cb421dbccb9d9d159d048cdcbd7f572aac75da5437794c50b4df3aed360ab7489e5e4d3e47866fcaf3d232b2ed522e65f0dbc37092", "010e8842bb39fd22a9fda6da380a0a47880cfee6b53065fd4c589215d0209922d4b279bfdfab90a0438bc8af54b8d96f87d1f008f9f6b6f2bd3bb8abf6891703" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29ef741199293987cb60d30df8c1d415a558afb02f962b8d811dd76e0a2fd2301adbdbaafc4a82783ee46ad8c9eaa09401b4e3db7a90f15234ad5b65e040e185", "197fff50d36fd1d4fa45ab10bfe68fbd8e89878c066fbf81fb5258efa8b382d650d47b010fc4163706b835c859ffeb76bc1dc459bf170c9eebe8e4bec5d3f1f5" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548035";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5e773edd270d21b864d3812440ca86ab71a7198180d443947b4b114c44b9580ee8a956ecbb9eca6937cbf38ed58fa279320e28a6ba6af4881d97db981912871b", "7ce96273a3f4cb77e2180e9adbe450219c2a159fb2e6e2dea758dfb8a7b95caaec881244eb29c9dc8951d4baa6b9e8b73652de8f8825f831a0ffcb2577b4a727" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "225dfebe3b9ec898043981fe213f78daf78620cd1406129a14b3a6c0bba972290a612f8d43bde707a977150d89dcaaea8d3f08afefbf609dfe68454fb50ba34b", "00879c098f7e4b7237c38ad574e09851ae672735a1943412c548b7e1d9418ed18a7b318b860814cec0d2ba2e620b864c0bc44bf15d043b9720f7ba68271aa3a334" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "76afef43c18620c0be4b177a088ec71d210b27d0ebe770ed14a3c7871beb16acafced465b4a088f8b4fc7816c45b231e841be50438f06c72989b4bd3197bc935";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009bc821c3346dae289a3293209fa23df56c9dd912e88af5baaa9c9669f0f12b781af352da8fbdc1633aec700579c0c685c65b799de96933e8e76520b888b48cef", "008e5cd7368e76cb71f89e33a73e1ddcd8a3b9055962622305703465baa4ed2c1901ab8a4f1e654d4494032ffa81d70d9d4544e056f001a70fba1cb8791b20a15a" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7b017ebe897989903d7cc3d349c8d0a027f8ca8ad9111cd6935dc549a9707a302867891ca82b5deea983ff3a2426f8265d77c39206a3fbfdc888f5d5e50272d1", "34b85c363f9d0f1a72eecc3036601eb2453435c8e4852ba69163015ec5fb6418f91e81667bda8f752287c37bbbc5613c540e678c3ad80232598e82b92e654597" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "71e913d0929bd85cd53899c977dbfd5a8775b3cd22868c09e4426886f5775af58e2992d6331b6ebb810440bbaa72b584be768d00b03e91e923afb9ac6870aaf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1f4de3fb7c9f984dabe0262a1cf2231fe5bff237985cb2aa2a93527de322a1f6ddb77517bd6afb517bf53d3c80f38f68dbd6248233e9a64bd95b2de7676600a6", "04b133d43a3d89fb1a55e445a97e2637e1b4c77f33d2490736db7afc5f5a84bf6a3ba5e208d3cbae6e79a50391700226fc925c79daa862dce8baa9932ee5b0a1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "11648f7c5e213698d5d89a66b913bc4e38b721f642a0cb0b40954716716d50968c7a829e8802df0ad9834dab93c5a462dddca4d445247a23b44ec38fd66467bc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008088d1a75da95c7d00cffc4d8d4bb0e15da4b2c38c4e1d85866549cda6af6089cba936176a61b4e0c495885b8b6f2bc9fa6d6141c40e84214d1ff276d96ca9ea", "0c8dc589509e70cef5c2bc8de480eac545b2d790c3bb10d65c07a41dbb7756122d12b69d5dd9b3a8b8e060e1c55f743fac1d4688f5f787406704da5432840950" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "496c71aefa8cdae82bd84e783f1f569d95e5bf053b9828189711de93499df9542f927eb5a8bd0b261430172369282f9a0b990bbf416c2f52cfe68ab789d3167a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "70db1300b5ab6c6d57ec4a631a10f8af6b14fc4dd9560ca0d75496b117e015065bf048eec072e41982020740fa75e24deaa3e1ed2d4f94342c7ab38e4842019c", "2fca27f209fb9274cdce5c4a8240d2cc25659ca9c1201f3401e60514f2e5a132b7418221a5be4b24e5ce65e74f7127b1147a86575405904caee62afcfba91533" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "95e33d9a46e40eeca7c6e7390139d2388f52a5f8382d102d2a3a407c39b21be3914581a55849a41527c1d7ff574c9a6d146895593dc0cadb1b54f2667c8acbe0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "50a8cb1c6920da9cf7aae8599581e5e52994548f39b7a82c1c563b1a50cb5285b3847af87cf12a95f768130d6bf4a61a9c5f8846371efd992ad27034a940ebec", "0aec1ee534d94013d6448573dffa141d3fea180c552274bdce9acc46b2e76b401b3770ff4aa04d24206c26dabda2e3d9221fe62459852b9a83b00d1e2041f2a3" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "4d3b6e932ddf57cd4d16a35e9f3f1572529b0fc7062b1a403139c78809a5e724737e021724c762519e681264547323a66cc3004d84570fe356522b246d8ea130";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009dfb96fc92c1e4c4e11f00d8b27bffbb3d19a8319c4274d247140c934cd3540d1c1dd98ac751c3ca87b7469e5c9cf01c0955e9c0ad726dfb2230c10620f1c1d4", "2fd3afc18ac368f3d26ed1f228422dad8effffddfd5f240d613904a309f47c3719c9d7ae0db588381ac2d9fce282e8d0cfcae92eb64297273f7f7c9a4f1f859d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "4685cb3fe23cb9fae1d5fc637be5d8cf88ebde0dbd6231cb7a39d4e11d7442ff863c66272b1ea149ba8631e91120b4987b40924df260b45597550476301d08cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009e3adcbb4dbd820fb3fbaf1a17274d97ff08948ea7817cc7f72beb5a9fde3f2a44f5073601679f00774b8324be5eda847786d0686b932d3109708ae75bea383a", "0a60056d99747e33e381f318c74a91310835430dff40e92b561fe96fe362df392634d49354fd098a91324e0e0545a1d556de6b8bebfdaa1d2a786c440a68e11c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "8d0b967fc47973f5c3abf8c6f7cbb19f11d7bc1b7ac46396f473a9c23ae885ff0c78cc4e563d4293750c63d222416930f681249be4c168ab2eaa08ec603a119a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "41703d23344835158cbf8fe91511470f06d893a99964e7ac55dfe5ea8592b85b5ccb5637af7af9366088124da3952d9d4e5f2401eddec72f3ed36b92585f8194", "23b6846b10ff47261391a52ce794c4b42c7b3bd28ac6bd51e9f36208d68ae8f8447a3f0929f9b1a6c41a9fb1b358065204519aa6f24d09d873ad276a5f799315" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "3e63d498f8dcc291e3f22d2099fb5eed77b6b4c43ee7e3d97032031f4d2800f817db0097b6a1336aa2eb5caa95f0f1724732b538e8f7027da874ed1f87b89a1e";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0f6a4ab259cd311419b042c15c06bc5fbb8dbfab5598f31c9770af038a9c93bc963c242b2342fe434a19959d61e168bbd3726a81477b0d62b064f3b2c424b182", "0080d8fe3ecfeddf8db3e2bfd9c531f97605fb166ced247e13198cb02eb1057d6a47591b9b77795fce03d0fa760e02b15a1726614802292ea2641b05f5fcaacc3d" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2402a9a013684e1f6f3bfb8e799f7dfc97c6f5a222bd36af037017e2326292d6f31bd3e27719742bbd46bc909d3f78d15c28f6b529d4ce920b0213f72fe68a05";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "425700671181ad2bca33fa9d71f8b54a3efa244a44f4121b22ec250ce8fb67b0ef8f1ad584125bc218db9fb820618b61c5fdde6e8f14634985da5d94e5715a27", "6956342b26e456467d00c2569f2b566ccb917daaee03cf2703f25e4953b694137f7a7cb58b4417232254813b9edf6ab11b68807986ddea90676689c9f5b2875c" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "5de916cefbc79b77f6a6abdfd15ce7aa8c86c9b1eabe95aaa386a5ca4c612a69129bab0357cdc167891e5db2f26ed3ca4f240c6563add09b9c85be62ab943326";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b6aba9b92f85dc3b29497622fe0870137141474ce6cb05832c790f566ecaa8dbf7d198bca92712a872fb5cd2dac62b35eca0bb649395a0e2620154c6dca98f9", "409440fc705e8daadda01ada8c3288b882f6f74416a85c9f80986fd51fb3e78ff2c7ceab5e543d13cc58e5fe0cd45688ccc10a01815e25790f00009f939af941" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "a22b55faacd9293ed4e8997ad7401de0aed4fcb892796c893618f93f377c60250f011af208a7b693d4c4ba43b5c93e15aec38116e5cb9dcbdb6034bab176cc8b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "392bfc61ab2fd22db9727769cdd5eddfe21f576782dc9b16915644482338b723e10f44492b4d1d3fca5c78bd88dbc4af9c0677d4caa40175ab2200a5c8bde328", "4a434a69e9508dadbf77d40841f27d244bbf07e8eaba153af0f6ee93507dc1d1c0ac9b551d6b563293003c480ec21b4275fa605692f9e78edac7f490975d021f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "99790e3c7dc88df269fc4c477ab63fb992796bbd7129070395ce55b3fec5b7d9c8c3d9a2c4a6470e6803136debe66be43fd52eacc33960ba0138d2f2c64498ad";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b0f56e9ab645420b813380530a81643b34ebff1f6fb41dcfab7a68d2efa9e2706632ce05d79745bb5e81a041339ea712503bcb17774a46cd25dfe8b8f31945b", "008a2fd86d337987f2ca92afe7035c720110935078db589252d1ebb65cfae5f9c2bbf0fb7e947300017ff3f2536ff9ea8be03b843fd506196fefae1bfb01ca8b89" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "90c6c67e4eb7f2a5ff0fff141e2c6192761ddac24fd8a17df583b228c60f0f8e8286985380a4d788fb416c98220399b2d0e6dc42a0a723a82711712adb1264cf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1e48b5906a33e435c7cc5c33350650b883bec5a6460af496be207c947402426c8f7bca8748960189701d0e58f88a49ef83fa7515fc884cef8c609f56a09c9c0f", "7dc1165038e113ae4a784bb7f3251f75636ab61885ec344bdf59dfd09e3ca33148b9071b83ad688005b85d7d7f1730697ea8dbc27ffde297bfb86ac5d62cb175" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "4af19ecd2372077653e3739c809ce91c47a952fc1c168816951d203e1cd90df1c8a2c0d2ac24d20a93e0ebffaba64d368a344aac9ee0656d8daa79333e4565f0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a096e63a5e622aea6d59d70a32078f083e5d27404e55987d928abb970cea043a44ace48b539c62566514bf19a99fda8f4a1f653da5d59eb366594334b59fe757", "0a91a26e0bc75cd2fa2ee79db9d557697f8ed30fda2b710cd354e943b4c95b061d2987ef964d47bfc272d6bd58709874799e0a065b053910e19b134d82e91e54" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3661b1fe37dbb7f4805590984e341a8996def8f0ca48aa10341fbb76ff6b3d3e63b9db4d4e0898bea0526fe862f185843080e37338933d48e251270f1f0af644", "00a6218f1233b1768da891330d22f855d6a4c5f45bd86b85618db440d93430c10f12c0135b5a77f35fc2280efaa2738db5de433faac4e1619e466c27a68ff7dc54" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "48d7851b079f620209e8ba05eb24ee515964d37577c7c3ae309ab2bddd7eee7101899d0c6c780111bede61ed1215ec42399409d605eccc9aac4c9548f87770df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "47b0daf2a39ab562a2f6202be62449b2296efd76919497f02d7bac2a49d087c02cde4d8aecc2cda3ad43a11868984180c636148c1bb42a894701fae30082c68c", "00980852ea6eeefb381dc7d89c1d744349720fc66f583b8e3c831f00a0845faa7cb4c45d60de94e7d444b7a1477e07bd557461484b72ab6aa7b9bb876529e6de17" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "0e6cf68d5be5138253de290ec41bde7dcf96065c280d0a09d9a4888d5de04dbea75038fc061b653340696c62baaea92d5747e50249034c427f2f813e2b98c24b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aac68d2a96e1ab96e0d645293c030ffebb157f8c09c20db4b36261499d29d6145859fdac25b11a38f3a11cf8be1e4d71b0232c602d2e9e196253aed5ecb92a18", "3930c332d20f4510e4fe4abe8a65dc70d9d8b5f016a630a4761f4a65b61d5863e5e368c97a9ebc67e91a06f2c555a64f50ef5dba271784f118bdc33888ecdf91" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "41b2af78294165d86f751cb82a80327a0eb4c0544a06d4a5719aea4a098f115973aff4c1a8cec2dcf0f5f0fa24190b474a25b9ab3baef7770f68ba9c7ef7f7ca";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "303995ba7f710be4437a20788cb715d5051fcf8102d781ebede6dcbffce53b689fb994da9ac73eae9ffca86d4ec489e83e8605892fbce53ab317719dde26d059", "0096f4e95ef3ff10b79c7edaeb2aff0e46402d1924fc711c2f9f6dec3ae62d474fed8045abec323b4b0580a5d42288338c35051dcc0bd28baacb4ad74c9735c2e4" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "9c5fc3fbf70f16ccdac92f95974408ffff7e05bd0268cfdf862e9beb174fb48ee1e0e10f942d8fc67ed69f7a94c85f61c84048617e67c1cc6c0260e048641a6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56071393be95e553a1f758423c222434c48dc09773be20a60f1b6a486af3172ea6d58f49804eeaa009f2a7c73609dab69f1d0c8b115ffe59bf731ebb6ba79ff6", "6d40994998e9fdcd7fc89b44688980e1ee801665cce687390df0b03a8f80c40cdadcbff1464ce4a26ebb26a8bec700a1c653b6e7b4efc0741df372bc8f795e0e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "8de1ea3f1234690e75bd787cfabe15f833cb7dc65107cdb035f99b0bbe6c60ad6e8365dddbb1f973bc26dddba9e4ae7c72cebd41f471a8bb227d2b3df41f346b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5917cd44a83143aaabf081b2a3d2aa6219b82857c74c37790a06bf8ecb51335a4ae7b6dc9c3979ffc3512dfb1ba5146363c32353b3a699b370bf36a05a538d39", "03e1744dfa2e883bc6fff0332c96fe047203d2251dacf74b2f4575506d26702cc13d95b6663d5f80b19961ac5f9833481933471f682d26ae9c8ba9f5acde98ae" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "326a7e59c4bcf9ba52235a8e06d244557acf66885b64f9238cddb3be327b6205758b60f3203418cbe5b330e28a9d7a360edfb8ddf39d46340d5c2792824b7c6d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "25c8490876dc176dd0cc3c4b31b8d9d8b9d102bf4af91ab431f373ff6c6bb915421853603740148f8ecdc75ccaad96fdcaff313f2df7e94a8d9f380b74ec74ae", "409a723e6a4fe6fadb069b7a17f84afdf36eb0e17e9a9b3c1ec9de8affa5d17c0d38ec5d8c5a1e5f1142516b10053335ccf61cde4afee1357fc624c73b6fdad3" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "3c5d08339f2f6f97a2b86b83296678f7bff61e1b7487cda14f3b12fce6aeafa3f2fb385aea3e82f312a6880efd18a1d77fd7faafaf9d1ecc5ee9c2c0f71d10d9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f3419e9f74ad96beeda5afbf31358bfeb480bc1f9c0d8719c4840eb68ac204ad72b2bcb02e574e88ebb176793946ee886eed7affd8711dce6b20857f6887c42", "24f058316d5b0650010fdca6ed7db83e16111650fab2c063bbb992c65638c6a034538cc3028472f31e81a4c1c0f3cb37525023332dde8fb5f82e07639cc5ffa6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "9584a4bdf0c6c8ca72211f589dcdd7be181accb926f2430dc7135abbfa7887d606030c85c72f5a3c05fcc7e0d1fb33afc0251fd33ea04b3b96470bc26ce612ab";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "75d9eecfa706e682ea570ec305154c4de67c956472c219df227f19e48b9338255399fe887e74f927580eedea6063ddc43a9a27ed5558a1dc4e2a16586069c523", "23613fec086573e5aed522c317f6d0311349802b965bcac0f42b90db324cb28700d782278f971653714927310dc286bdf7ed3475281799a0e909408115f43901" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "40197987189f8cf04a951e01c48fa8ae9042f184848f93b215dc790fe2c42ee2d549d8cb50ff3db74b6ddb376a80b2ce3983946b2ed99819856e75ebf8ff2ae0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1121f3f6e92decc48190b516f0da402b8339835c1dcb22f5d79aa87267cfd63a6a855753b07d4544842009852d19f6b1c5fa1a207c1e53a5de419619781d8eb9", "3f43849eb28c4c07bac9118322df9536b0acfcab5eb6a8d7d8be69fbff664f85d3c9949393a06c589f0b3e3bc050d7307796d1909bcab7911b01fb465ab7a622" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "8032f30e313f19e0952a3c03891f515d2085e309091f27642bb8f21fc5885dc5aa93b196a1fe7b6e96dbb66ed501659c730728d65db330330adcebd7f1fe55c0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009eed5f5cacc0b1e1beebedc6e20805a612d53e9496b23ece2efae35efaedaf99e0e9682ee7669c3bd6f53a2ed44767588bbeadfe2075dc0b3b493b813c6758e1", "7c83287f63c98491a39217255700be076ab2210c5c246ae62c73cb978943717fd35a23d90795228f6dee180ad5a7705cc707b8e3996e859012d472296a404193" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "156ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548037";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "47726f17f60c8bf1ba0f8e2542a44514e3a79638db9587e923fc23b127e151ce4ad1271dda6a1514ef729759c32e34dfe9c301c376ed689911c5e6fcfb03f953", "479373f795fe7ebe83f6909e01bd6c9c3077dfe159b1c288b3fc1373c17c6dcaa4f834d0325efd569d980bfb1330f5e064ac6eb2a3929fcaa4d1171ce7d7bed6" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "5ca54a231be76c06c9d987de7bf2ed42cd634a07edeb6e0c580412abe709ab177e474a9ea96245a640f7e6be1d2d5cba3a7cdc41a8b093901a5b8be06420e15a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009d5e546d4811392fd2e2df1dcef201796594983ff33d7a6de9b757b46e20e41fb6af901a11c40d315f950d456877dbb7c938d5489a04c094c536d00bd7b09e6b", "58f2650fdbd597cba2cc1dfbef4ef55807273677e64cb79e9f7d275acfb06c1cefeef754c118bbeb8c4d13b64ae69489f63659892325fe20fa4df7873f528511" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "1b8e8440bd94752dc603159728a346872cad48dfff819f181f9d53537a80868bff1280acfd2397a846d3259049352bc11f5fb739410c766d1344cbcbc03bf761";
                bn_t sig_s = "a476729284481201aea198dac1a8c53c0c52033b59f95f624355bb6c5e78f00ca023520f6af4e6a114f211779480c12d1e2b30aed4f7e735227fab558c01a480";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009d5e546d4811392fd2e2df1dcef201796594983ff33d7a6de9b757b46e20e41fb6af901a11c40d315f950d456877dbb7c938d5489a04c094c536d00bd7b09e6b", "51eb38a900142cbf9d08c8b2447b06afc409573bcd7d1a7036e6756fa0829c548d5ea3abdaadac5722808d749bbcec5c324ba5a60a5cc8642e5c68cf18e7c3e2" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "1b8e8440bd94752dc603159728a346872cad48dfff819f181f9d53537a80868bff1280acfd2397a846d3259049352bc11f5fb739410c766d1344cbcbc03bf761";
                bn_t sig_s = "a476729284481201aea198dac1a8c53c0c52033b59f95f624355bb6c5e78f00ca023520f6af4e6a114f211779480c12d1e2b30aed4f7e735227fab558c01a480";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "14f407a71ce36307179845462cb54cd49b37f3742bae9b2d2a4184fa9075efa0f514ad596f2f8201a51736385034f63da07f33f60c55b52f6cb043898fd6e9b4", "6b1593d1bc66902cbea4aef71a1936db819097aeba373a05f1191e7db1fe0912a1d51ac99603c0bd97f6ebcd794ad5f4d73543369fc22da765093cf312e75b37" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce1";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0096341d3992054acf1844642796dcfbc39e981ef86f02ffcd6aac44115eaefcdca299856e40e5d8f47542260fd1cf494d9f46afbe0491f06f89f7799a5d39e8e5", "57cc3e41c1bdfad20a7b3e87ca179795cb942c590e4ba493bf1e5e5a98ee6d90dcfe227ba2fae5c21e59c720b25398bad83c0d7fc43a225d4cbc465fb82797de" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6c8ffb4ab20f31a365cec80cdf91cd8b2e4f47752f26b245754de63fce3b15aed1666506121e22fd8b844e9c9fab170617b78ad3521069077c883c7758b9fb31", "00a0ced03e1472d31171137eca5a5427fe921cf16d713ea67f433531d66d0b8b63d6170740800f8ca66c9d45cce6d0ff7f4ff5bb209bcb420ba4f6e6c18ede865c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "7a0c02f1c1a6fa1a522a5ba1006bb4059122ae5bc9902853bdb4ddb52b922a996175af9c5b543fc8e5a920c9120d3032cc114dee73b0c0e781a9fdcb022f9294";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b8f4ea522a9b71ad029fba418364990c9de9571f825d5e21ed70dcb6cd670e06be1304351ca738709237cd8333c867766a0873fe7f6ad88cd5ea1af14c17d90", "2f1f21aafc47a19d095fce0d6f32b469592d8a8b03a6e21df5d3a0364f242bf3fce6cc051514852c60cfdeb8e4faba7cec38212e364d27d24bba593ca8fbcee3" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "88b14afa4987d06f6643ebbe8fd4c99fd5c0715c8fd4a80bdeb6170859c26d26aa9849cdd6edb814346b80e132f00d05b15b0f9a6d17e24af79fab9bb0873387";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a3196e7e4ad2e6c45c75103bb9268c78aa9b38f48c8c901120b11201d97b48da9481763b875ecc83d3bfa006c676876a46633fcbdbe920d35f69048229b89f2f", "71cf061f4316648721750c7a3733c1e9f82817b82ebde96e1411f9096c8d7f0839699062955c572fbc1c42bb5cdd5dd074883eaf311360b0da52d7a4b8f4a31e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00903135f5ac15522c5babc5a1e2933c4c561ee37a3e22f758f81a509ea37445877c92be06e5a108ad095c2fa293c281936ae2858fdda85bada01da46660c6207b", "5276c908313bcb1d49af978edb752540565bf268ff2b189f358184066da012523b13e3602e808fee2cd7508df2bb3b5a13bc053b6f31986eac6f5a9788bc8875" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "30d19ac71a42ca70edaa8b0d335e48023a0ddf57ea39a9bb18aebf1544a0ddd6f3c8aca4f154e6505bdd40506d9ee01451a0859294ad19f633dd98b79a796dd5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "208b4294376fd0bd63b076a82dbba1aae25540aab0f82bd22dc441c9b9423ab77bbcd5cb520cbac91fd9a82bf09674bd3ed5dd77068c46e457f4f0c0b0060d61", "00907fae3d37db127df32aff0cd688f9b3976e877af472a2890fc358d889f2cfa62c5aeda0acff5f76ed5376e817834ea62ddd097556da74b8efd35c8a4af65dee" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "10b989002855ffafbd8c23a661f3b93ccfff4fbe84a23d1a6c4aff4405bdb94c3f860224e205032fdc9a1dc80c7d6b21409f9632e0fb540021ccc42161b70f1c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa483ded217e380a5f27f9564a647b3e25d6b51030043420bf74feaca0215759ec39b6cae1246bc29165128f0339b197d92ef8b751e8f215f04d754467c98a1f", "0097145e356e04ccc05dd3adff07967cddc35afff6340045111e91695d7a3fda5e37d15e06f87cb2c49968beff1d03659502844ff47662727d3981100b31689ce8" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0b2905a02d1c567f6c08c1299ba811cd56532fecbab2fdf2be399c662deaccb97e3f8993e8833ebb9ac7ce34c866fc54c84ade4de829133063423ecddc681692", "5a07d4db1b5f3c105a9fdc88979bfd11ef4f2c5683b3bd0a2963a124ca9bc758ab7d4b3baa89bc0970547bc2d590339ab00d8b6631cb2e29cf5058e5c3a770df" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "7a0c02f1c1a6fa1a522a5ba1006bb4059122ae5bc9902853bdb4ddb52b922a996175af9c5b543fc8e5a920c9120d3032cc114dee73b0c0e781a9fdcb022f9294";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00805d6de6dfa77c6b87631334669c839a0639d73ee5bb88f5fd0191ffa52caeb8b97e6fe1bfc6b2905a725ba3f807d59908f66cab666b5bb5f5f9c83451e3c7ff", "00958b3c307f2530ecc9800c491e18d70f9791e46d5877012333fac02c161685630a50559053b14276464777910aa4f77535e7be2794ab4d05d3a00f86fc653f7f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "88b14afa4987d06f6643ebbe8fd4c99fd5c0715c8fd4a80bdeb6170859c26d26aa9849cdd6edb814346b80e132f00d05b15b0f9a6d17e24af79fab9bb0873387";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "566f693e8a283584fa9b296ce8be603030deb85e70b6221584d2fb1bf734b12f2cd0baa99d8ebe0a15c50d430926e016b1bbb2b13b633e73ab9dafea50580226", "322ee5ea25de62712580a56ba90c6fff0f4ed941bb9551fc14a2381e7c35d7b1b62aff1af730edc5be994296bb61523f1abb48de1b2c0c428e73861841a2c3cd" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3ca7d87d19a857a2d5bdfc96eba6d70f972404cf3186244c4921a1e2994f18eded0fc7fa3618478246c7227822739d1f96da3fbcbaae76d29eafb227241aa30b", "1dd667c1197bef0d96285d65a189e5060f57a4af74fc3edd7468684f75eb0996ed19317185012e9cb2115cdfbb44ab77ac65aeb14956c65cf80344750e7d767e" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "30d19ac71a42ca70edaa8b0d335e48023a0ddf57ea39a9bb18aebf1544a0ddd6f3c8aca4f154e6505bdd40506d9ee01451a0859294ad19f633dd98b79a796dd5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "39d878769e7743e6e11999539989ca1c34eb802a88dd16db7ae28320c3adb34b5f25f0b003295096b7da32312d6426d05515f092059319f4318cd2b751452407", "7a3536dba71c37372a7f0a7e590bdd37d2725639d08e200a13b13830000ebf1813d3fac317942c7b4c54fd02db2376656e212e793669ac89b2bf29024e0c4d48" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "10b989002855ffafbd8c23a661f3b93ccfff4fbe84a23d1a6c4aff4405bdb94c3f860224e205032fdc9a1dc80c7d6b21409f9632e0fb540021ccc42161b70f1c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                bn_t sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "76afef43c18620c0be4b177a088ec71d210b27d0ebe770ed14a3c7871beb16acafced465b4a088f8b4fc7816c45b231e841be50438f06c72989b4bd3197bc935";
                sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", "2cff655b8586919e7eea27046451d909d92696b38f2456f43662d76ee813875fca70bcb751671fe4530355525c7c1d3756b7d3ff8492727eafdd42471d624061" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "342dae751a63a3ca8189cf342b3b34eaaa2565e2c7e26121c1bfd5435447f1c3a56f87db98089d208c89e902bb50ed289995ee7ccf6d6e6b1cec4aaf832d3734";
                bn_t sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "76afef43c18620c0be4b177a088ec71d210b27d0ebe770ed14a3c7871beb16acafced465b4a088f8b4fc7816c45b231e841be50438f06c72989b4bd3197bc935";
                sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30a67deaaf0cee44aaeb903d8cdb24ad9dc191d375d7d6a60d2520e19306cfc47dde9dcb80aae0b040554bb98d601e019f9336e831cccb99f2d92cf4b91604b1", "1a4b00c74a5a61ac196faf4dc39acd41bf354def0a27529964359132a76f28654248d1ac004d11d811aba0acb9c26d2f4a54012c5d8a9a1e7c8b4a52" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "21ccf03c30613238a86518016e8f256b2ed4bf1f621cc869f216ace7d3decedce2154f8baf3708d6b5721eb55d0be0507e9ac0906dca7b3a8b03961e734b7325";
                bn_t sig_s = "1aeb420cb2ac1eea951404e6f5687004a2cc5d371c88e06aa295bc0dbb328c342e343f3c89bf8ff41f6789e0b5401aae73c684ae5221c36d0f29312a28ff2e8d";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "2ca029e929f20f6efb694c6560f57b9e4ec5b492bbf5ddf95b346c63fd9aa4f6a5172eacddc80f21f8ebffbe7ff4a33919c9f6231e99337e9681448656646ef1";
                sig_s = "a3640e0f518d4affa4752e7215143609d6d7321d92ae07da0a684209bbda4264ff41239afd18adf5bc9e35dda17b56af510fa9521a855cd6ef5b4f51b10e8d32";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "09f92592cf37d01e272bf9d79b73fa59f3cd25a356853a50d98f05798ac0cd6146da84526c7476e528daed7d33231f569b5f57e06e951aece14142f4209c0eee";
                sig_s = "0f091d7ab9f6f0d846fb229f3d6938685ea0b0653588e01b8ebad56bb6cc35b61c59eb83cf6b1f3ee3fc443b1fa000270fe390bd2be60d03c79418b3a4a5a1b4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30a67deaaf0cee44aaeb903d8cdb24ad9dc191d375d7d6a60d2520e19306cfc47dde9dcb80aae0b040554bb98d601e019f9336e831cccb99f2d92cf4b91604b1", "00aadd9db8c19ec3c3f57a85021a5a4cba0795c071f494841fcc3c4a310bfd773ed5de729b597d9696ae808f52d4f7e0396ebf91ffe32ec558cb1fc637dbaefea1" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "60ca11896c4609553b45a9e6ae462a49b752c85ae18bc317d60b0183d6de68e9f671d19494731d06932e9fad9d366fb2c3e281973441bbd1fba2f41eb3ccd5b0";
                bn_t sig_s = "1341db7a111879dbb638e673526db92303ad65877965acb365df60759281ed81fd56e35642ed04351c2a3ee91463ff2bf1a033ddc1045c57d7023b0941a4aed9";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "21a69fcbb4dd9644ce052c0d33f4a7fd6915a2088bf81764a6743265cedd5538c829e080b371f5ddb11787b4e90d3de7167c98c336a1c3e5bd1e1a7a41b45238";
                sig_s = "a79380a268494a3d249ba117425033ae07c1440fc360aa64d393cc33b09c2a9090bb099efd9be8edd8f7e05391fbc6cbbaddc1a88368d0b4a623c760f6b1c8b3";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "41a0fc30146c44f61e55a67de022532c74b6f798af4140a803700f2802a9556e41ae1168880dd0db4e2599f339351127d10440c402815570309a05bac246fa0f";
                sig_s = "9c96054269d230f674c116e45e1a9c3065744073ea163e38a407faacca3542f6a0e17a98a6cd48d67c1022f282ba47fe9a591a08c0bc16b2e93ae3a587c4d07f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aadd9db8bb4189a6d2ab7b5aae550fe8dc00be2e00f4b35b576d6f862c09869210fc82fbd15a54def1442979fa0da1c64408fd8437a60046930820748ecdfc66", "4a59a87eae338d22d0835523156f8f7d934710a747cf192d3e317bc45f0489d6979887c65ec17ab7b5e3da9f4cb110116ef0739849acc56d24e5a3365fcfb289" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "953125f87ea07e4cc2a3d2ac3177de2a5add49444f75d98abcee14ee5e1a2a2a0b0a30ddb5cd142185208bf353cd27e15fa3072985849419ee0f7780c60233d8";
                bn_t sig_s = "67affd3ba8c2054b5a21721b97953461b95021764c262a807c4d493efc1a973ea6473c20512d4b72415f59f1389b6c54905b11007b7ab014114ba11a524c5929";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "370f99213c05a38d7da1267bc261bb743bc6f208a0842dafebf182e9db4869bf54b2c43e8d47a59ce03ab40359cb293259044a6a2e5c3aaa8f10fd6110fe3c53";
                sig_s = "01ab8e479ab4a4f33e6c3c294486a68ec241b24ce02a927da6b609a88f9125cd3c4ba46455ae79759d92688649521ef3596fcf3f72551580d00fb889b720c577";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "798d1f0dff57170b5575d1bef0c80ea65cb02b1e739c34f0711f86324a2b3273674508d46705db5d7f790e1780bc7dcc31fefa5792e67f7cc4b96afc714af230";
                sig_s = "1548c3dcd990d435b4d981eb97168b970f7463033353f30fbb5e0327b696eed644e48896c5a587824c72f24db2ee03c8fb43b1d0386d3d220f685d66f735e65e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "24c10440e37a15d7ec9a3a48965a9ce9380221fc51155f1e992716cd9933d09ce0a5424471877e8994494a4c2ade0a81ef52952e395655157f0b743b3b219e2d", "628fd5ba510f610ee693a1e0d39ef39d91a6248379c622a175a23a5330a88b2d5a60dbf6d249702cd1504561535ea17e1be1b70a41dc463e8e1a1af000000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "99b8f9d6457ca299b690a0fde913627ce347ee800306a85b38abec6fe45c16ef8d72269b8d68fdebeb345e0b0fe858c8fdfb5aa07061f8df9b5b38145d792de2";
                bn_t sig_s = "7061fd9fd19e1ceae952f6ae8460296d75171160b5165226d653278a79d0d46ce21863bc1617c13f7762c36b2fcbe40b3e19fac13b757883980fe1bd00df9e67";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "2226ad36e404dbb807454d85eba5b2af587bc66d0041e625da3202fb4dc8e21ba4c407f1e3f34f07e911435fa72a93ef83e77f440128903054042d2dcbac94cd";
                sig_s = "1772a3e35d5e8a72a4f59cc08a428ca610a76c511872a75e17d840f51055b51ee203e0dd9d49bb499332cc1f0171e2d17124dc8f24343f777894702b4b570a61";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "5efd45257768d1455b779d4184cc4e537c21907d16918d782122a295e04374c6ec708daf4cc1d7b0ecde364cbca89dd3dcfbe2d8c22b6080d25570305ece010a";
                sig_s = "4a794ac06b6c8cd73a73d8bf805111c4c6cd65b41e179311f811f9e6eef54c1b403be15280f74eb01bb05807ae9361d8ae6195f0305cb5bb7b23562e0b28ba15";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0ba18cc05572424a7a391f4b48258a871a0f6d8216c5cf82446c2d156d5586b4c196da0b2f3a23511b89eff31dd4f0c88dbb1a76c5e4b27c4276f8fbc74a1b9d", "00a28cc8c341ea2e3908ae6ab6825f956032c53e625697f80b7b4ee72dcc9f3cff730349e0d30de410917f3d0d1c8988562c1d55583b47f0dec234fda2ffffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "1175b923d0a2a76a5a6f7ae0459a46e24333aa07eba2f8fcb2eaa5b52ac66ecff94bbea2b9b380ba6e94ceaa27e5672d3a19b2b99a8ec153e6a969a3c8598404";
                bn_t sig_s = "75cc576f2d5bbdb19f9e2b2db2f212a27cf315359cde310a1bd654e02568f9eaefc76469f18070a7c63cd1e49d8a6fd052b5d6a6f7dcdce2be07f8176b3a47f0";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "667139a304c529db10f8b3964fcd302b78c36cd923d7b4ba4c7c297749e24e9660be8ffb151f60482361adaa94f74ada0748d2cf2edcdd095e62835e4899946d";
                sig_s = "1db2b428a4e69b570c106d535c1e64fe6783b6fd3eac74159be1f414154555afa9c9c9568eeef65dd6bdc96d120eae03dfe19f8fbfc24f72a4a138c45eb86fb6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "750e123464cfe1bec09840e97a0ba5e9bb36ab244455c80008aae917906a838d77fddf8362f8996047d4a12ed36b96e80a4f001c57393a094059b58029f08c27";
                sig_s = "2d036fd865f14874342aa2c8fcbc1875b7cd9003b09c9dd827f2ac75be1750546461234b909969275c95c8db1a430a55cc136b827310b22ea83fb72cc7bc612e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f3327e34662274aa147953a007f30c2ee1b06d7bb053e8ce1c9b683f0f46563dd38db071d87433b30380434c92e8cb76d603d1936fba1e9317a06e200000000", "52ca478f0367ab24857e788576f17bfcd05e62d20d0fbefd1b2d954b996eaba67819023635e31483f5b0257f89b46a1d2b9cb2420e1cdb940ceaff5429dd8013" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "2c178175aa6c06c27c489f607ad06eae9d4d753318ef30d9e31ad56a7d88ece3ef4772e2cbe6bab95b8786d075a9e402da628267abb223bb7a63fee0e8f52ef1";
                bn_t sig_s = "47c8c86c650074e0191ab5e11704b3aa70236029c7844a90f8ca397cad28b4822378e7f00af77760e74d684f5ea2f6775b4b46ec48b31e03a4f21c9e242300f9";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "33624e142ab7bb9699daf2cff761debc4455efd5fba9bccee38f5b1bfca56b4f986df50fc3b75f5e273956904c120211b13e499294da15947812bfa1dcdd5c4b";
                sig_s = "3640e8f89adfe6d911b76d4f15a28be09119391cf4b608786d88269896ce44b8d308a50ddb7f64d0b0a9bf7f7029eb81215dee3d62916771ad9d45fb5bfe4f67";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "4bca1b396468f4dbcf023b9aafdfe60c8c40dd6df8e4262d12b40a8af98f25473fc3ac2b3cc25293552403dae618ff01521c0bb1151423716c1e9dff5faad049";
                sig_s = "76565e9d4c7c6479dac5df1a56b307d76aa03e5a5daaf2536c65c3bbfb38b0e053f1d48b01ea45cf2085b459c274bad6a8a9efabba0dc8c37d6685197fc11d96";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "12482f158e62e83467297b4edad930ad319048283f0949300605a4a2d19f72f924d41e1cc3ad2c246574f4a0eb637cdd386c1ebf4a00707b71a646dcffffffff", "18d851ef92835f7be92a25b988ae8d5f7ed42f312f7c896850a589f7bb7500330d138cc20dc5630a7d525926e8f717635ee72937035736ace88f0c491f31930d" );
            {
                // x-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "2891b5e4ce86661d6d4fd0834559a417dd88ce61462456ca245ce7a6b0da8b545e85af3ae34137a351de75d38b69c58895b62d1993d1c41b09056931df84a245";
                bn_t sig_s = "18475d26c83c44b67a720145953e605ab0bf8fc42d59a2ed26654f808f097ec09dd1c2f313018ca7983f75744fd4416054f77fc1c15a52e1e9d1cbb13b1c95e4";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "1663dd047beab782c1d27be3b3c8dac56ec24597a9953e5c8fbf3b0b426ffa5cb2cf5d2597111e2dfd20dec77b6467a0144b700ab90f14cf87c27a067353324c";
                sig_s = "3810269213b9abf636a6b0fd0b266f0e81374e0cf7e3f3a19f8703cfc31fb8a0dee4be308faf533e136392f01c0f1562a912b0cfbec35b61507320c54fce2b81";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "52b10bd0aca0cf4682ec9afb29ad33bd0df95565c33182ade5eef4bfbeb9048aaa561f69a7cba60ad7e805e37289322eb2548d064df68fb4056fcb1278e3c45c";
                sig_s = "7e5544a75f58e3dee93de6b7993eee4179ecfd1c9651952a0d0f7dcce5a4290ea2afd3d898fe6512c525aead31bee49297218be6bc08323ed4f6634759e85143";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "727e75d63dceb1a84a7106d802e8eb34a204bc05353567a23ba8b6f54e50d2d8221c87fd8e5238a3374df958b3cf3e3f38c618c1cc8c5b9574b50e405d691218", "37f78918506ea9cc14f1492eb66c9e1c4e27f3cb00bb511d5dfdbea6f817a87bfd81de2955fa032f52873f799169cc445cb0391e46e57179ef84d50c85db5c97" );
            {
                // y-coordinate of the public key is small on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "aa1e7972e1c66c0a9da57d785235733323a4ec87793d05ba8321c1d76217b72403ea7eb9ca8df015d56195916613492703355561e6ea5db6c3014beed7d7851c";
                bn_t sig_s = "9d7983c5b3cbbce9a1b642c644693c605fcc127df878ca35dab2c90eab3755a1a45349e164bad24e71d9f888a0680c4f5fb01db05350c88bbead6a548366124f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "9255be316fff3202ffda038a193328be99c774a20946fd24908797696b44073f68f15f2d9b6cc28da55153849879dae332224d286ad186d0fcbc5ed7ecce6038";
                sig_s = "38b38835e763f5e3d3f0adfe0e5e1d846951fdda434ccd20d84b00fd3d667ee30d1f0cdd21f20384978cd0228e9d936cef6183fc3aca069bcb34d2e9140b69ad";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "06c16d74fe510d6f621ec845e95613b3b605b68acd5e9dfd0f73c19e2c54ff8a887df0336db80b385f3df3fde0ff7597ee8a73ee81c29d8fd935bb3d992166e5";
                sig_s = "31e1bd918d45e01824543bf42b25cba5eb7f7a39e8b8335753ed45a158dc65f921caf5616502547a5c3416396aeef6a77f851da1a3c98c277d60c9b377accfc2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "727e75d63dceb1a84a7106d802e8eb34a204bc05353567a23ba8b6f54e50d2d8221c87fd8e5238a3374df958b3cf3e3f38c618c1cc8c5b9574b50e405d691218", "72e614a08b7b1abf2ae39d7f7d5d5deb7d0899e8b30e80f17865de23781b5ff57fcbbcd745cc65135c4661b15539b4a1cbd1c610e69d550b39258b49d25eec5c" );
            {
                // y-coordinate of the public key is large on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "52ffd56788027a6feebe9bb2ac8a337f640599a965b0e21f9ecd6ea5339dc6bfc5f87a1089a05d3850b6cfb5aaa865da4f84be5b94759b8c6640e5349b23a6b9";
                bn_t sig_s = "6d284ba24e2e8d3f75004324945a3b436d2edebf7646d1f65279767d2292aea4f6f1b208c1037844c9a5ed76b0d82fd51ae834553422b8d7d4a39727bf923273";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "58ac5cd9e16a0d35fe1fa365458e366cc0b08c4ee73ed4305b1f2b2277b034362a244f41f21bc17f99d0dbd704cb60c68242413a9d3931808103f723d88774ff";
                sig_s = "54586ef4cad8f9a4438a873e6874c3e039973d96c8be7790bbb8882873543bcd978380c6da4204bf1ec518365a69af8bcfd50e1996f2ea72d8316238ce3fe33f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "73475e6127e457c71f0063f43d20ef66a6cf3474abd0e651fd1b295806da34bc687a19e72255cf651907214757d89240ca7a353ac6338a15455312dcbced3070";
                sig_s = "43b18232dcdeb85c8a66349f71f8a48629d7a1f395f033f210a9f6bb2c1e0642a5d8d0bce2c44e7c118e12e216ffeee8e25aef5d9b25490b30ac512687030b70";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0518ff14ba05188abed0a8c88db0f097b5660aac57e9a3cdbb9c833e2a7f9f613e49956b53a635952e29818e4a8015cb6a150cede636c2558f2d3602483963b9", "009ed9fe842f3ed418462c63e266944ca2747e15bd8f52844d6a1ce9815210421206805c6ed792356ec57d79fa3e36fff23e2fc6370c67bc51d3f8b555c9048d6d" );
            {
                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "6492a8b0522069df794128a0e9a386285a28e2b916dd80a60d591420ca286084f12042ff91647211bd3f1411916b4ccccdd38feab145a1ba629c6c304bcb9460";
                bn_t sig_s = "6b3a53cc89ae3927e94c7ed47add89bda9774ad0322eb9a8963ba4abcb9ee230ab21c34fcc66d08b089b1da29a29a293c5cd2ae4d9ef7378e88a142b1bb298e2";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "91753b4cf3e5c1905a28d61d8ec2a54e8258bc30b6744e8139e2e45b6ccdf35a8a28741b7d36d34383f7c10067730b2bab86d651ecaf4e9af42a1c957224af4b";
                sig_s = "3fb9e0dadacb932a60bc962039e0857bde3efef3a4f85587c733e998ff44f94b54cd7c923b158df27b13f4c2d45791de9a67e7c9c74a9a5148f4bd886f777620";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "082bbcee682526e5c2607206f3b671f9a59047a744b3e76b45a218da6a2821384f53f9081a3791b3895afcfcc3a95bda91ba9a08310f8d6e9969839e0808fda6";
                sig_s = "1686a56b7996d747ef380a623a7d39355b4afe82846a0f31aeff74c67369afaeade1019278b73a1df96984a0f78e2a93d1dfa963c8ff5998f8418010c9c8bb90";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3f89e787b4d5d2599624513530e750ab3c5957dc9aa0e7b08a3e25356818e2037d062f336d4eed417c91bcb11b54b57d54a4f02a72fb74262f742cc6f3404401", "3a448b8e2d0d5a7c5b4f1b9f5b701a9d21ff55e3678ca119b6d7c511ba0aef89f31aeb195db00f248359aee924e7c860b76845f6512a2a4aadc1287a15095220" );
            {
                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "61afa0a615778deb6bff828dab23bacb1579956d03a67d3668ba423614385774224a52c0ea4fe6280e2da16a9edd682eefc1138b9db66980bc4e2128099b7e7c";
                bn_t sig_s = "1165718671968ac217e622df5cad999fa13b84ab499ba6bf6eee73793952272526fcab42259b0b79bc5fbef21d8a905ab204e061c7165a566747ab126db25500";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "28d0f64e58b5a8eceb0137789938a91f8f1d67a827b78517771aaa2bfa2637c89dcb52c55b6d314b98d79f094944c7cb39b87528731d25956c6a1fbe2e1a444e";
                sig_s = "8f9ac999387a212ea1013af5506efdf82bc48c2546fe3b3c981ee92dddbd9d6a270999751a08304e3993cfd94e95362c6a309d4efb23a4cfd5ec74c8bd1ef360";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "83ac5018d2d61f498d6476b79a0d34302d617d8e599b77f01b59427f16ef16bb2122f2c311340258c4214c04d3a9fab263dab78293690e6d20bd80dc23d26ab3";
                sig_s = "75c3c9761a876f288fb882763d30e5fef5a6f78d51055ba3e6409d68b9773c0691303edb0b54eb612c701a80dcece8e789b18316a24ec24d269fa763f2bba7f4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7860a4743bb48e7793c7f1416fbac6ca0b538210d743f24976af3efda97f28bc95913401ec4ca5e744a23d1a552653ff110ec8421b3de531f3bacda07bfb09d6", "03662f2f2475bbf5e20da48b50169d289c89c54ed0f97bbbc7f38016f1a955cb74c52727ef802055ea090fe1a49be58ddc6083bca3f7c02ff644775cd0027f06" );
            {
                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "0521fe837de37d3693cb79b6fffa29fc56d19ef8a6006acaaad20a6be426dc7e54ce2d73c9a92309bd0cc90de50e38fad692d4d25b676bb72dbd0722b2b239ef";
                bn_t sig_s = "9648e29cb30732bf04591989adf1ec4952bee64336994c39633b07af09c691b9c21c9f66b0d6d1919678d5b95626a20037b53a795712b2fc98419d196d5d4679";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "aa4574e2c4e0ad717ccf41911bdecb0c6d828ce4354fd3ffc374c77e70b40fa7e761c26af250642a1e6433ec8794335fc455249c3b252968748f6cc2ef055824";
                sig_s = "08f1e9a509ebcd609518d9b6ba20dcb39447f9a4773be27b12777c3a22732be27cbcf500555e1d20943f9111a315594be55c9df1d2a7eccf7e3cf12de1f46f5f";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "6d33308ec4b9c24a16087c9787c638ad940f8573e8a3b43efa34cdf8ebd16bc32bc96738c993004a6ac4041277e80c2182745dad23355c1f3a9084d1e1ffd885";
                sig_s = "4bdf5d90681327fbcc38d8e15c699e6928b36bae1c19a13879e9224177e013fa1e8794e609065c48ffc5d722c031d643864fc80d6343a9018fc85d5c4bd47e78";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = sha3_512( m );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP512r1_sha3_512_test

        // Test vectors from Google's Wycheproof RSA signature verification tests.
        // Generated from: 'ecdsa_brainpoolP512r1_sha512_p1363_test.json'
        // URL: 'https://raw.githubusercontent.com/google/wycheproof/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d/testvectors_v1/ecdsa_brainpoolP512r1_sha512_p1363_test.json'
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
            auto pubkey = curve.make_point( "67cea1bedf84cbdcba69a05bb2ce3a2d1c9d911d236c480929a16ad697b45a6ca127079fe8d7868671e28ef33bdf9319e2e51c84b190ac5c91b51baf0a980ba5", "00a7e79006194b5378f65cbe625ef2c47c64e56040d873b995b5b1ebaa4a6ce971da164391ff619af3bcfc71c5e1ad27ee0e859c2943e2de8ef7c43d3c976e9b" );
            {
                // signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "0bd2593447cc6c02caf99d60418dd42e9a194c910e6755ed0c7059acac656b04ccfe1e8348462ee43066823aee2fed7ca012e9890dfb69866d7ae88b6506f9c7";
                bn_t sig_s = "44b42304e693796618d090dbcb2a2551c3cb78534611e61fd9d1a5c0938b5b8ec6ed53d2d28999eabbd8e7792d167fcf582492403a6a0f7cc94c73a28fb76b71";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + n
                m = "313233343030"_hex;
                sig_r = "b6aff6ed23b6308e0ace840e7557d0366549da44c23127fbe2d3f6771c987375223c7ac494ef54fd71ece3546ddbfdc3bdc4bd0a1659446423027f0e01affa30";
                sig_s = "66297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 256 * n
                m = "313233343030"_hex;
                sig_r = "aae97012103190f7429fe04b940b89dbf9caa70044d83964c3700d241cdf6ddb5a0b5a5fcff16c4825b6c79bba9a40349a51e66a916bd6473bf5116b280e0762c7";
                sig_s = "0066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by n - r
                m = "313233343030"_hex;
                sig_r = "9f0b4484941d588874db494df23c27d931174122a5627c21c9f3431dc3cd9d6b88403dbe0462f735111fdede917c22ca7d9ee9f7fa627157480cadf737a206a2";
                sig_s = "66297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['ModifiedInteger']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**512
                m = "313233343030"_hex;
                sig_r = "010bd2593447cc6c02caf99d60418dd42e9a194c910e6755ed0c7059acac656b04ccfe1e8348462ee43066823aee2fed7ca012e9890dfb69866d7ae88b6506f9c7";
                sig_s = "0066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced r by r + 2**576
                m = "313233343030"_hex;
                sig_r = "0100000000000000000bd2593447cc6c02caf99d60418dd42e9a194c910e6755ed0c7059acac656b04ccfe1e8348462ee43066823aee2fed7ca012e9890dfb69866d7ae88b6506f9c7";
                sig_s = "00000000000000000066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + n
                m = "313233343030"_hex;
                sig_r = "011107186cd1400fb066d93c809c69d2bdd295a3142181bdfdd2f593d44cdab551e38f64afc6c8b247c733dab9d241a0bee33f14c1d651a63ea1c2b962a99a9561";
                sig_s = "0066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 256 * n
                m = "313233343030"_hex;
                sig_r = "ab43c7338fdf1ad664fbeb0406329bde8137f2c9143789fac5602ec17a0fb01d36ccad49bb2345a5700c0e931ffea5d7957760c2492bcea91673d1a57cb5f1fdf8";
                sig_s = "0066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['RangeCheck']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**512
                m = "313233343030"_hex;
                sig_r = "0166297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                sig_s = "0066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // replaced s by s + 2**576
                m = "313233343030"_hex;
                sig_r = "01000000000000000066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                sig_s = "00000000000000000066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8";
                r = false; // result = invalid - flags: ['IntegerOverflow']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=0
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=0 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=0
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n - 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=n + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=0
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n - 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90068";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=n + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006a";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Signature with special case values r=p + 1 and s=p + 1
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f4";
                r = false; // result = invalid - flags: ['InvalidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // Edge case for Shamir multiplication
                m = "31313138"_hex;
                sig_r = "7da11e5b4bb7932135cd91accef8892c4286654a7be7c9d384b600d97900ee12a23ff1f9ae9a4fe74cca185d0dc9f59dc24be03d0223d8feb55b6dde1777475f";
                sig_s = "0686bc313aa5c1923ab0543331398190ca5f22a3a97e963a13cedf688da1dfe4a348945497b21c01c8a17c23252b3e8eac1f9a92d6320eaa324b44807c326175";
                r = true; // result = valid - flags: ['EdgeCaseShamirMultiplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393439313934313732"_hex;
                sig_r = "6d87be05958ca5c70c5d296291605021402deba1772f31bbba09dc65a837b09a78d332b6162a3201ca1a30d4162d8f186b2bffca5302333aca14894d5f093fe7";
                sig_s = "10b8b3c90b4609ccbddded275d4249857d882749e4b836d017dbaae05e3a19cf7810632329a02580dae44136cadcf06ca57dfe560e1c1122e2ec00ff04d7881e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333637363431383737"_hex;
                sig_r = "23e9bac3f14d56679bda0bb2f4f19eecaf6dd503649c81149227880f14376d0224193d2b1bda4b08f87e46687dd9141278a399f0a3cd0d002f236d0e7d7382b7";
                sig_s = "9c24fb2128d62e5ddf59bb86b3a6b787b10cc75865e5aeab41a84f878ab3a947a2f6b4b0871af494c130f58bb3957ce03d61373f3fb5cbe97ebedc1b3aca174d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363731343831303935"_hex;
                sig_r = "2d07d8bb6277b78fa448d52e3e1d901ccbdd682930fca9d86959a63b5a792a8aa82ff9bd7da3e4057f402a76e82836aa3da34b6ff6bb8b2189ac242baea2b0ee";
                sig_s = "58ebef50ea30d15ac26fa03e2b065c7ba50f331a5cf240175ff3a6a1d8db400e1597ce675eb32f269b4367011acf3276580602eed7c2938439772e1be1b938be";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323037313732393039"_hex;
                sig_r = "0d6743a7bc904a21d731205fcaa7fcd0018ead446ecc9bafc4532bd0ce6bfa6960159f59b5eb37c750d423c4fbcfb20a718e5655d517b74fff8986c9638f4f29";
                sig_s = "0399d7941fe5f3f308afb8a8a4ff8f2bec1bfe6b910c8399d831eb6221684875f67fe6a2576c86feadf3cd2af147297830113611fcfffacd8a8c8c52cf957ff8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131323938303334323336"_hex;
                sig_r = "aabc4bdcc44ceacfe03a96a7939bf08c407d300de446514fc964de4dabf29ebda0608c1709c72244f8d888cb0e556d75828756d11c11be7787603bffc6718ac5";
                sig_s = "81eb84c8743ad6ab78a021a6f55b3ae0845f18307ea18e771e3c4e11b312eb8e530002c95cdb517855b17ea9726ec9602f347e789fab42055e688a558e3fc98f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39383736303239363833"_hex;
                sig_r = "4e7f75681dd7cb2eea022e5b86329b25307c21b828c7416916cf1f5938071519cb7da668ec6bc219e72d358732f1c77abfcc61065aa3239419089fabefe396df";
                sig_s = "4f9ec196a71c5c8ed88d7fe1d0038f372ac60bfa180cee2498aa9c0248166f17382368fa2b3b8ce29d50d7a21e91a83ca88db5d4efd073f821a8c5aa4d26675b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3230323034323936353139"_hex;
                sig_r = "a0e1c2bb33200254beab5e735c1a2c590fc118540301add7e5491701d22c71293adfeddf4308940fd8a066222ccfb3802eafffe03b2156c8e79c3260d180b3b8";
                sig_s = "9d8482127f22eca10b2792747d6016ba719965603ee8e71f2a39500a2f211dcb2da582d5dbd0c6a407155e1b01085b759c80971cf185fd0a26e3889263a7f2c0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343531363639313830"_hex;
                sig_r = "2ee9ca54e2df79d6e06f130189faca801ccb081c43472d4f888aed892df878d12ca14c8e800fb7a75c2290a028fb7d12936499c3010bc5c7c07b2f738924766e";
                sig_s = "558c02bcd13290ff34e039a199384385a44f97ef9a7dcdaa0faca66357ec7b9c1b40ea7a3529f4bb796fbddadfbe64d3e6abfc54c2946f5b1f548fa0877f3ae6";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303933363835393531"_hex;
                sig_r = "54f45f0bc30a889a4fae7eaa047ea02ca0b9e387d6367801f8bccec2ec7c0ff89d6603d70f7c8e055e59fa69905b185faab437779d62c4d2eef4b12a90c20ab4";
                sig_s = "43c2ca3205a7f8b61f64661d0fe746bd23fd0f264999310a56b398048ad46fbab8a5e3b3e2e16c4b2f03f101573e2f6593b64accf319dc9e2e2e847b06fcdd31";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323139353630323031"_hex;
                sig_r = "8a030fd4ba48d3f5998010c764e869211a4ce33122a7fdc7b8df26763be180f25e068db6c92820be641b8afd178a803360bd197a86cc8ef76ca008443ec4ad63";
                sig_s = "8037c3a2c1cac26e6ff89894a07b3e25f513680fc2e46ed693df96d0ee85b9400cd62d723fc98adca2a679fafec9db5fe078f25f9804e0d0ce16d1a432d194ff";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363832343734333033"_hex;
                sig_r = "3bbd1997802b5fc5d4f2b87b6cddb97529cac1ba29dd29cfff7315b787116d9d3dabddd1b4414995c2269906a7bc1959a06de5bcd4d563042e1741af009cba9f";
                sig_s = "51b3d435efe79573aca8efd3cc1c8a227ecd94eb4079675459b6f4f168b6111c07c633e64e60d43a5f3b0d0b2f4371f68c7cdeb6bd8fbbf3bed2effa2542b0ae";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373336353331373836"_hex;
                sig_r = "8293a545974430b3d7f7e314ab0ef48731715a5f79c2f34b94f120fc0170397130298803778b532ff10020db060d19d931d74856fbf330a75b28416d45af54b6";
                sig_s = "2b8db48308c0b1f621e22c7dc1e762b08508be1a8eb4355f6f9ccb842085a1f664d7b68b1a24bd88f17b16d141b0c1c3a5d7f1a7ef4d533b900d1853bc5a6f6e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373935393033373932"_hex;
                sig_r = "525940c217986b7ef0e18c81fe10063d65dbe1809d726c8a1aa0b617f334891e94c5df14f7b944a1639950a43e98eb6f1c349121d107f91ca7142b7ff62ec776";
                sig_s = "6b3567e4965f2d766fd07280f31f8c77921265f00e719c7c0055e51c85e1f3d46ac93967816130a6532c902543a530e27b4197cfd1478c90ce1fc74124636b73";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39333939363131303037"_hex;
                sig_r = "205caef78b7f0300266108ddf4e28b6ec1a2198b857f92b2df58a6d968d3db3ef6469f7afc20c632219ac43139ea08476e1658ad145ce8e3973c674ba8173efc";
                sig_s = "4a7a5320e5e249c3ff54cf903bace86f39b620acc19007413cd13a2df0a1f5984e7a4d18cd8d1297560295d4183af1857bd8e6e338aa3799ca1550635e4ae006";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303837343931313835"_hex;
                sig_r = "89f6e2f342b4bc2f004fdc1d0e24a7d1d4cb6b0032b8fa2f50e3f90f3880918f31aafd5022ff74bbe1cc64febabb3bf33a8e714f597ddb0be8067d8a0964dfe1";
                sig_s = "3ad67dd55364c29d4a5b446c646f30bc5e648a889ac7b1bee49b71918c32554d0d95d5a57ef5e7f4b267042fa3025f1323bd7dbd1d60c44e325d4f78c65a4adf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323336363738353030"_hex;
                sig_r = "2f3052550c595ed8920a7994b4adb78b8f7502fc066ac47ab4ffbe010d4a5e3e54545279a747d29c61c7d2856b8e47d0040e0713bde50e42e038dfd5af61e891";
                sig_s = "54f8c58893f19fbcf010d227017b88a49cb6fd1ee6ab883d21cb58fc0869c37ed73c7312c67f5ac19bf5bf0abe4bc836ee35b2a2c805c3953c48e79ab8665aa0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343438393937373033"_hex;
                sig_r = "8e366955ffb2a7fbc836441492f74cae4552fb0d2496cfe7d8c44b9420290947e29bf8a88265e2c6cfc37d29d2bbbd3d10513e0895e73551e2d7fa80d0697106";
                sig_s = "6311528152bcf6121733867b61fc523e7f01bd15009984ea30b17ec15b8240c13f1ad137df37de4a32f6e3b93bc190959de17a1ba3fe71b03e97541c90a84939";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373134363332383037"_hex;
                sig_r = "38a49f5f88f99e64074f0281ecfab9b8bf02092dbc11b87041bfb561b4b3cf29945ab5d9dc45f1edf41606ef6d2204badb67611584b892993de27e8f6402cd9a";
                sig_s = "97e2da758a8e377a7d682f50b0e30f695a6f6c53e6714243aa9d533b4a9b9877d5d50af3e7a4f1fe6077c7ea704b918c599500afb84d0ba016828aa2e6fd132f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323236343837343932"_hex;
                sig_r = "6de29d0b50950a6409d29d2583e6c2d77389740ed0be4ebbd4571e82b5303ca27087ce1327832e9991cbf73308a1baedf97d1f3af9edf35e27c15a0cc003d6aa";
                sig_s = "9a19f33ff3a88ed303fff90535aa1605bbdc006b803a804eb1df092b5aeb9db1be0cb9b676694503e36d2cd3868db0c34896c94cddabd54ec95ffeb6988a7fc3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333533343439343739"_hex;
                sig_r = "170f01e92b69cbf0d3d9e4a5740163d7ebafa7bb8d3835039f140d075e950dd57dfdf1b7b8d1678548446410468cf2898e130c745e07ddff921c5542191caefa";
                sig_s = "a7b5d928be42799a55b05e15758a1aff02775af9edc214214ca89f73ad12017d672e59cd6aa54f18f270e01ab4dbbb2f748c87cbc2ac9081df2e76524da17711";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373837333033383830"_hex;
                sig_r = "8bc089bccdd8843c06d5a79e386c513af51931660db8b888bce5b5bddbbe4c73956a9acbc32e1ceaa5053fc39308dd6451e6e403ca574310667093c6d789b980";
                sig_s = "417c966dc36dba5c13d96701946c86a0683805692f24c012b1a7d571405efd850a997065b19d35621bb4b39c764933849ff7d8b8f7df9fc5048b598ec1faeeb0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323332313935383233"_hex;
                sig_r = "8fabc939e7a6c13ac69cdd47f996248bfebe3f8e80deaf9c35e5a5cdca086f9f81661a1a41f69e3595b055a514d57efb2eaf5c1525dccf21736d2bbe89a5668c";
                sig_s = "a8f9b171b3d33898cf7eace35dad6c3fdb998fc409fdb708338f20c9e4b8297b375485a5e87eae6fe68b1139b1fb4a3bfa250f47045f12a5fae945a2abe70c50";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130373339333931393137"_hex;
                sig_r = "26f405c9cf5afb29e3f60de672e25016d39666f6b34af54b74562d4ca9e03dd87e2bf020189e5d2faea5bfbae21adece9f210bcb02a7558dad1b73d78b0532f8";
                sig_s = "2b4b0c35057b9524e866625e7df820e15c86c2efdc1cd6c4c3cd4e6eff5d5758bd7f95b8f77e10163ff65b380eff970caaa7ed3bd0a121d3bbff3b6e7a261b75";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31383831303237333135"_hex;
                sig_r = "36c5c4720d10a455f4952a95872cc69e5c48e9689a6ea6e3e282c9cba58b01fa3cf64c9c99a6003d424895b996e26072ab6e76b29d1cf1dabc2b276802358ad6";
                sig_s = "81a9e6b79f8055e2bde4365eac153df4003d487b589ad3306d4a49387d244abcdaa09c1b63f0877b15468fe3e14dcf4cb63400a99fae7dce5fe946548e64abd0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36303631363933393037"_hex;
                sig_r = "6e684611327cfcd9d40e5252abd3d48fb735885970e9b3ba3f55a10b3878985c548f0c5244619676a0e5c44b4c9b1ccc1a20acce42e50d4d1aeecb4aa6d87ae5";
                sig_s = "7749fd228293ae527e3d30de8f6fae99151e38329a1094c92b347209a4f7b69474ac90f21d56c625f1c76ab91b4c3d12a2bf4ba2826cf00adfba75368ef50c24";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38383935323237303934"_hex;
                sig_r = "887fe53394545f107a27867df02fbc1f5986585a42b52195243a0fb7d1e700bcabed301caff3ad8c2af23497b2ac027fc186b8aaf4e6512bf5bea5a357ad83fa";
                sig_s = "a923a3b4afe30eae49b018766da2913c6647d7384178f656d40d010fe1147d786ee50932286c813ea40e5c11555f6b8d8a6f8275145cb94cc041f1cdfcdfddc1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353830323334303934"_hex;
                sig_r = "68d9fb181a8450ae377dc750f3bfbf82cbc39347cf5d2526bcb6c3f6343a7451065cb4a7b2c0ed3d68ce320d9a9c35c966c05bbf45b1acd2cfeab33b7bbf176d";
                sig_s = "8538469e631960f5e13f6a3cdbd5cf6e893d0b154f43032b1bdcdbe2c5ff5338cff5223a1f0eae7ca3ed39232219c848fa75b0aa18e318c06abe474730e26edb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33393635393931353132"_hex;
                sig_r = "0d0d1eb2125eafaaa47d2e30e0650bc7e5c99f4fb5be1473708d19a991f4cfd1fe319ca73ed1a8b59d4c00b22ee0cda9bb2f00e78f13bcbf372efc0a003d2d1e";
                sig_s = "878e71c2f5d53ac07b2ea1349110ffac6dfdfa2152d3b9fb662f6f9ef4e760dfabdf81ed690e85d80db3213481dabef6dae14b20c25f6f56a360ec9762114bda";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323838373332313938"_hex;
                sig_r = "1c75cfcca11661bc91289b25990a2c836869a2fb5bb61a5530cf248918db45883273d8d9d24a492dccc429480eb9d843544dfb8bf96ea75f06e4caee91fc3c5e";
                sig_s = "457a98f6870b4d131f9f769229cbe93e9761432cf4e22ae0f4b35c55123770336784060b747c34bcd3bad3f8970718fa88777b2b565da3f32498286ad00153df";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32323330383837333139"_hex;
                sig_r = "96bc9787cc6d512a2fda9b3498b04b53f9c03f4060ab0382be7cb7077855196e60e0d150eaaae6099acb9341a15d06c9478afc445021a5ef298f1498bffebd9c";
                sig_s = "8db26e51fbf0d7a5eabc67a7f7dd698d16a97643784d49c7f292481114a01c581fdfc6f779b1cbccf5e8ea595c98b760c3c5a10ffe1e6e2cb101e1a5c8a14a44";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313239303536393337"_hex;
                sig_r = "06e20f468d6fce4b5571d6e188f10cea05541d82c9f81791d7e7b2716d92dc57494053712b0b01b346e5797243326db92028e80f1d8e0382b1e63c4d96daa9d9";
                sig_s = "2155eb2364926fc34797923125503cdada9983e6251273e5fe1e0298e61e26857dc412190c7e677760569500f85ab2665b6e88901be861cfce3fa4e2bda55429";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373438363536343338"_hex;
                sig_r = "1e2480c56be72a52fe00945fd7c2feefdd03bd713bc3e3d6e6d434d5a2a7a2c8e1b47cb1428b96f4d8589d6ee5fb32dd7d0a767790f8209b5fd3412c0d562579";
                sig_s = "3c0500f7531dc5f0040f0bb0f533bc5bf344fd1f325a80c420435f93d3ca7eeeb15b1a4f4391408f166971c9ddb79bfb68f23c6997c2ae40d66cd0f4fa711217";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37353833353032363034"_hex;
                sig_r = "774d852a1df9f3b530db4d0345c3f7c413c8dc4df1c18f4289cbdf39de2d9eb8bd90ca7803c2b3fe8a8eb9d804dfcf0d0bc79211ac199da1c09abd80b0f220f4";
                sig_s = "70fd03a6fb63582bc64128758cc8bffcf5ba0bf154ed421b37e95987d4647ed7a3ede5159ac175f7370a2e23fff645105c4e0d99ddd1486ad6ac5a832903d55e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333237373534323739"_hex;
                sig_r = "2e7f63da657a65105287c644cba07b0f986b4b2f3a18c0809dcf8d8ac2169450b2067cc5e0ac3d65e1eac67f3cea3a62c723eee062d30757dcaa9e926ebfbd00";
                sig_s = "61b262a4aa850ba12e31761dcbde8cc7c9abd48852a734b38b26cbb153a80289c4788389b16baf101f6c5da8eec6d584d0ba883e53b6d7d2afe36db83ea951a5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373735353038353834"_hex;
                sig_r = "9b0be1eff11d16b6c480a0e17c5f3471eae4fcaeff92487209f0f23c57a7dfabede9756698efc625c77935667a519e42062e9d087842c83e08b976d3b96ea6dc";
                sig_s = "9c9ef5e7760a036bc40ec710ba88e9ad6f8e06948dfa77a26cb8fd6c3b87112dc0d0f6ccafe08fa5b636f429a097af39d569433c933f902516e85871bec30107";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3137393832363438333832"_hex;
                sig_r = "7396b49696311d10da5c85a3324bc07b855aded9f556fcef6b3a157ccdeecedfafebfec27e9b764acc84f0ab137ee3016dba85f4564eb9b220641e73671f8509";
                sig_s = "34d85eae9bfd43890fcd2b0511aeaa7534a470d4a610fd592acd0e01784dc6be4ab0fae5ea6faeb6c17a5c2a84dc75b91a05173594f6212f2aa2160f229bd096";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333936373737333635"_hex;
                sig_r = "24dc7d0aa89ca22dcec20248f6706b6209583236dba3bc326f29321c5bef77ddf4968e27ab2dbf1882de2985e4901c03dce539d0df1716097ea207fae6b61140";
                sig_s = "6168c1277b7c881766b767083de4f4df82af8ac407122295ece58fa49cc051308848dc380675800a4a4dfd6b813207d8d0e422c232f30bdff7df7d89f427c194";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35393938313035383031"_hex;
                sig_r = "2d47ca2c03adbff284031e2c6315836397ba34b7605057526b159e6975ee660ec809ea15f552087b2ab5bd3f718f8f82f9e9ee47f10c7e96cb06a5a7b4b0247a";
                sig_s = "3cb1f5681e4ba1b05b5c9a2c03f0d6bd839ad5bccf4be2ea085b6db5516037cc5d36faa83c67a17cf73f8f75e50ca33fb7591cf24f9508a7eed61314a47d9e54";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3136363737383237303537"_hex;
                sig_r = "0af3273b4119624979eab305a0f83e5136ef6a56597c5353d8d76723529403995c45f3a24bb13ae85d3872dc811e008eaa2c5842f49a7c2ec68dc7cb4f33ccc3";
                sig_s = "61f5b236334964eb3ee2c6c6bceb9f2f8ecf0644ce9ca723d598e39472e3d39a993481d27c8df5df2b781d6a022ac489a9199475620d4bab390a3fcb6bf44941";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "323036323134333632"_hex;
                sig_r = "9d54ccdcdde1b7b11fa6a70fd75da9a2387aeef94882506eb898d7256da4d0ae2ea0cf54f966ed350ce474c74f00aeff42cc16064b069b8a68820ba557b534d0";
                sig_s = "9912c602994781606f987213b4e1e056f3ae17935da059341bba17484ac62e32f2d04b3973275e738876ebb16fa1465f8e6bd26019d96aaa28ccfe94ab7ea94f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383432343936303435"_hex;
                sig_r = "7f7b14c2502a2bbf3f7d1829012637a1e46311efb1b87db41304318250d0d1b2552d2425378dad4bfda6ef1197d7b9846384acfdbfae036a5f732e9497c8584a";
                sig_s = "50693eee71ae5d706105d819089ac948b3d7b4151b0af55436899854d9cc8b7526aed896ae1f3dddfe301962043f4f3ba140864ef8d1bb6d45d5add1325d848a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323639383937333231"_hex;
                sig_r = "8c33b1623e10e2f51edc0b96862cd2eaf5faee8ea6ccc985ccdb94bfb141d63db251faf1e7d69ed390a2beb71185db4029f07f03af4ac4aaeaf48af01e6f2420";
                sig_s = "55b0365b12f7d640f758e5af6e2d6a41fc5c56c80598f7bba0990b0d899f22cb634c22f64d7a1e970856b3b31bb013d39f761d588ba14a9583f8387d91d058b5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333837333234363932"_hex;
                sig_r = "a34ac9c077538c21f92ab4bf0dd40d9fabee1f409e81cce71bed23d06ba72eb15b7b7a96fbe256bd0c41a0d5e3f0748996c16d742705d9a06c544a4e573c3597";
                sig_s = "4500ed995c2608dc62ecc920ee560590648100e5b89e7f109a2c15a851708953e699499c987c1e9523f9d8985e6061cb9a84e58e2c26579bbb084b9d5d71f3aa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313138383837353336"_hex;
                sig_r = "639a6cc0c3e50f2457f843c40f1714096e61637c78ba9d847adf0f6b2ece78adea98dd156a91638eeac743971f5d469506fd19e11555fc55fee3f82ae7b05b8f";
                sig_s = "2427b3fa238430e0cd794f28b4e0f2c1d3c83ab6fd00d47a4c630f5f072f961523cd5316b0f8e7a1387727e330fef692890a472495c69cf216727fba3771ad8e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838363036353435"_hex;
                sig_r = "61949220d668cd59009b0069607afac3a3be3866f50b0c3bdbd98e9eb306082b23136fbe6173dcb6b8d34e81a9e038e8a78071635b7bc4c787efb7bf8a8ba12a";
                sig_s = "8426f68e8c7fc3e8bea84d7b56aa2e6bbb2b063e320ecd520d365a066d9240f5daa533daea28d99ca1ffae9c3b9b0e7cd28d7421ba35c305c891034867768b1f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343739313135383435"_hex;
                sig_r = "47ffc9cdf40e5580a4a938c3727acf8c37ad638b11c235d05e44bfb0a680a3c6eff57901541be0c60246749f1f0071a8594ed6eba43ea1f92668d54d938c98d3";
                sig_s = "1521ecb3eb408c9860b83bb748afe306c35b93ee6b9e1e584c98d788d04d013de691cafcd0f5d71fe3dc6c8c77ed03488d8b92ab2c2e007ee35ad02c4ddd0563";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303736383837333637"_hex;
                sig_r = "64638c51af9269fb24d8e0974102be6e94bceadfe9cea1a9c89fd778010891845d26e5dc7a0fe7f0a6ea9ea0c1dd7c905e8ce43be648609eaf8494f06050b550";
                sig_s = "9ff2abd8319159bf51c6f3307198d3c0500ad8674f42a91678317342e82ec0781d4310d618694bd8d074650ae64910a24a03598f00168120e530aa60317ad470";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "393838353036393637"_hex;
                sig_r = "253d7aff8171372196dd152ce3536e65ff00ac3feefc32d790b6ddc85b0cef074a1736bb473331b3814b2f69d20e90050ed2d3ca125735336d15f9c012e289cb";
                sig_s = "3850573a859b7f9b153fe0d95f48ed30877eeb34ffd30e9980f4c42c26e9538f7edfe50d52f8e453af03d4554bca7ab2b3b98d794a317dda123fd31e4ea706da";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32373231333036313331"_hex;
                sig_r = "7482b5e6bc84f289be96ff9c01ea2df632cc1d23b988f953264100e8a212e77c836fc3f66071d9ec6254341cecfcd8aaa940cc0cc1e26077f3c0a1a855e30c51";
                sig_s = "328e8a1fc140c8791b9d17e1e2dfdceb969a21d2b0245b1cc20766b6b41a2d6cdf9609dda1b1d2c2c6c385986e6c6facbfd68a674860f48fb8d113f577ef231d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323034313031363535"_hex;
                sig_r = "6599441c0ed9e2a82f5f09cfa9627b25d50195750723ac18907edea3b588b736deedcdcd0aee44df73f5f364e484b9949b7d7b698fde043e6102cfeed69db469";
                sig_s = "40049f8dd6ee0bbb4b9a29f2eded3c8bf0b10c8bd3be6bf5e4f97f074d716865fa824f51fa79ccfe791d5df6ad7fee6bad96ac5bff21a502f90ab80e211253db";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313530363830393530"_hex;
                sig_r = "74e11c74d4139eb9e532e583cf3edd0b9e0e7b6e82a3b79d8200e8e581deb71b153b961646a76320339f4c1a5f75a638ba2b0c3f065ed856ad0a158e3235c70e";
                sig_s = "6ff940339c0449d6e2403730b58d0dfc8de79bca0df06c5a6d437cc2c1266a468a8aca2a2903c29979d7f4d4f7871a106b31ec485c28cab62eb2100198871b83";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373237343630313033"_hex;
                sig_r = "5548020c2a0764524ca543d08e1526ce1476ba976af8d6150d8d2ae47495e5fe68cce98493b50304131df71c1a3d4776a77d5ceb74e47b2a8e650108ebab1428";
                sig_s = "620e2dbf67215f95fbbc92a992f20a4e7f301a2c3c3880b7e891ad484647a97aa00aecdefd03155207a9e459ef745a9d29a54b08f47b81cadbe4bea457eac6d4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134353731343631323235"_hex;
                sig_r = "83de9122ab462722939d851d456b9b022937be85b15eb65d2ec1a48410a2f234e98140f208ed595de2fb5073b2ea494acade8dc5a44ed7162cfe7a70182479dd";
                sig_s = "2e0c938f56533857956e56d79c78fd101ddecb1a9695a56f18f6a89b94c0d3db47429afdde6b682832bf4c0fb849ec7faf729cb59d8e219dad70b7c8e257ff14";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34313739353136303930"_hex;
                sig_r = "8d42b3bed0202593ad44a93b43ebac7ee0d9ec1dbc5c546619d5a9bfb5c9cee744a445873f10539b51545ea787648dbc44ba2d27f91eeec59de92f2d71601553";
                sig_s = "985ac4972c7b1223656dfec796cd3352d91d6c83ce330e1dcb1ec9817399340d7ca97457af51c19c6fd0787e6965d4f85ede5c7f507598b8bdd5c808db459e73";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383932373133303534"_hex;
                sig_r = "5b826d16040e448dfb70195de16e97454b133aeb1051373d5111f10814b7f4ad1714b25c0c5661efee43fa9329a4af09607eb66c72b2be2e21bb4d0229e3a1af";
                sig_s = "07f00f3935566f4ca16e346ef5ac47b2953fc8b5cc8870ae638c55fade1b586b37a119015fd7be3a33fd39165564f6117435bc1a20bfd57406608b3b27a91be3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33383936313832323937"_hex;
                sig_r = "8f89db5a6d6dc6fe96ec5f95960c2f03a6a072e644d158247d5b8b66e2346834ee11e5ede6bf9e8e0234a7f75ce8644914c585e0953d371c363e2f21feaa2763";
                sig_s = "6601d228f4b53dab1546ebf7673360dba5dc3d59c953bf867c754325c0cfde85b64505fc995941929b53c5566b42f034ba1a09ed96e113961a1a7357a22793a8";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38323833333436373332"_hex;
                sig_r = "7e6107bc6e5f0d0958789e4b91201ca19d93c12bc4194c8316c2224451f5748bb6fb46497106c613b07efaac954e2ccb21062005b9ef4ea72ce4471daa5a3ea3";
                sig_s = "7f1837827727685de8c8868d9425db06e33f6778b3b4d1e08e5f73e26804a142723a3d68a7d75fdf826e79f791f7a6b0f89a36e579cda9196fdd9f6419f71ccb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33333636393734383931"_hex;
                sig_r = "3539944e52d0db1fe5e9ca3d4c8d93139a2d5c85e51960ed68e8fb5f29cb108fa184fd66864fed2bd90e0017925c5d543d618e287de43d22f7a94f17514f85aa";
                sig_s = "060a37da2753925c18ba4b97c95d16ce574ce9542e918b4ea2e7f3890e723a375b0c7ccd497cda6c24111503ff948ee1b0975b90b21c0747f0b4bfd354e2ea36";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32313939313533323239"_hex;
                sig_r = "1339cc85b910c82c7d5a0604427150e325c458cb2de1cf27194546db13cab056c021f6a78f5505e8bf6865f29b36bf67a3c23000617e35f92c8736854c5d72a1";
                sig_s = "8018936e27847ee6819b10458522d78991cde9d08b5e85f2e339bac6ba9afdba19a5c99e2117752345bdaa7a71be57f00e4a2d8db088f350721853f6ea1440a0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35363030333136383232"_hex;
                sig_r = "0b62b76886412a3e92180ada31e86c28e288659ee71251b5fcab69fbe3a3ea7a9ecbe513ef2f7e0900738250d2818d255b838dc092f045fe5f90e99a6fc48c20";
                sig_s = "75255debf55318a265511e3f7bdf647c88dbce185ae139050c437154fc4dee2786c440b4f67528a1a343c8f42057e9bd223df64ce757081dff7f16a784ef5868";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "383639363531363935"_hex;
                sig_r = "02517cfdd22c2be4c62ff72f0242f844cf137f230b41bd1b968426d75fd01f2b467a3d3dbae156d19ee33498070a672794129965064514337596d1bc66481a1a";
                sig_s = "1e40509a671fbf9638d1d2b242f3041096d6b59d1eb71072068620fdf31953b20a4bdebfb08d248f0d7e34f053e634f43aa42a3863d753147de7368b28a74d84";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36353833393236333732"_hex;
                sig_r = "8fef6b52c4d643fd9d5f28fd5204fc5b5b6a3e57e6db9c8eef7514068933377a7f16a069a95bb6f649dd3310922a982211f242093a23ab44df810eb4d744b054";
                sig_s = "5e3862a42fe8a560432d5de042f980613e68f6b3444d7d53526600a505992371f6f72dd1aa775e58e24212a0c26439d2eb717340fd536d38f9148d2136850a7e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3133323035303135373235"_hex;
                sig_r = "14be636d9aa0aacb84f1d7d0b88372c0322687767d45239d7b8837d747d60fc6cb0fa7e897bbdb19194c82debddb46ddd094cb001ddb7e025923835d7e0eeda4";
                sig_s = "090d62997fb4ff82896d2e8a0ae22cef6dacf1889bef71805dba0f701d41ac219820e15e915e10513d491b6aa308b35906dc5d45191928f5025683be8a3a9f1b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35303835333330373931"_hex;
                sig_r = "9af98bee9911640fb5d58fa0803e5393b772fb0c862ee9f8545d9dadbafb1a6c73c85b79f39d1185f4b2c4bb54e51317e2633d50fc8f75888504268b84f40e24";
                sig_s = "87fb7c8a2d81f7226debff31b4f0a29a08f1f9a4c50e5615b570555ef2cca1df2b704e92e9b8adb44189e69553ed79effe315bd401d0b2328cb065cf10e130cb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37383636383133313139"_hex;
                sig_r = "a64a9dadf5b6a57028044e08d788784e07ac98dfa1ed238348e45e95d44f631d9f14abb94643f87d1cf3f9fec5dc2720e429646c0ec7151fb89924cd431c3073";
                sig_s = "115f653a3d327d93118cdd24ffff039da516afa27f37c78735c985973cfe55275b610d7be24969eb531721a0a486194b6b8823d0d70b0dc1fd4c7611c32861e0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303832353339343239"_hex;
                sig_r = "95d081c0728fee3f5b11a593395869aa342c260dfa05e5575317150236482d00ee80a6f0a3a25c0c8e3a6790014c6747d8b5ddb081328bd53e4c6422c623d795";
                sig_s = "98334ddc2a1ed887b26fa23599012b31fbd5fa384db5c0902233c1efe61f85fcce09a9e7fc13fb0253c8cfceb8762360ee5d20e17debbe84a1c8eb68db7ffd4c";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130303635393536363937"_hex;
                sig_r = "9ddd4ac392e9b8391d766b6f5d26f164ef6f4552d73f1ee9d096b77e3dcc3a42023573156c5954187ebecb2f60ed7a01439809dd8eba286e5340eeb7e184593d";
                sig_s = "166a4a2b9e0ceeab82783c1a7d622dcf7bffc69b85ae41e5ad9b552bf3b687a228cff644d5497ba0a1644c039162ecdfb095d23dda25efe14f48032c6d09caa4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33303234313831363034"_hex;
                sig_r = "7db0fbddcf437e25804bfa6d476007bb2e49138527ff27d759d05c0b1a3dada2327c49813200cc24fd81f0deefb6061314d06829024f4464591f520d5cbd9dae";
                sig_s = "1753cbe7f6d18e8fc226a950385a43858ddddfba4b57c5c07d581f51cbf5c8f93781b48ccc887c039fcdecd6e65e3e594894c67875ed89e86c44e52d656c346a";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37373637383532383734"_hex;
                sig_r = "8986b0ea9c57e037960e76d8b539afc714cc3adc90394b96bcfa3f7fbead4fc585133e4f61b7ce3edff093b98c257dbbb497f86dbf467f1aed8d7a7dbfb44632";
                sig_s = "9e7d1fa09ccb4b4d49a2463f12a9f760d3cc0be38e409a3521723e6f48398001901153e141c121500c8ba689896e2c3c883767378920375cb52f0cbe5ae98161";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353434313939393734"_hex;
                sig_r = "75dff0fc67964d57ff013e4eb8a7d356b9f408be6f5aed818546b064102270a8147f3ab78b94327b60232fe086222f7ee7c027c6a2f856467922156cd00c5246";
                sig_s = "5972544117567221cd67575428c5c61edfb228b131464927657e45ae8e55625c874c46978c7dd481d2db8ee9cabd1a61bc2447ced2ff9a72ede122dabc6d9c31";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35383433343830333931"_hex;
                sig_r = "a2ce4a9661c71f7ede80c167c675860cf68d7ef5400312f2ae050c412ddddd8869ce093b2e11e38495245d04252e44129e994536435210e3b7d1ebb0c015bac5";
                sig_s = "6932855efecc41215d2caf8bbed6f0a2d806d2be3485760dfa8c8817958147e26f6f6bfd91f0874e1449c9745653488c068ab80fd99227b5a79c17fd266b7bfb";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "373138383932363239"_hex;
                sig_r = "1b60263f05e2e818f67941b1b5f5e8668dbba51aafc4dfdf9b49979a80ae0c51f2b1b28824fd9d4b0a2d32b7e6f6e3eac580590752e171bf1ded04da5417ae29";
                sig_s = "7aaff63685f50e01fbb2d727aca66355c7f524b3b0b7c52301cb9b5aeaa2b62385427cc6aac126e1652fe0e62ccb1479b1a48ac7dd8173d754d06f505dd443c1";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31373433323233343433"_hex;
                sig_r = "86039c7f139431e6648bebeb5eaca3dac07ce807b51c68e7590120faaee7fae4280b33b1a4dc979201823b31f150ef2d0285a4588662b7c87e50155d406274a7";
                sig_s = "5ed7cbcb6ba08d0a20514f801503ca84b4a409ce8f55651643013999f8d3ff65a9b0bf2a7c52f84dd2945d22677fa46227a64c7359180fbb4b15033ee8a8abe5";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32343036303035393336"_hex;
                sig_r = "7016468a36f855abbbb4d4d859937f5fae56a4da2c4d2719fa77e111a56cd3a21e9267120127db5a67afe2b32c7b4c3bfe15d0ad44c60c4089a4fe4fa53cdca9";
                sig_s = "7fcb61da561cb7cb8aba8c07e7417423bed2e99784b5f646990014e6872552a07e1034d80e69b319b7cd2c7b157546323df4a2ab8433c623eb0c77d4159f014e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363134303336393838"_hex;
                sig_r = "43acf84a076d740e997bcaa35dec9e75df3c0c4f25b2075daf077de60b5b9fb7f784a6027699a216a047a2135a3b530fd8fa0077338d4dc85fbbaaceb6641022";
                sig_s = "807a3cdfc0f33bbe7a5a52f7e4787c67340d958baf0d957d015c73c9c8d0b60f87a426bfd2c9209fa7f5fab1b05a8860857171400714081b6f6e733f380c3963";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32303935343235363835"_hex;
                sig_r = "851fa88595498dd5a5fb5a0710e02fee1a023e4b4aacfeba03f7c4c14a8fb433934ea233e5d27de155daca4d4e3843f0f2cd586170728a2d4ce65223580cec66";
                sig_s = "1731b6c00200f4474d4ea2046775d9350e45f2abd45bbcc1163c77deaeafc94210985b7466cf61bc78d59bdd2439aa1c7ddac71e0072d73d876a14f3261af77b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31303038303938393833"_hex;
                sig_r = "78456d3583b93fba209d6faf7363f8e87866cce8f1a8f756520d5fc7d22d369408753373a999c8e5ba5817c61ff9a3a0a9804121a00104c7c15dda9b60bd744d";
                sig_s = "67e149ae6a206d3deeeeaf78f90fc5fc69c0c101273512ad42d5fd3993babc671de9c4aac015310be8eb6d83121b9709b93cd43763bfba9dd83976a91a75f567";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353734313437393237"_hex;
                sig_r = "5ffc31a2e8168748c629e0690161cc6249680c03de5cbad44b121aa856f557cf9a84983e493f40e2c0f598738b0f6ec8575b66e4c4e59b6b63996058e4aca2aa";
                sig_s = "41e0857e6e959c55bd807629361ac41dde640feacdc212d7cd2e1dcb9a3a9a4e933cf8e91fc7b1257b7a4f9696283e06e32f976987df86da2c87978b34cc5eb4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32383636373731353232"_hex;
                sig_r = "31492b0888f6fff52d247bee1734c8425c35606c9d8cc63df382dce5224c8d55ff2ba6cfa29d09500124e8576abbd0d710baeb099efef02fe810d4a19dc2ca44";
                sig_s = "24d3b320def3943ac856680e00891c28da011840af29f4f2c8884a022463a1da9dbccb11bd4b720e72b9afa8b6b871a86f12f875cc1c09077fcc15a90f402acf";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363934323830373837"_hex;
                sig_r = "8ee3ad5b61de2a1e3a10aaa2b5b7c1f9f790ebcd110afdcc08ac9b70fe7530fda9ce94e44058740e17b7308331ddb0ceb0bc69b949442122713582e4941aecd3";
                sig_s = "325dfefb8f462d5e7dc4124ef0719fef7649d470f3f1555172484b0304e75ba122802d1a8597b462b345f34e17df4a3c25eaea269ea11ef5b042440b5cabb714";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "39393231363932353638"_hex;
                sig_r = "556b513902291450e9a2b126b858e1e2bb0a23e2ee904677d9e5eac88a25f01408b8f512d91352c43c519d9d74570b3d78366df437a4298b311a39a63c442abd";
                sig_s = "7b8426258789971c56c53d997dcfa1270543bc9f7c42ca2ea2fac08852c472bb2b284aab59a4baaf0f2c986a2c68fd3e6fc91f1d28be9b7577f7784c587f3714";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131363039343339373938"_hex;
                sig_r = "60557b793efc6fd8e22f6fb880b9b24f4ce95b090f694fab2866bc18dd85ed5f479fa896d84092dadcb4b9686ad8074d69be8429eaad63d03c63c6217fd7cc71";
                sig_s = "7819879f5105f30ce8efd87c044279ae9eac3255327d9a8b083e9dcdbbda1e01ecbc9ea690bfab771b63318a964942f4577847f571b679363311ce1bd20a2ae0";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37313836313632313030"_hex;
                sig_r = "96a8b736b4d1c2e40132b0c1dc351c700b62db81e8bb39aa717a1ec0258eb92da819df0117a7047e6c33549d3848d6eea3f725aa39b03222463ff246e8966421";
                sig_s = "6bb7c1e5fde98b5eab976193682cea8648df80a649c2ad68e0b2eda5e2bee9aa9b773f4d62486edbb09ecf434c1ae0dba273f68bfa0f985ced5d7b0120ed88e7";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33323934333437313737"_hex;
                sig_r = "4d9d07d3a45f1c913634713d7ba74ffbd3cd114ae75f178fe7ac7defce7314818b6167760cb6e7d0a24f427d8eee6012b52c683883bd97e351405c937e4f6eda";
                sig_s = "27bcb629e31066dd6a4c65432d39c25add00bfa369d48b0e4820a19f081e9eda977875636a8cf9840122d5e1bb3cea5fefe0203f601616d6aec820a1580590fa";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3138353134343535313230"_hex;
                sig_r = "9151eb1014557b00c8f28892a2911f5d67d59396a93da4327d0059fba767b97dedd52e0cc85e0bf8988c7eec231008a0f972d51139a2fe12b75591c071fce9ec";
                sig_s = "aa89b592fd309327e6c911e2df0d95fe99bf01de326a9ff06648a321a363a79e7bd5b051e0160fef18ab814031a07601a6783cc4efc68c681d2df648fbc5477e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "343736303433393330"_hex;
                sig_r = "374e3d3bff57b2a0f924aa19ed2c8d44429f8f8a62934ada5c0bd83c2ca9ef2538f186f2863680183c51324ef4cac5a945dcb908ac40f4dbcb1d2045cac65854";
                sig_s = "2ba1c3960386177723809dddab3f806a10da5e74c67c9c460b6c4163f37230c355cd4b098aad23da524e1e7040363f4d728fafe4d952ad5ff1370c1010efbf09";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32353637333738373431"_hex;
                sig_r = "60f1a5bc4a35f001114e5d7105c21d6e5161adeb5d1d88251791fd08e0192a6fc94ede2109288389b3ea9d00575b66ec0cee5f1e531c05c0885427a3bd65d647";
                sig_s = "5f62c35cfbaa2aefdec113335fc5f5646ed858da0be4852177135d7ee62c1220ce447cb6ab26cbf543215b2c15af42d95a515b7250fb5ed79204a57cb04f6567";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35373339393334393935"_hex;
                sig_r = "4becd657fd4c9866fbdda4cc07c4cd528964b120b4137afe1c142758d0480398a1fe6e203b564657c99ef03a044f89c4a5bcfb3cfa6659671fcfa1d8384b82d9";
                sig_s = "a1649256d0c43f7f6c19267741738903d82976cc3a678b480c50b52aea3d493a80c20ffde7b57f9291b22be5b4130dcefc82fee70bc3f1f308ab0a8403828ede";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343738333636313339"_hex;
                sig_r = "6b3f1533f53fda7448a710a4d0e3d8278c96d656635a8ec9c86085ed2337b73368f5c5934a46d59dc79ee6c3349fc78874c05f5e5ef859eab03dd858d2c28e85";
                sig_s = "25cf5a2f2638ebf2e76238bb54dab1e96e9de0d67d5579151e2256c9527ebd4d3857731fae84ab3b56b74bc89c4a99639b0c687b2a133bf77029d5abe4a5fdf9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363439303532363032"_hex;
                sig_r = "6ff4be5df3f12cf2cb7816985e9ba0099cf589a2a22367abe019328789ad5092107d12dfed8352a1dd4ad975e861ab9f9c64cb6b5bc98c5786247bdb4ea4829d";
                sig_s = "5eff29e6e20e9ebf1ac602589c5ba64b2020d1f2fee83e6d0c9cdda1af8d7c0ab8e5ff059ea457b903d2fdd48ff84a32e338f0270515fb0ba44c009524ab7880";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34373633383837343936"_hex;
                sig_r = "56b91ce37f560c1c6557f7fe0029754f87c8f10d92dc525dfcb4cd5a966be0e8d99fc00851e85b85827d31c861034c20d2acb49e4f1eebd8e0d0215d54db2b11";
                sig_s = "7cec2970fe9f293c9d3a672d3777ff0edf728545bcbe005c178e0b405fe4223aab60dd44521be321672e81445892911130e602a4b8359bb3632f909918e02a58";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "353739303230303830"_hex;
                sig_r = "49cd57e25cfb68043705184969e309066986057d9c0b7a2f87766aadcf76eda8028d4eceaceced9153ac9760f47514dddd33473af09ff0dfc000d53130a2010e";
                sig_s = "73d534bd76522681e71109c07cb17b09e661c11c519b20fe6db80d47756f844840b7be6b95c5db497e706c5f58c78a350a8e802effbd55b5967bdf87ce75f064";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "35333434373837383438"_hex;
                sig_r = "680d7c82bbff291bb71f2da532f1a931eb39a222336d5e40657cc2fb126b2247cf2dae233555564ea4424ec37912b37e8866d45c393c6a91ce132dbc9f46635d";
                sig_s = "1f0c515856a62af68f0f23145aad92a77d7107d8d8aa46cabcc72b2c082185db1d75d1546a4e6cf527c69fe52cb76ee15eaa620444b6f272b4027635ebe83676";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3139323636343130393230"_hex;
                sig_r = "59fff5ae9729b21c389a12702360aca2575ed4a44922e17de57ce93979f19556de0e25581cfc98c1a68ef001a7f8d157e7591baea44e003c454e941bbf9e5f7e";
                sig_s = "109196a80b32a0a57a7bcd3a6ce7f925d14f51c6152ad866d3373008d650b5af7a25e2bfbd59b6371fffecfde116d2a36a8d1fe9178ba3b3f37c09b271a5b050";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33373033393135373035"_hex;
                sig_r = "66ef246c7b80b56e0ea783ac737151c73610218d00c936f4c18d5a6c44f35ee19d8aa15765dffdfe51aaa331123ee4c5c8d67263f695561e7cf7e648efb7a4f7";
                sig_s = "2a0ac49a984cbdf66c59c65dee9a3cc5816b7882af45341e9dc514aefaecd2468cd5b967a53654880046e18e1adc991fe1b7bc0e5379179ba3dc84bcee12c61b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3831353435373730"_hex;
                sig_r = "7469767e7512c7d294d83290871b5cb7ec5d6ebf05b2d7651839729b8727818e9e530875e901b759e92c798610d4473591b2cfb87428a2f0b1afb25d25f9868c";
                sig_s = "13aa65ad34388ee102ce4fe0f3801db5f1be38b8f591946ae55be7159a2e047d037618ce45a0980c9f686a7bee7fe8c7882262c4f7c6608596e12900cea620a3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "313935353330333737"_hex;
                sig_r = "2dde8dae883b5f5b8222b261ff198b0d4615b223735380031e37603d9766c3a660ccbae350d40994ebb49a09d8c902beacf8f0de1ca2b0a4a31d00b56bd845a4";
                sig_s = "6604fde70ac761420133624def5c44b5d5a5795d4412dd73983aef629080ae47636497018cd5d31c8b85b2b03d72171488429eaf4b8247aa6b01044c0ae461f9";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31323637383130393033"_hex;
                sig_r = "245dbf6c53a2d7881b8d157a6200d9ba3243e4d9c12d3edebd8ff9e103c6158f896ed5bcab43383cf6becdbcf081604a595508172bbf43f152b669c4f41d21e5";
                sig_s = "a1dfaf17a6e551fe0bc0cc24cac5a8214dbd750860a60300210ae9dc4aa160f788dd58b82f9688407551b0a20e367083a1a0f99c35715228c2252f0f0ddb2585";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131313830373230383135"_hex;
                sig_r = "4550b986fb04cc7fde0dc85a95a1581794b2521020532dc00fb5ed4b0ebd6834f183f3c62a5756bf5bd0b9a516bc3d6c7e81efe551164b9de0c152938295e2fb";
                sig_s = "485976253d58032d27ed6156ec15cf853440ddecdf63bdb304e1e74d139c1319674664c5aaed9bb3043a6e8aab1ca2e15afdb45d3320042750f9ea8296fcd5e4";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "38333831383639323930"_hex;
                sig_r = "539183dadea6630bd4416a49a8d6e7792303e1e44d2028726f84697c496c26daccac5fc4a4ad34866e718e9067c4af1bc9e22c70b94e74f2822fef929e7bad56";
                sig_s = "4abb755192a18efb2e72a2fb4ee51e47db6d3bb21be2ddefb8fcff5e084a2d8c8c7a1f44d04c54b6bcbb957c14a62d7547feccb5d3f20ed20093136d97dcb689";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33313331323837323737"_hex;
                sig_r = "208250a2a662f8536b5cdcffa137b83c525512d9e3cdfed020760c1b05b55fc9f66c6d7a8c25bfa475b107831153738d55a4dd07a78192d041692bf535e1ac04";
                sig_s = "3d857ddd8cb246ac6ed21e1dc5368190daa99bf8c36449edd318b27827a24c9ab0314c592617249a1da9fde135bc85e4c4805d05179b40c8cf4edbc0adf19f46";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134333331393236353338"_hex;
                sig_r = "65c639aa06868153b7763ff68bce97c7d9fe2f028d9bea623285214ec5572f641274e419a8335dec43fff2234ded00bb0123411dea843e970bfb8fed4a514ee4";
                sig_s = "3fd4eab53713231e9191906ef0cba9c4cb50fc24628c8f2db1914d6ccec491c780c96cdb1b9be6a63cd379a8463939aa8a6eca6357237fa8e829fa4a38448f7f";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333434393038323336"_hex;
                sig_r = "4a110cc6aba129603a617f0f83c8d7e9a661df8b571fed8498322d5e448b466f7942e39a56a085303ddb922db59c7dcaee44de094a7853e717a3e928179fbc76";
                sig_s = "2e5484867e70cf9e3bfcff309e89ee1d909904f4b94022ae91177554706122e5c45f9a72aee76410bb844f09f8e66e0eede287d6c365244e7632f478a7530a11";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36383239383335393239"_hex;
                sig_r = "39c896c0409967f9be11fdfff9e8f7b08b7f2cf44be471d4ea1e256932344436663a4da8fe28ffe79d277458e9ea2f597a7db847414bb2ad2438037cb6c4a6cd";
                sig_s = "910d53ab2c5c56bf05837429e5e3d08a02d0e602272830297922bc91e29f4f988271fdd60f070eb0aa1e57d742ca75965638274f3cfb2b7b28d1a1462a384fa3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "33343435313538303233"_hex;
                sig_r = "431701fe9a41c1cda0a23b6c4fffb7128b536bc9c0fa1455d7263af04a1a1d409a96a2e04a56e1912838d4ad45ae9d66db7d9347e160495b4be77122852a281d";
                sig_s = "824cb138a29f22435d401880556e16c5859349bd19f53c5c20516ace4d84c5c600bf61114e05697cde121686921b9774b83b84d00c2cd6b78cc5920c6321878e";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3132363937393837363434"_hex;
                sig_r = "684e6e41e2588506b6ec29b458301a7981c1093300675a9cfec0f195696d35a16068c4e25424fc9b276d84f7afeb39af096effecff09a6ac67327095e2e25c2a";
                sig_s = "1c3080b7f70cebd1930a2b8bf60731e8380fae8a08f0311a27abc15d1105e4aa626260cee865d2cf224ac7a925c4eb5babce2fecb5e20d61f7a5dbbbe33a0193";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "333939323432353533"_hex;
                sig_r = "4c56b13a81a39cb7f2767b115fb409b9cb9988aac5885b632712b133f23bec54c6fd53318e265fbcb18476717339ea901259fe629a396267741ef44e4475a7bb";
                sig_s = "24fca68064bbf8bee1551c2d00b54a16b50b4821c299e2aa1a73dfe2f81c73c40993166ab8ed9bd8489cfe523e41cf6e35ef7a7a331bd8d2a4db77dff40d113b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31363031393737393737"_hex;
                sig_r = "682afc3b9259dbc9160119014619375a7d4916bd08a931cf7877875fc777d18a3caaf253c605c1197399ef9372b9f585a5841498565fb577018160f62f9f3b6b";
                sig_s = "56a7e2dc08f6fb561b620f09e830ce6fd52b49da815f9c3e89959b0d2fcc79adfb6dd9f9ddf0ed9e295b728c305effcb4d97efde40d93dc2b6377e9d4f72be15";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3130383738373535313435"_hex;
                sig_r = "8a6854acf4c80327def8e3ec1046de4f35498df798a916edc84431674d4eb45d20559ccdb8c1a14754de6ef404b5e8a66c3628abacd07e8ca406ddc0d97560e6";
                sig_s = "1e5a07f82bf320b774a460f3ebf53496ef632f7a33d51fa2847f63931fef1311b53c213840ea3c6e70d2846a576599026ac16690258e4fc8edbb1211816fc11b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "37303034323532393939"_hex;
                sig_r = "1b0605be20e4374b17e4eac26bd2bb957020e1e05108279bd26960de64d39ef2d19cc8ccbe8fd72e122412c2c620cd2c4640268b38df93193b8ac7e0d8382ca5";
                sig_s = "289927ed08ef4e0e5a41728775a10dde8c6cc6e08f9eaba51077c880c5aad647bc2f35def592d0ddd1d3e140b6e756c46be36013cc5a6e5bb9870b5c4dcaf2ac";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31353635333235323833"_hex;
                sig_r = "373844063323beb4e6a4d282193592df39dc5767519a8031b62d8aabd5ded695407bc4687ac09de93fa38a89412cfe6acb5c09975779a9e41702e18157b84457";
                sig_s = "9262014ccacb90a4b8333b9743f25b89825f3f7d2171e6f3afd82c048a9805745b7812b46c2c5447fe100e3beea0ec3bb4fded3744531eb00c4df1e05d39c573";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3233383236333432333530"_hex;
                sig_r = "798f3008a628ad65c7f83ab51f2e7b9e1d1b74cad864334cde339ba3d2d73f13549a18c6bc8f8272d5a036570f45a1cff2051cbc48e8a990c3303bd6df887ed9";
                sig_s = "60a1a0ef92d5c28b6d6afeb2718decb57661253ac5fd2e13639b04fe6d417eeb40d753146fdb804937ac6ba92c8f8bf96a9e0c81532ef03910bf4ce0483bf39d";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31343437383437303635"_hex;
                sig_r = "9582bfa8a212ba8d0852a4690bff7c937bafddd2f8447d850ae518389f20182bf83b00052c3b3dc65b1a70cf216cdfa62dcd17a5adf331a2a732baaeeec0ad9d";
                sig_s = "a4a1e41f5fdbb9000d0f3bbe311995a28af86b9b0334de549882964c5311aa52d87de9626706bb2514c1cf409e9907f4e91e9a49d65524b4dfcba52092025506";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3134323630323035353434"_hex;
                sig_r = "4d6790c49c82a7ac06ce84215394c86c7011b1b5f714738b1ad4d7b010d8546763f602c9af1e6748a27d297bed04ebead4bf629043e4deb398a27d4f86f3d795";
                sig_s = "6a6dcf9c898c07d24f13e76366fdfb76eddd4157ef2befa910524934a8d4109c12e01ec45d9fd4978fb2910681e5460371bbfc76528703e8b8a8bcbe8a6c8a39";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31393933383335323835"_hex;
                sig_r = "65b49ebf5198da395aa182ba31d473129acc2fd65fdc0df2cd59a1c68a527882c922f73993396355bd6cdf4e4fe9c42e1716f66eaf3e0e73253d5f618c300639";
                sig_s = "8deb03cc4640194ce230da1d77aacb007427557f70d4a0ee814812c560865f14f24a8f79393cef1a159d2834d9fdee0a16a85bcd5cd50e0f7c26323036335ffd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34323932313533353233"_hex;
                sig_r = "873e39e7f6b7dde5e40ca7fd4b8e85f3cdeeae4671d63218b9f7195445661da0d1f54607599ae7531202ebbae9b5a1a58d37c4a1fd3fff8e96547fdd3f76f883";
                sig_s = "74bf6db093260eff6cac9f06db1646c083e4bc09c8f1755aa302ecf7916979019cad8bed739007970c2cee87d0252cc68f056f710330c65fc56551297312b220";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "34343539393031343936"_hex;
                sig_r = "0127ada33ff4c6441e79f6014651df82d4d10cf4601ac567d44142b0dcfc933f7c8a2e231d0d290cbf042df6112d6fe16ddd2c1e96f798205cbf595268a94157";
                sig_s = "2235411c90cc9ac1872d238e7c7d8deb0755b3662cd9f249bf3c844e750cf58f90fe908f28b138676ef9cb24efbbafab8d3bebc177a5b32a32d17b91fc49b0dd";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "31333933393731313731"_hex;
                sig_r = "8244c73317b53e37473d7beef9f8e5bd31ed801f9bbdb9639b7f0f24e0329c7914959bf0cd2006986fa81f7f4b4002503343aec0465d8f1ed17c97746ed6caed";
                sig_s = "14bc6cc4d155377175ea95c359c69624afe18579014421b66a140e87c1439f7d78f5645d4bd8c027549526865855fff0fc527f493623c3647b5c901d8de4b829";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "32333930363936343935"_hex;
                sig_r = "0011ddcc69dda56764afdbeacd615b3c2950587943716ed6dac7658679a21b2b4cdbe85a5e4094def253ede57f31ef7588ee3124d805abc12ecbf7f55a7cb55d";
                sig_s = "119d722bc372a4e6c5b4e39fdf25816f2387d00ef040d0ad75bda27970001ce5cdf5a2d4dd8bc804219fe8e9715296adb53303b90f2c5c1f3f94b3f5f2fda8c2";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3131343436303536323634"_hex;
                sig_r = "12e59cd484adba7d0fc2e402d6caf0e44a0ed252a891623d2687902b518376efd734a7b7533d797ce8f145028b428c18f5f20443c53f04e604aa311315e9266d";
                sig_s = "47736e60345f1cb9bf7bd117d8cb82c941179f0893a4b7d8762f7bc9322025a564acbd7b3bb47de384a4582f337b809e84c48b08610a3dfd0c875dfe9b8885f3";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "363835303034373530"_hex;
                sig_r = "009a5f640cdaaf26f1c15cfc5c27498a8231571f22053154cc2f52877cbe5cf289c553d7bdf86b1973263604d594e529ab2d1df1066d885fd5a061f638e7a346";
                sig_s = "91fe33e050748bd7d76883a03d5f2976487a0326a3a3c5ef276c38a9ca09962570ecc8b89f931a145497b77a482a731289c2f79c4a7b871928b39e94a1488c83";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "3232323035333630363139"_hex;
                sig_r = "68c001ac8c8804c0a9c38f18109e26b4e8a1ba18d0fba8547f70e3989f3c510871e80f8a7b314fc521b7c79c3bb3b691560ab9d699a24915fc682fdac1f01c6f";
                sig_s = "8c2fa0a4d960d2688442dbd663e85f46d858faaaff91b7ba9ae96ba6619663780f05950d0ad89b79cd695d14dee57f27bca99f0165f1d4bb123d17b1a46bda32";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // special case hash
                m = "36323135363635313234"_hex;
                sig_r = "4b1e61394e6c262b1e4a63ea7cf41e660020b247358d1b15aaec9533d587d82425a860dc9f7a8e2b1761393d3fc2a9d1ac433a0662a1e2ee2555fc9c3849ad4b";
                sig_s = "86daeb1961ef422a09f53bfa0e5ffc7f52a3b55e76f0c2ebb7f8b034b3cfaff08c527a15a9f97e8d09da812e395d5c611680b7f651d41694f0b58fe9eb310b6b";
                r = true; // result = valid - flags: ['SpecialCaseHash']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6b6763a186aa5159049f2ea5c8a232dcbe6337b0d92e969da52af32524f61da3097fa314ac792234e59867af320478774bd4c785a0330624c0b4babe257f6597", "2e4063e45e13d505e14db6f5fef3538db181cc1a6e0a9381fa3f0321be47f40dc05ab80e9caa3b7559c67535e83d984f3b9557118dde29c5e7a5a4a18d0c9d43" );
            {
                // k*G has a large x-coordinate
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000001280f3ebf4f1d42296d47401166f7709f0ad02bae2524eba77322c9d3bb914889";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90066";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r too large
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f2";
                sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90066";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008f676959bfda02d373977a80528b61d4148f8eabc2027fb5b5db5827677d147a728661fd5c546b6ad5f0a89a347449aa2f32112e3bbda8035089547929b56a55", "78c45ce0a688aea390d4e4db4d48d2cdb21865bc8cefd15f2bbae4270ab765a76f049449f17ce1ac7f513977ce0a5237e5bd63b4af92a6cf4918d91bccd0f279" );
            {
                // r,s are large
                auto m = "313233343030"_hex;
                bn_t sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90065";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90064";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "14f38afbc8d6be59ee7075bdfd2616a44b86535687d05c2347553173cd14df8abd0a4c102c62e8141127dc66d2dcaae38c9324980ede204688bb9f916ba9f1a8", "23f358139316ca27b8874e68b93388f9780d9ba7e23b8421bfad38a19ed161477e0a05380bebd7a1156dc32f69047679fa2b977fadc0c29ebc1ebcea6cc1894c" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "4338ed95ac0d09c51d7044d59f1bc26f8f3f11fc7bf2f81bdf0b21b5c0b9c89bea3cc6dd8b3692c8310b98117b508d130073e74b02b3ba482fb0a5ef1036a3fd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3df9e586410ba633b9f165d29b073b67a167297cb4086889e52b925a9cb25acc4c85e5b8112221ba49ecc99a0cb7fb3385352a7140072f79c2f44396ee8b6786", "22c7b6185e4b667a5cc427c99ca53fe54f03dfeeca92ba2c1ae1f2b3feebedeaba62ee3ba065ac5303c2d56969f0b341486f29f3b2a06df32830f25999c42f88" );
            {
                // r and s^-1 have a large Hamming weight
                auto m = "313233343030"_hex;
                bn_t sig_r = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                bn_t sig_s = "39c982e2a4f560c509055888f60317e6b5bb61d594d7bd4f5897396bf3e81a09cf703d319f9b4a092d46d5f202ff5ddb776c57e8ede8454def7037b541c97436";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0ad66abdba9fbee1fdd1b9e0db9a7460f460de3916efd16d7d9c6cc7a6cc9fa5cc03020d9f8c9094c0cb52fe1babd63c69ab20f04a116ecee3a009d5acb5729d", "5b4765858f696b61bf6b3a1812d057bee93b143836a764927971fb746141b5422fc077f73caa000f62ce00103502d1ecb0954f2cad60b224ec6fe1033009d64c" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009741c2634e42f1865625a9d97ebc549ac8c67eb6d03cd2a7c5987f0f5164c9be9775e32c5d59d3175de468e243591021ab623f6b09b31a4028639b041684f359", "470ddff173c67c71055f5f715b7b74993800305938bbda89d24b187f4819c30575d5e2275f08cbf3ba86b1a11f12671d2eb009d02516f3d1da0aafcd1d81a0c1" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008b06a77616ea21f14093d3a373a8f57106a71939f25415f6a9aa001640b5ed0adf39fc2f5e58d4233c2eefe4f170499da57e9dceb7f8cd5f38c4181fa7d2f768", "074a91e99eabced1bda358653e09b51eb8b1a9526f5a1b32c7edd3b701f5af4103314971d5c082c5f20053c3b66d39a1cb6c4d310dbe895546892d4296d96eff" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00868406e64e4e37672a23017cb578a24d1c85294304537f8cdb6ea38509843e754ea44a21973132ca70962861b0725b3ccc1979dd608b66023b70e95b0923d023", "5a959fb5bc9469ab5d55fe5392933cba8b413acec2e8235c36d10438d24bcd89370bd4e6ae3cca53a48a1771c5d0d00ecfea7385d2b4bbbf180c50bc45fb27a8" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1922b96f38799a34a2a0d224066af4e9c807b4daf9f26cea3898f133f5e1d170f27b9342cbc78d1ecbce1d928378b30c907d933b694a613dbb9fc2a9c2a786fb", "2d014013a6cf05f66c47c27f62a26496755e8d348ac2241ed557db81a333575897b5b28d9b9ddebe1037e373b9a15786a6baf8c3451c4ee7375a34edac3fe0b8" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "14b0aa4450b941337e7f946739697149c68aac733c86a124e1becccac1f032854192d878c4e7d61602dd3d080671c6f9d1ac473ef73bd6d8b284dc66c1b2eb37", "769f521f4e6322d3e7d59eeb9fc9e130575c358986614e8e6a44ce4d57c7715e13b958a743548c938a3384c6ffe32d3ea51b98a81e5b81918c4a720ea2252eda" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0091dc47e9e1088e3e373dd96bffb4754cb4dd62bd6ee59fb3dda4022e9e49683d02c4606f2e3402008b22110fcfcaa4f06d9e0bb921d495c158edd89889d5cb0e", "06f7da53bdf6589ced48d8f6af92240018f859e3c29c461eeccbdf6ef9b9fc122636237cb48621df6d15a07a43028c7a5e4a99de939d844b61aee2b67acebccd" );
            {
                // small r and s
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005";
                auto r = true; // result = valid - flags: ['SmallRandS', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // r is larger than n
                m = "313233343030"_hex;
                sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca9006d";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "008bd6529fe910f129d6d6efbbde7a025bb7efc799ce3eaca21dd1e10717e2d8a393265e1fa87b73d92747bce3c3506e9472d07f831e9e3e2df88ad9009ea52b3b", "0b3d56c4b39d73dcd13266292833a402e6948351b85260aec58f82f2e936d53dfa01d21441dd8aa4d5f606d94a99b7db583cc890ce4f6cc685e14738cdc4a5de" );
            {
                // s is larger than n
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";
                bn_t sig_s = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829cbbd6f0";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081b42adaac02a5fd87a04a16ddc2333075778f133ea0af66049c72a06721e3924979249e04291e4b99d4ecf448b3fdc5e56ea23381d6d06e23011965d1653816", "244327f9d59ca6787575bb7707ef2672f113ba7a302d69c29fea6ff66f449dcd3b273b3398481776c2f2a685cb6dde31e176be8f2b785fed313be5730c6624ed" );
            {
                // small r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "12d5e9125cc71fbeb86c217e09bd92b646c6dd3a1be1d6a6ed4d80267127e4b5b4bc4aac7d5d3aa0033114c85aac2a1bff3def001d248d0a5483dc2ea66f5ac1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01a0e00bb4a669f10f594489a42f1babd3a028b5ea75757a986c55f6159469752b88bbe9f52f2422d503a4d9a849c3dad410a6dc4e4e32b95469e09386063401", "574c501128906459a23af93b9830e297f3e73d3173df7807679b713ce6b34f64b1ee7547b927e43105118c496b9a3c1e0264e84b5b0fb459582af98edf0c117f" );
            {
                // smallish r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d9b4d347952cc";
                bn_t sig_s = "76752ce289c38f22de7f75d0fa6da056f473c77194de931d97efd65421ff3ec82c57a6393a42702e14a2d831768865ab933281abf1bcf52a7ef6b73f2373c9ee";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0dc4c5639b7690157c210b75e7a006d9cfdf80f9d0b2bbd643036890a8168a88947b197aa9a60047cd8f6e77c0777bb9e09da737dbbe57a977a6ae0707983564", "60b0a49d4f9578273f6e5ab3873194292e893e06c5a39bb1f8a0551f4e01ca460a03a77c35cff8d7d6e0f33b8a88acdc36eae5a83a129bfeecc2a68936883d91" );
            {
                // 100-bit r and small s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001033e67e37b32b445580bf4efd";
                bn_t sig_s = "9ce766006a5130005e79caddba04302708487a27823bd1d3d9ca0a801f4fbc0b83126aa1911ad44afd6a770c753d619fef707e7c773f467de5738b35333893cd";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00867dfdd726cee931256dd9aae0c1a660a12b1dfd6baf180b35e39c0f93cbf9800c5cf11b29f18678d325121fb286545a512dd8f6c2cb81e598d05fc40cfcf9dc", "0091d4d2153f667593e25fee42e39dafd1811974943e875dfcc6badc0ea22db4212637be71c6b74375c43cfbf719088691aec70e691e46edfe8ccdb4cefcb1351e" );
            {
                // small r and 100 bit s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100";
                bn_t sig_s = "029c0de2216bab72af9ec823411e7ee444482bc268ae1ba9064e04019609757d95b2e0c5a3fde377a87fcd38b32f8061bd3dc81cbbdb96ca626e6582ba61dc31";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "34308c7d6eaa1bd7d8edc02fc6277c5271ca847428ff210d6078ec968df4e8730e21bc7715a7ee85a7352802466c0ab23560929bab49296509937fe7cd6edc02", "36491a29b86ea0e6124f4b72101f48230bdc1f5b36d2e6500c3ffd4ba9818b435046335a2da15a89bc51117204d330832abc0f7b09a59d82bbb01d71762d8df5" );
            {
                // 100-bit r and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25";
                bn_t sig_s = "029c0de2216bab72af9ec823411e7ee444482bc268ae1ba9064e04019609757d95b2e0c5a3fde377a87fcd38b32f8061bd3dc81cbbdb96ca626e6582ba61dc31";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78d35a1c8a83997300a02eb477916e7095b001bfc47341528f75c6cebefd2d59c5d5efaeae9c5bd8ad4bdbad76da1cbcd3547a95d392dff53ce85bc4e4b23ff9", "4bb3427e6074138fc0e438320a314e20367137133b4fee63d80ecfb5931666b0873dcd456a36994edfda75b0f3ea81732277e77adc43a481ff0f0ed4d2f37ff0" );
            {
                // r and s^-1 are close to n
                auto m = "313233343030"_hex;
                bn_t sig_r = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca8ffe9";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7656a55ab37b38afec6e6a80eafff691c2b8031cc860a17a7ba07e3ae2f6aa0cae51cc5de2b36f17143fb7ee34dd1db97e522f84dadc6c2a27a7283e551f5758", "308df3b71ca6953d18fad0952dec4d73fac8d91b47d05ef3a74121072e1dc3bade11544116abc8cb0ad80ee0c58036ffcf710529a28c475cbe708ccf8819c7f9" );
            {
                // r and s are 64-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009c44febf31c3594e";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000839ed28247c2b06b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4f4f975357749aca4f64741f72bcf20acfc783d15c3b54c973d8981f7a028bff5f5817814276ba1b4baa90b3accd1ca8eb7acb6ae9264a34f801a62e34738db6", "1b9560c2652d95756fabd4ca0668ad2c2df84f6498ee683a8b4e5122d6324f3c731c8ddf82a6d663ab87da69732758680290ef433ca514c16be2175efb02740d" );
            {
                // r and s are 100-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "44d4ea4738f3214b0fe7d36172c7134d04a1b547f595a54625c4fb0973192aa4faa7743f042b1ef162fd8ea2a5e71cd5456e565cf278eec0321cb828fb13435d", "0088d2fbfb90ada22f40deab1abf0f6496da14e18947212281358789ff8ade72b48bd99287cf69eb0b0935430d4a179b97f809e5222b0e295afb28d773cd59e1fc" );
            {
                // r and s are 128-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a598e563a89f526c32ebec8de26367a";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00808af7ea25b2321eacf98049e8fd410366d2bc5e702808272a899f85a17e6441b4ad1ecedf94a33932a65973d5a45b898466e1c09ee9012ac3d5fac3c766ec6d", "71729acce4c49c99a1584cb3f85d4146f1669e504bfeb1c0554cabcd86aaff254d66783c8a5a19f2291dcaeee6d053fe379a72cd3518db05fe381c2b478e8057" );
            {
                // r and s are 160-bit integer
                auto m = "313233343030"_hex;
                bn_t sig_r = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0be2";
                bn_t sig_s = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009019be20f640ecb2b7c3311bcda870954938a780686c063fe0ab26f57ba60511ff3cee3286d8d90487eb8014788a1f134ed59a774fdb8b0d24770bf2301b2d18", "08fe934dc911d15c44e59b9026811e7cd8fdd874410d51a56f5aea137bfc4a8e85b7eba7528949cdabc4d33aef16157d14e3f5f68bde5de1c5196917a56dab29" );
            {
                // s == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // s == 0
                m = "313233343030"_hex;
                sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                sig_s = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
                r = false; // result = invalid - flags: ['ArithmeticError']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6a4c6c879b23ca5aa34248d48628ca12e4f2279aefddae460361d68e6ce290461182f674d18a8ee5a2c5bcab910d83dd618d29eda613f609081cd34d9d1fd9e2", "415f6649b18b2b1decc9a50203ae86a8689592a9aaaa35303296aefc2d582bcbedbde6a91f0b8a237a2bc2639e59c6579d7a76790ba29cbd90f22352f733e067" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "0cc5750ba98b8e7fe373e57797c29f424322828b5dc9a2f78ef8150cdf0266254ce9967b1197bac6caafdabaf5eb81635809ddad42495d1fcb934cc443dc941f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6327eaa44d4da78ee17ddfb4ccfda599357ad6b20d487db31ff40e453e1a7b4eb587d889988bb6dc1ee169143e0a0b27919f176e489747fe19bd5571f3b45cd5", "4420d79011792653fd17c4230f3b7e69ecf5cfcddc837e042651104b955795ec701576cf228113a1db2ba158614654222f6a90850c5e3abe64e51a84404e7234" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "296bc6cef75ce87d064db7522f1a440b4df4a71e233cb176ad7b0514958b3cf97d3eb29930a87701e4ed00e96de9f0d5e4fc134995b44f08c4c30e667778865c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a97fe60e1303df60cff6e107eed6430eedd90e4af6609aaea70a7d33620f2602af2be8d64d998a47114f04568a5ed6d9c41fa836958ba2dd63353ccd1c5e8598", "009868b313ed367999c54507ab7eabf3be54be1b9deaf43ddf3d2ac04e80e5cc0cbd9f323bfc7d3244b6bf39570282f22854c41792ea4861d478bbd7b089be0051" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "189799adf4d3362bc1ea2f7e331b2d80720506236ff2c692edf712dbd287712420afca0e56d43da8ae915767fd24836eb92730845ea132514d924daf2faa3139";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "33278003231172bb924dc1090cc8060a1ec95cea39074860699d64539079b569897d4e754bff02e36917db76cc14b14ca3997f6e5eda006b49ac3453ffee9ce6", "1b8f30c2bef7fbd0de37a3e146b8456296d8678465f7717f50e005c26532d7498ee864fd75c7de68830ef37e83b742bcae60cda9a4a3a649de0da2ed5987cfa3" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "392843478a101a81338d7d41071f557c9d4ec593a0698af9842c1cfb17ce21d7534a7c34c40217fe9271983a9f6304d906299055a791feea1c579ff1ca499b3d";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29f97430d99b8d83ceefffcba675421408f5fa14031f6d155221605a81e501568e27262aa0db953aef23d81271f213de830dc1e23a5b1420f2bb3948161ef437", "3ddc2efd449bf28027869e4c80a8aa0b306299d614e2714a2ce95d1f3b5370a2fb633662e3c8b8bbec10bd3a4e0d9541d8aba256739eae5bbbfad102ff6105f8" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "2887c685af0b7e900a0cf73e59ea4da1198f03f9d6bb8eab7419ab57913db4613af4f5a0fe2f56f2fe971a684051830cf86c1dc80811ccc9ac725847968dcc73";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7c48d58691a6feb3896b37bf2c3f043f28b86958eaf33306f878ad36e3c5bf0e31b7bb9014d90eb87de9b3a3fa80fca12b4b179c5dc5be0759b043537e3b89fb", "4ae9f9b8850d59adbfa2816481461dd33c6edc3ede7254f259fea1e13c818af80d2db25c578b370516057c796fbb25ee30f6c5e6ad5796e0ea4f19d75e9223d3" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "4dbf43f5bd4ec65b0a2ed08d57a895af3f3256999cd1fa3590e01b525268a1d73a6d8e9b005f0dd1ba30696543e50ad6881e2ec16a90a3fb330799c0d33c309b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "52a245adbdba1fb8ebc134e335e31eed7945b0a80e98338d9504f95301659e3ab9ac06be0fc8b617c9e728badca75b312bfe6c47717ee72c0c406291c075339c", "0b2b670aaf3bab09ab9ff57cfca9813d2f1c2cd33d7eaf4c2c820bd41346cee851dd456eb5391ed7f68cbe207acaee57966acbc3bfcee86bab216e7e99a8dc6c" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "2f11c89465684e0fa7be9442d3fbb654f576d4007760ca2e01fc1292896fe32b859cc1c4ae229ada8d7a3a97714f71cddda1d6df6aaea3588cafb4d7fa2aa775";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4b8ec1fc5f47d9bb1b3093ee9a362bb55fe1866df0ddc1df985ed1c4b8cf2e7309093633270d50c56b65d6ae9162cec891c7c7253642c7be3e0d5a744fd8b093", "00914f0a09325788cfc22c7520a93bb10c28938474ccf40f70d97dee97b720371b2c2d68a2ce539fae02510dd500e3afdc27bc288b85776acb02579dab7742f61e" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "23454a8b6947300e1ec258c437e73c99a311842343a3adedf78c7c07e1a78940d9d384b3578e3a81f1e3b10c6497ac1678eb2b3d0f488eb633909befcd6a654c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a8a4784dd8ecf04a038102acaba7741a45ca351b2bbd053343bba336da9f8276a8b624fefcb79fa703ff59fcee49ba016934b18f40d03d72382edfe2f08c4904", "22e46cf4df5ee9473ffe860c4d1ea26c4577f30656853746926ed87247f0d684de11d12a25e36ded85fa9fe5cf96393749eb392e7857e2cf12e7ce5343b4e51d" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "240fe194ded1b3052326c2d494cdc1e188a0976b58469466db614fac8332c5a5969de23cc01d8a06adff67b70e53fc6321ec787688d6f4371fdd7a24ccc37472";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "79dfc2a4d98bf5e4dde41b6ebcb2b2a83923392c42148726b702f76db5654cf8d210da714fd9a6add863d59a60ad3e098001ee91801ace759a7adf546e740dc4", "009e1d3db77f8eb0469e85efcc71fed2cba9fc2da05373dba07a76b68c18f85c454730a546a215a606f195a98d442e52137d1a8533bae7937ccf8a4c3ae4f7bf86" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "5398eff2db5e32e09b0a36e53c02cf2b859073e665ebb0dadb4d3af22e87dc2987f4ee0acccc174aaa057e3f48e67fa2d059b04f310c788bdd0b8992bb7eec8b";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0096ead5f90bc2e698a34fb04666218d801894e97efe8e656a33ed2a9c3055b460ca03cca9139d3c3466a757f9a5d20d31205a50c16a5319185a1e1fa6f2f4476a", "3e33a0d50eb6efea22cfbf9498337adb7e767016f2c392aabae1dcd1e165f99e78c47a991b158a9ddbd909c75df3b74745a91b18b8972d5fb70d93eda1c69614" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "53cd7557416ef209fbc9ee0a01e16e6c99b6e49373d5d12d475db5f87729506b6fceac8998666c4f6d42f3da0127ed210e6c09da38f55c4a87cdd758ae1cc07a";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2e59cc4375d1105f014493e0498d28a68f74f119891d6c4d75972101059407b57f2019772cbece06e45e858ee1d081e8a608ed8aff578540a468082a01fdd08c", "1fa24f6cad49b77710f1a1f5bd4a90440f857cde44947f4a1a5276fb847359405ace19e317adffe40ce15b5304bd1b6ea6773b10a59b9052006cc397944f93ae" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "431d863b08aebdbd2e7391372d74d61960e3e52c2c415d51a92875511e1b1abcb4283104f0cd5cc00c15d8ea8d61f155452de73032288972f24566f16707498f";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5132b247407f75889e0732954c367f74c11b0bbac0aaee34b885f1f0119fb183087f3845c13f872b4fa7ef7e989a83eec039e6e1fa7fbd340817ec6d62991c7c", "79acdb13801995a4d12943f5f70afd3cb72f6485a6dadd6480b467826c980881fe7656454c37d588ea6b716dbc74f6395c0a7557ec6679015382bd62d4ee10e2" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "258b4b91502c1ebed15fa6c5ea6159c8310fb182c42881f5ca0e402a62e2496e2a2e8cf25f3c6afaacfbf45264fe00531dcff0f09818a23f7162c1d1dc01e322";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1654013d5abe7f52eaf8e8876b36f0dc255e5ad7655334abc31d816b9c9f15ec3ec1fdb7652666c044d93fbb85ee577357011854117cee4733c5163d3b09fee7", "4d9cf5f0e654d37270ea72b8bb8b1bacdcc2a4455023b097a2691d47399b71785af639d4f5590358a18a999565ebaaeb52c1a0b53cda9b97de3d51c4645c4de8" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "1a4332df67419f9d37cf337de521727b50ef133c0263aaf2b9e34cd2fc01b446930d4b8b4b3d5f626c5c14c5592b564bc8c2d8b93043022290ae36505b4f774c";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "627e1f72fe43c73375275757c0916a9df1c10f777f50baae6dbd85237ed802fe43896cee6e96edac4111905822c3465b04f3adbc4cfd2a70267edbe6b19df08e", "17e2045b1110b128ef049b707dda2bb6b7537b4f2860d71bd5394b7b8a4969d46613d1c090ea48020a4ce1e8c0e57a2fe66c4360a65a37c211a9f4987baf3394" );
            {
                // edge case modular inverse
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "0da99c942e117eaee5c4109d7dfbc571cfc4722696bb5a1b36dfd53f1b70ee797d895a2f7da21aef675f6cb366472f400061a2aaac587be49d1b1df49e79e786";
                auto r = true; // result = valid - flags: ['ModularInverse', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "417db8e95f89131457983e75379009905d2d8008b790519d65e650d3b60a32563c18c5afd06ca314bc3a17746087a578ce78cbb60cb599cf0dd9cff22acb84cf", "0b86f2e57ce298c85bc28f3d0274cf3140ea5fc6015f4b636fb271da09445e15adcb60ae1f6d001ad4e25e6d69767236cc16e725f5d7b2af449939017a8c8c85" );
            {
                // point at infinity during verify
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = false; // result = invalid - flags: ['PointDuplication', 'ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009a8e0c2aa4955203df866d44ea320d62fa43f1baeabccd34ec0849b3fa19be2900ca10677c036da9dbb51ca60381cd58dfab9b2a1f6f776b712a22d6575785d5", "1bed652cf775d91bff11f988654ade8dd28415b7c0de7d2c7424256c3fd71e9c4fabf1eff380fde6f8a8fe0d1560d121ba65618451ef60f935d292ac2a26729c" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "23face62062ced95c7888fcf7d4c5af3d2a2a1cbf08693264969621882738ad798476fac70361bbf2cc79c249fc50271c1bfdc3f5bca20ebccea8c3658f8d4e3", "073c1a74b3c46a205d97077833dca1f363f76f67b68ee176438528aa76abbc36b6f0a988fb225fe7a33ee8851ff24e37138243e2b21da852a334dbd036cf1039" );
            {
                // edge case for signature malleability
                auto m = "313233343030"_hex;
                bn_t sig_r = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548034";
                bn_t sig_s = "556ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548035";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "38597c68eabfbe648bca0b3e8d235f9082cf15d694e14e686b1e0a89b73e3dbc346ebbde38da2c602fe975c21a1fbc8f363b592903d02d4434fae52ee8cc3b3a", "572b82084747ea5af0633936b570354365ee2d7fba4c404bd69458eb825007ed89067effec6b2e67c32d197e8c28ecfefa7ee79cea09d7eb248925c543c30ba5" );
            {
                // u1 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009d60ec91976a8fc7f8422876ccb22870eca8d39b8cdfc30193e3bb22a10e37c537a092dbb0124c8c4b26655ad96127d3140bc1f9556ebabf477fd95951b4b0dd", "2bc1fcd7d6840fd83a5e982361c304a34ed10e873aa4637ecac29f555c0526b519c238ce0b002d7e2f98225dec884c95d742e86fa68ce6e81f6542fe81730cfb" );
            {
                // u1 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "66e59cbcf0f0a0fee7256d52661cf74b816308a77a7c9e8c4130461a4d1205eedfc32b5fba90829c8425409283eab77c74fcf1d45571da5a372a026368794c9d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a911df350e95c0da4d56c3c44a84aad88ee85e628ccc44c5e131dfad8a3fc69eed9c620ed8c821c84de2c2113c1d6c10aaea5544903b1d59678d39b052e0f1b3", "00a2c16d1e74ae6fd993b986234665eda14ff678e58c414ae55de8aa1eda26242d616b267e6fdb7491efb5a3c179b84903127070e5e2597d2f0b2af333b6349857" );
            {
                // u2 == 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "01823db8fd2ba4a34bacc4f64283909f4d01d02b8db66f9cb9bd77806b890ba31a6915b93dcbdd72c83338eb6029f22c31795712b1ac7a1fb81a304e3c58d8d5", "4ec267bad3984a3e2fd87defbe863d73885872488bdda9d6e3da8ecf8eabfd4674d201278ffc63cbc1ffa0f99eb5e85c9b20ae10a226e1e5594ca78fc0d531d8" );
            {
                // u2 == n - 1
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "71e913d0929bd85cd53899c977dbfd5a8775b3cd22868c09e4426886f5775af58e2992d6331b6ebb810440bbaa72b584be768d00b03e91e923afb9ac6870aaf1";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009fa44401db098e9f28579aaf02adff61faf1e6f7039cf1b3134b83dfba962b13a4397dcdd6feef4b64fc32eb3dfba3f596f5f75beabd3dade484089310b65822", "008bb1897c75da51e56db19d8df13623754a0db9d6da5002ffc8a73be21b80eeecca35ec541e81831b3fec4cc3193dc5929f12c4c463a4107911bbb0f15ae390ef" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "4f9c8a3c424ba2b2882c200355d25596b1aa063ff9b2573079325128dbc6ae5098e88460f4eb4331ffa2808ad3cf2305eccce70f3e6df3cb114c638b459d9167";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0fe7f7ca44453560e1ba38b34ec8dfbc745edefc58878255452f614fee561a8a620b4d8624e159bd483db08c9a62100fd2ea69ef7381f520abe651b2ea226eea", "156e75af465b22d226408314536d4238a739fd2f4003bac552ae34bfa27e9be460fe40a5468cedd3221048cd1b8d796bc27494565f88aaf7fccc4c0fc36b78b1" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2820c603534f430db8e49727244a316acd6ea30733070dc4fdd24e2211dded80597a9cb6bd866f37b255057ab771925eb439293319a9a2c12dc0b7cb1dbf4fa7";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0099e5c3ad1ef53ad780c3c4d90c27cc1986496a215b25829a88de200a9c2146aec8f182dc6dec6611c7ffda1a55b0ccb2045b1ed5c9231b9eb3cb232417e2fcfa", "35e8b3f604f5d793d135ce06e23fc6ac82c0997de9e3f4d2dc3636ba0b521c785776dbc8d48da5d59a86fb3e90fb00bccb017d25100be8e35db1dfb5b44967ef" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "6e5d2dd1e3d278ebc6f73409651ebc46b65c6c3efe1165b74b5164356783251e3bb666804faa7bf389b5ff285b66b912c51c478c58cd2dbe5293d95735ab9436";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "423fc7aa8d6d77fae60bebce7757e15689426cbabd2c3fa6ff71da7765ab887a93c93cb8e1008892c0d8f1e03e48555c81dfc433d42f4890b71177b848aab9cc", "1ff6abd7c7f953de797480e292b987ddf47570d88dc5e51c7a47c357d71978190931976f55cc84c3a4cd4635ed5ba4920efa8219c7aa1685bf1a9bc7129fa2cb" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2bd0ea22df17e2f0854094002df56a63da80713274b5192327b1d86c256437bd10f7a21e1c7480836dea40f56ee9b5810c68f2a06e728a802d01b5a514db6914";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "415e9d50af5da71189607811680dc16d3da9a0e339a53d166b9b226806a6ffdae01eb40295cf5e00f47ddf0b4afa6729a8f7d18a437d157df4d99c19181ef524", "00907efdc15b338664e911b62f9ac015d9e36bb7be0cccdf330517d52970dab18848bce0bfdfc0bd39c675753666036e4c4c5eb0c62321b22bd1cb1fa352670fbc" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "3da945bb815ee5303a05dc5eec3285b0a1edf43be7caa19fc8f5ac06122b3451d85b7df2da41f347e2e51458f39d4d16c3cc87aad7b451758d3afd9729659156";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2c65b61fa1f4d3c86c829d15d4de5b47c5b789f53a4355661f09eef3b97b21a3b93fae0f035bf347a315594785059b37ccf8062a391ace30e69a984d8417ca2c", "341a8019653ad617da57c9997c2debfaf340a6780bd8371aee2c668b7dcc70fe06789b8f36f8f13f40822f0401102e03742c8ffaa1dcf0baf981c7ecc1a7e278" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "7b528b7702bdca60740bb8bdd8650b6143dbe877cf95433f91eb580c245668a3b0b6fbe5b483e68fc5ca28b1e73a9a2d87990f55af68a2eb1a75fb2e52cb22ac";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6a8222da632550f85a0d59fa8e8f327e16274b6397d5a42aa1bf6f1a1b5cedd3a1182dd0f22fca690c5ef5a261e6e5d8bae34f2e1ae294b50a287c882574ee7c", "0082d86218782338757b9bab359e63516ce3dbf5e7fdbd5baa4ae99713fe5dd85bb61ea12a178cfb50a25eef41a085dcd5e5b88f148badf4c8f4031e03d49aec6b" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2d17048ee57e45b66057acfab9c3b2a4939e81b1eb0f8972a8c2b5aa6b04c15584894e168e15dc5cf889fa09f7934d1084def351042c2b97cde3c100b894bad3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aa17b5bd2bbfce1ae133e2479fe1f87e64e6165897ee457391bc2daee9fd7686b8d4bec8ecfa8a5693f39b4ef9b4163cdbc5c4546fadba0cfe3e1532ea2aadd4", "73fa93039717f9dfd49a9c2884dc2d1012d71d6054ea0f391685bde5e8c0d5d611b40bd1fbe35dc5bd7e916ddc9a66ba54ae8949776f2f21d4cf54b2f6c757c5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2b18986d87bd21cdcbf0f13103794735979354290c43aa8c298dbd473de5a389cb55f00c2184a235f6b7347305926c0e25785eca6d98eb2bd921562164f365f0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00a72de8d4d2896f9bc6d72a68f8b2588fa2ecb4992e8e3616fd58a1a12f0327db1fc3740ed384022078156fe66712bf092cabbc43659cddc9cf3dbf807bcf3635", "008819319aef0e23b142e75d9c4c139812e55e1c419d96084a68b950356c46eb2357512f208bb1dbe970d1900c8dfda77d2f477760db63d228dbf8b342265bcbde" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "445f8caaf2093f6882bc6c7af537ebacbf8620f0b6ac68a19a5de1935225cc949c24365504222938c56982b824bbee59253f4a866485149ec4c5b5ec9ad74ec3";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "37d8519f0c7492ff443bad34cbd54eee9ba120e41fbb9fd604cdd6d41b762bf2bba392d4f4646978730f6556662b99768dcb2754c180c0fbd8ad707636d8f8b1", "43b17d728ffeac454019530d2bb0f69a58535a2e8e609ff69596d53d11a00e6f650d49d9a5f211204b4e5a421c757f8e1738955df96bad5bfdd71e155a932d1f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2da089be4ccf10ec5bd463556efbd3388cc343b9dd0bbd6f2e98a5d0ca362d0fde2aebf02bdef173a0f1f04755ee76a098727638e4f7f389521d997bab85b781";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2afb786d246b43a53df6841d04d4c7705357939697714ed4681dc595188191877a46f3c6bbc63170406e0c6db7dd6789a644738f7d0acb7c9e5959c01e39e975", "20327e6e5c925198b74af0beb51a83ea662efbc3f85bba8924046b97dacb0717d6b7f422d8426625ea7f6b4ce865dfab264ba5247b4dad3e2ca5614bff4c0d5f" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "5b41137c999e21d8b7a8c6aaddf7a67119868773ba177ade5d314ba1946c5a1fbc55d7e057bde2e741e3e08eabdced4130e4ec71c9efe712a43b32f7570b6f02";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1b419aa39d3e3125ae705f77885c3b11387bc422fadbba7eb0a66ac14ae26c0f978333dce64e4fe0d3bdbc6d52adcee3b51493a26d21376bef764e0628dfbb12", "73ee3ef2eae04a27e798323d50e0f4fefbc43fc4613677311da858f83e5d9b3b9e41af6c5582908a3ef2948e4b5dc8c5b8a590b3ceda18e4c4cc05ddc268dcfe" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "88e19d3ae66d32c5137d2a004cf379a9a649cb2d9723384d8bc9f1725ea2872f9a80c3d0839cd45ae2d5d0d601cb63e1c95762aaaee7da9bf658cc7302912683";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "327a6e5e4ef2bec0631e13354094cca4df5bc4018a0572c00873543d98100ac09d76d27bd6e0bc2dc96bd8cbbe19aec0c141320ffd64aedba5c17a1be4bd2960", "78dccc453c2aa7e92a7734823306c6c1ae3e52131edbfa5fddb719c8d5d00ba3d38baa8fb727bb941e21baff375503c27eed7046fa6d00c70ef136e01d36efd5" );
            {
                // edge case for u1
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "372e96e8f1e93c75e37b9a04b28f5e235b2e361f7f08b2dba5a8b21ab3c1928f1ddb334027d53df9c4daff942db35c89628e23c62c6696df2949ecab9ad5ca1b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009aa189b5b1e5b66641c7ec3fa7d0dbb6a72d874d18c7927cac8470a70969f35705bc73182abc10b5a16955889619bcba6ff310209473c3120e44a2e1bf9fc9c7", "2e5de74749a05227509a2b3d0322a8f9020709cb8e5da67dfee28e96e0ab8a1c3208055d1f08f38fa1cc79c119ff704592a8eef58bf66204b81ad0b0abdd0390" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "439a859d7aaf99f57205f210c93ab89c317bd2fa215e7903a67976d336d83b1bf9719067077420078f837514d607ae3981185dc7b02627b05ac66e491a2b94c5", "4c3fa47a926dbd6945aca6d404f85f46e070d04e7dabf6fa9cb88c3428dd02fd01a9b190bb61dfb7b2439e42d0b689aef968356b011cf3054ab929c85777e652" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "48d7851b079f620209e8ba05eb24ee515964d37577c7c3ae309ab2bddd7eee7101899d0c6c780111bede61ed1215ec42399409d605eccc9aac4c9548f87770df";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "66fa158c51d3a9421cbb133799ab90a12387ec7875a2b354b8487673495bb1879ef1672f4928a2034095a02c7d083f27e0eac0a40b87d837f52e7648200c5666", "278037cd7e5e8bc6821027b21a2ca7ae9c694ae809966b79d441dcdc9d3b444f8793122f30956ae0a7aadfbe431a342dcd857095bd058a742ba58af18b1a519b" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "0e6cf68d5be5138253de290ec41bde7dcf96065c280d0a09d9a4888d5de04dbea75038fc061b653340696c62baaea92d5747e50249034c427f2f813e2b98c24b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "29bdf2feb76740763f5098cfd5efaca5fa2b19654bd4e8d5d75978b90520e7483875bfbe2ac0e57adf90cc140af59821786724e5eab9111445a2de4b3768774c", "32ae3979b352dcfb0c72e8f6799ab76415428a9956ca5d2b14d74b9a1be189bcd3032f742ec94744c33a3cdca10dff4d5b07929660d6e78729ada6e5be9ae101" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "41b2af78294165d86f751cb82a80327a0eb4c0544a06d4a5719aea4a098f115973aff4c1a8cec2dcf0f5f0fa24190b474a25b9ab3baef7770f68ba9c7ef7f7ca";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0080af1bb9dfce00963799e01aecbf8bf5a659b6bbfa4689f0674a6115bcdf996d155d9a75c5295141e2cc3e611b32c589e6ae76aef190dc8a363ba9f9c3cc5727", "038cd95bcd34420e63ae435afed09f70e4ebc3501b42f35ebbecd8b0a165c61616090b118ef05a43c31f3b710907c745264b1f537c28596a403c25195e87545e" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "9c5fc3fbf70f16ccdac92f95974408ffff7e05bd0268cfdf862e9beb174fb48ee1e0e10f942d8fc67ed69f7a94c85f61c84048617e67c1cc6c0260e048641a6a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "6eeb4735286c2c094dda29710a774eccdb6ca5fa8991f9adbc769b448d3899943c860e3fb50cff34825adaee82aab5a533adaf74fbfe7e8b032e2642fa5fc86f", "5ef74aa61a26823bc2ed70f08b64a6906db981564d5e0c15a076a582da8fee20b773ef591f9054da34d90a1f1317294610a81d3e0f1adce4f6d2fd6ba4b93501" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "8de1ea3f1234690e75bd787cfabe15f833cb7dc65107cdb035f99b0bbe6c60ad6e8365dddbb1f973bc26dddba9e4ae7c72cebd41f471a8bb227d2b3df41f346b";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00938841937550134c5a4bade19a5021c73cffc774fdca875413a7d541e65145fb77dad4a7c7eb3a966c184d73cdcf3f1bea984ad25dd4fb7f47239faa5b539f6d", "3275cde53c18f3bb537a7f06c7ea1b4f355025919002bae9a3a3c1dcf150c1b53bc8dfe53f60cc785e44051c95b735552ba622897d5bf7556fd7b9e38b6531be" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "326a7e59c4bcf9ba52235a8e06d244557acf66885b64f9238cddb3be327b6205758b60f3203418cbe5b330e28a9d7a360edfb8ddf39d46340d5c2792824b7c6d";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "78fbd1e762019602ff7187cf06a886d2ed2cb5d06481b06c3c4be4f7f3746cd0151d57f4d6aebd6048895cabfe9500adf3daec59ffa6ee9621c8b584ed6dad1a", "6f3c2070e01421a1ebb969607d44f76778748bcb559a8b5eed83b04760ab53556b0039e8765ab85a92950c10ca6bbdcc9d6e2f03d88b6d7bbdcd53c8b1ff86cc" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "3c5d08339f2f6f97a2b86b83296678f7bff61e1b7487cda14f3b12fce6aeafa3f2fb385aea3e82f312a6880efd18a1d77fd7faafaf9d1ecc5ee9c2c0f71d10d9";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "4c9ada2fa2acf8d01fba2b015f7badc322785c85f2199b6c4ac490da8e1ec973387f4abe26d526a056dc7195fb1c9c0ca7612cb65f15f106380d8c5dece529f3", "2172c8b9b3b6fb0bbe9f2273d9a218bd512479dd27605b2a6e8b44f58d176178390c2bdd1ccf60c1e823a23e8b0fce7dab2f197913b1fe30f699e3bf366bf1bf" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "9584a4bdf0c6c8ca72211f589dcdd7be181accb926f2430dc7135abbfa7887d606030c85c72f5a3c05fcc7e0d1fb33afc0251fd33ea04b3b96470bc26ce612ab";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00854cf9601010be20633f5d17214cab687dab3aa54a38a02c55ed003615ec8efada2ac0d62d923d0e1df9aa382d512706cadf5539858a62a5ec62fd8248e63277", "6a783303285206018cbb9fc1e98cdf94ac6f2fecbdc7d8428ff485e59b00b2bfa45a06aaa93e6b51b7ad1b8ac0dbe135455d8d2875231357060990abcde563de" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "40197987189f8cf04a951e01c48fa8ae9042f184848f93b215dc790fe2c42ee2d549d8cb50ff3db74b6ddb376a80b2ce3983946b2ed99819856e75ebf8ff2ae0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "5e3de509f7585c0f6d05c387a6d07a061c9f98c6adc8b3c36efbdefcbff2e6ad4678960524d116154f5b17332204e3a1867082d2e518504f433e2726ad58e9d7", "00a0b32e9d3c523bac3c1ccdd75f82b909a8306c74be899f13228abf87db76b9115c0b293d7d30f3c86230461b28a45a6cc88b8fe079143103c5b01016ba95bcd5" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "8032f30e313f19e0952a3c03891f515d2085e309091f27642bb8f21fc5885dc5aa93b196a1fe7b6e96dbb66ed501659c730728d65db330330adcebd7f1fe55c0";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "15d2ffcd4617eb1b400610cba8d738c76c8e15ad72b34e576772ae19cd8345294644d13ac62a293788de2a92dd547c2ac3a98aba72952d3ea2d491d7eea5b9cb", "00a3ec2c79a2cf7ba0083933b2c534fd4b51587c4ebc3cbaaa28d92b95e3c8e90142effac27bbab215ac0b39d1c5f332feb779351a66c294e4ed62f5cd3229a923" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "156ecedc6df4e2459fea735719e4fe03e59846d9d9e4e9076b31ce65381984382a9f2e20a654930ca0c3308cbfd608238ed8e9c0842eed6edac3cb414e548037";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00974df3e7a61283830e544ba9023479cb8d7559524df76fb38d23c55d29923e72ec5cb48717fab859f2f3111585bbee004595c5fed64411fbbf9f6351bf5f69e8", "4e1fdd691b30b0b4c2590a881ce458053349356da747cd93ba931eee6ae88cae827007105c3b1633a48e1c9db5272ac01145aee6132ba73af83d6e6c4106b290" );
            {
                // edge case for u2
                auto m = "313233343030"_hex;
                bn_t sig_r = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb";
                bn_t sig_s = "5ca54a231be76c06c9d987de7bf2ed42cd634a07edeb6e0c580412abe709ab177e474a9ea96245a640f7e6be1d2d5cba3a7cdc41a8b093901a5b8be06420e15a";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2cb7364ccec9148a3242eee17ce01d82a56d037cb01746fdd24b893f35e072827ce463adafca6282d93cf666a740ee88adbef241f17955d2bf5f9f95958a38a6", "0096da5643e5fe057f1c3b931e36d33f0e2f5fba680932a35987b79855b6c1f0ead64cbe9c72959ece2184ee65a768410df1dad81c4dba853340a2396abf82e36a" );
            {
                // point duplication during verification
                auto m = "313233343030"_hex;
                bn_t sig_r = "1b8e8440bd94752dc603159728a346872cad48dfff819f181f9d53537a80868bff1280acfd2397a846d3259049352bc11f5fb739410c766d1344cbcbc03bf761";
                bn_t sig_s = "21610740799a83a13b49aa45dd854d85b058bd955a4105d749cba74b8f2a38cf7c33ed56921d029e7493894ad3d8f28f4431dceb89cd56316de93dc09777ca10";
                auto r = true; // result = valid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2cb7364ccec9148a3242eee17ce01d82a56d037cb01746fdd24b893f35e072827ce463adafca6282d93cf666a740ee88adbef241f17955d2bf5f9f95958a38a6", "14034774f5ebbf0c2399538ffcf6bcf99bd0d34baa972eb54eac0474b9711786a700dc642930c9748d48b2c53f3b3fd836a72712dfc84151e80826eb98b76589" );
            {
                // duplication bug
                auto m = "313233343030"_hex;
                bn_t sig_r = "1b8e8440bd94752dc603159728a346872cad48dfff819f181f9d53537a80868bff1280acfd2397a846d3259049352bc11f5fb739410c766d1344cbcbc03bf761";
                bn_t sig_s = "21610740799a83a13b49aa45dd854d85b058bd955a4105d749cba74b8f2a38cf7c33ed56921d029e7493894ad3d8f28f4431dceb89cd56316de93dc09777ca10";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "063d566fa93ee219482ec947e7be4694f9c073b2bb786db849e1f3973c5122394cf68edd9947b58e61fe42c98d3640844ed2775b0c36b5f4c0c9605d028bc0c5", "07521b29889632bb0756fec98e8e956cb7ac515a3fc9082b871861548e9702786f591e9a222391014725167a6c22aaf8c2c4be9425248b4d5f94f31cbd8bd352" );
            {
                // comparison with point at infinity
                auto m = "313233343030"_hex;
                bn_t sig_r = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce1";
                auto r = false; // result = invalid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "13b9a0273b3b283cc8a25aaaf2a8508a745db022e7f4ddc06acdf06eb7770fd95ba68b047b030419aec366bd187eb840a43df7d9439419e2639614d5b4eb22d2", "3ba9a5c0301708dc50ab9e4ad4ed48ad0f701cf387f210e57b6d06fb69cd58dfb0685f89d9ed1a319f00151d9082663046cc27101b692ca22a6b3e083dd0ff7f" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "45d4d4ad6b3aaf94b6d739a072f31b1e744f13876304ea11113fe8123a155e1a921be46cde2f2412e02a0fa5c1865db8a6dbd44eeac165b0f7fa73c04783802d", "1cb951cc65c9056480695bc467dca577964cee048a14c81716ce9558b450981cf3a0f0059d581b076afb69efe0a505357b8060e02d6b9f13a031a1dae5f1ce3c" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "7a0c02f1c1a6fa1a522a5ba1006bb4059122ae5bc9902853bdb4ddb52b922a996175af9c5b543fc8e5a920c9120d3032cc114dee73b0c0e781a9fdcb022f9294";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "009060430c4439c352cbc08cd0906f91464ce37a7974de996525758628b9d3580540afe9be74ba1050d03acbb0ac29e60aca9b96295a6b5e49707410257fb7639d", "59f888ad8a62becde0661defeee48135d36167f9e8580f2714bcd5b67ec70ae3deae5d80b1e9d10c13f21ce7c59c79ac2cf705aee890adf434f29aa841a05b0f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "88b14afa4987d06f6643ebbe8fd4c99fd5c0715c8fd4a80bdeb6170859c26d26aa9849cdd6edb814346b80e132f00d05b15b0f9a6d17e24af79fab9bb0873387";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7326137c699e6b1d2bf313c04c34b86e63293d7e2054e47187ef843fb42674f65b7e0136ecdaf8e411c6e2dbbf5ac5007401743ec7244e7dac0379516bb92f39", "0092e546d01c1655cf68549391d8582035ee471e58f433ea89f38f8cc1edc1928225b3f5a376e015cee6ae9e1eaae609be2e69537e596b06b77e4b6b7482fab60b" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "56bd4e3ca322f65c29b611f79f3f950f21638e026fccf673b08cffc73cc39495ced5b88e26419ebde75c85fdff1460947ef7afe99aca5878b1af79688181e323", "69e646bb9d01a10cc4931259dc8f597d95e85ebd56729098cfab1443165e558f053698b0bb4f44222ea245ac4c21717eb22aaff650a329eee24203841c59d13f" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "30d19ac71a42ca70edaa8b0d335e48023a0ddf57ea39a9bb18aebf1544a0ddd6f3c8aca4f154e6505bdd40506d9ee01451a0859294ad19f633dd98b79a796dd5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "688d0f394acb16119e0b29b56e780f295a24dcba1615a23e59e67b1dc9549bff8791a62130d4b0d8d75739f06dfc08cf6b5cb1e31a63bc72b1fad6f058b1cd59", "009f9446ae8a7f41bdfbac1ddbcdd6e6490193260dcdada072079cbf139b666cf5934f11abf572a33e7f1235cdf70820a5475d14eced67ad6a4a8578f9b6e4093c" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "9f4945f680edf9800a63285758f399b3d18d8141b8a18064a30d3035f4cb6581957877f3a8f0f72597116e702915a4f4f698f404089a4cc5080447def02f4850";
                bn_t sig_s = "10b989002855ffafbd8c23a661f3b93ccfff4fbe84a23d1a6c4aff4405bdb94c3f860224e205032fdc9a1dc80c7d6b21409f9632e0fb540021ccc42161b70f1c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0083672d9b61f73f1a0b2e066bc3d009749d28d4e584a1afea28dcffd78b6b2d659dbb0c5cf7bed61f3b03c3c129e31d4b49ca8da3813cf25b6f025d84ee82d561", "379be7f5c837fd23e0acd749167549e8703dbad3bc7add9d3a9ff01abd34b55342f532428d95cc1f0c9bae7f458d9411919a2816009658224218851b0f8d5720" );
            {
                // extreme value for k and edgecase s
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "38f489e8494dec2e6a9c4ce4bbedfead43bad9e691434604f22134437abbad7ac714c96b198db75dc082205dd5395ac25f3b4680581f48f491d7dcd634385578";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7386a10991c1475c6c53f05867e69a35219bc5cad4405c960322843a56bb07bbaa317d20a0bc98786ab7b4c0cf6deadf093bb07d5bd563c0d56b380f880e7ad1", "009819e9e897c76405dafbe1d785b3bff2e6e48770ada1f452ec2b4a347bdaba7b6d7122002d5f6ec4cabc585b4ef830e52c624641fe038297805ef0b7e8e82bdd" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "7a0c02f1c1a6fa1a522a5ba1006bb4059122ae5bc9902853bdb4ddb52b922a996175af9c5b543fc8e5a920c9120d3032cc114dee73b0c0e781a9fdcb022f9294";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7d76f09db5fc7ed767dfad2af9af5470a43e062f21492499af5fc719f6be17881957ef476688fa3049b13d48c51f259e5d60434465d84445d359b89f66c88bac", "420661699273b23838827c69908978064b7c98f4195ad5e2ec709a036ead56e34a3e999e8c37ddea5b00490a011d9d116676e9022c124b3c0818bcc3488f78d3" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "88b14afa4987d06f6643ebbe8fd4c99fd5c0715c8fd4a80bdeb6170859c26d26aa9849cdd6edb814346b80e132f00d05b15b0f9a6d17e24af79fab9bb0873387";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "2a3a7f8815983c9251df9220cb5f424f4d8eb9cfce3d96de725bbea6dbfefe226d789fef8533194787668b66f8fb640d135a25a30f5a25111ddcfc5c9c7eb22d", "009ba35f3054ac439e0f558ead8d0979a0fab046a47aa0339ef16c0e1d37e4d1d6f29fb7f674dd51ed57233409ac9e505e29d40378897194cf5fbc92595fd774be" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "222c52be9261f41bd990faefa3f53267f5701c5723f52a02f7ad85c216709b49aaa6127375bb6e050d1ae0384cbc03416c56c3e69b45f892bde7eae6ec21cce2";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "03f498f2ea6e36b498ac66463a06708fb931ac59a2a1dfa6ebb4973cf01a06ceef58b344b85e89fc78351211f71fd1f11818f7ef96e296466b0d3b70c2da6920", "64aa78285439f17d69a98cae8a1379bdac05ced930a18f44939bd91f8669a37fe8fb1e9ab1ead4db0b337ac594fd21d9e0d4325ab7ee07208f1c07601bb91320" );
            {
                // extreme value for k and s^-1
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "30d19ac71a42ca70edaa8b0d335e48023a0ddf57ea39a9bb18aebf1544a0ddd6f3c8aca4f154e6505bdd40506d9ee01451a0859294ad19f633dd98b79a796dd5";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7bb5f9efbcc260b08120c7c4193566133322ce47e666047edfb462fbc310bb06503e8d62d0cf6055e271a8187be22dc5a1d6b09704a3b99065edb87b46c2ae32", "401f0040048f947fa02017bca61ab6d6353fc58807bba2f0a46521e20f2066824ec84bae1b545a414a296adee22315fd48573a7c5b3bd4c5398b27d7f2824f2c" );
            {
                // extreme value for k
                auto m = "313233343030"_hex;
                bn_t sig_r = "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822";
                bn_t sig_s = "10b989002855ffafbd8c23a661f3b93ccfff4fbe84a23d1a6c4aff4405bdb94c3f860224e205032fdc9a1dc80c7d6b21409f9632e0fb540021ccc42161b70f1c";
                auto r = true; // result = valid - flags: ['ArithmeticError']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                bn_t sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "66e59cbcf0f0a0fee7256d52661cf74b816308a77a7c9e8c4130461a4d1205eedfc32b5fba90829c8425409283eab77c74fcf1d45571da5a372a026368794c9d";
                sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0081aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", "2cff655b8586919e7eea27046451d909d92696b38f2456f43662d76ee813875fca70bcb751671fe4530355525c7c1d3756b7d3ff8492727eafdd42471d624061" );
            {
                // public key shares x-coordinate with generator
                auto m = "313233343030"_hex;
                bn_t sig_r = "43f800fbeaf9238c58af795bcdad04bc49cd850c394d3382953356b023210281757b30e19218a37cbd612086fbc158caa8b4e1acb2ec00837e5d941f342fb3cc";
                bn_t sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                auto r = false; // result = invalid - flags: ['PointDuplication']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // public key shares x-coordinate with generator
                m = "313233343030"_hex;
                sig_r = "66e59cbcf0f0a0fee7256d52661cf74b816308a77a7c9e8c4130461a4d1205eedfc32b5fba90829c8425409283eab77c74fcf1d45571da5a372a026368794c9d";
                sig_s = "1868cd638d21653876d5458699af24011d06efabf51cd4dd8c575f8aa2506eeb79e4565278aa73282deea02836cf700a28d042c94a568cfb19eecc5bcd3cb6ea";
                r = false; // result = invalid - flags: ['PointDuplication']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "1ec7fe2275860c3bc0e4e6e459af7e16985d37adba7351ac357a7c397e07522ea41bcca8e89777fe05b8f0d9dc8c614004fcaf30a97001a5011a159f46fcd544", "3cbc1ddfc7ac89a1a2f8eef77bf9bba8ade73da2100cb6a371546b495fb5ea885eb631645e79591db659c49266d263d5cbd3403081cb407536efe9a5bec69955" );
            {
                // pseudorandom signature
                auto m = ""_hex;
                bn_t sig_r = "89edf75e6e986305d8181386c16db44ba0d7ff40f4335569754a481f5cd48c6211a63de7bdaa485e9fa79858a4eabf111fed2959f031de2a132ba709412683a9";
                bn_t sig_s = "7a8c08564f51534128bb52fe36dffaae89079011256ef8069e64d64c5610d3e611c0ba8b19027388fccc212523b22c44e85a789e16cb1bbd3240c86b43480fde";
                auto r = true; // result = valid - flags: ['ValidSignature']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "4d7367"_hex;
                sig_r = "225dc2310177ce6267efde9937eff898fb0bad12b0dbeb4fa9c6be6e20f88563e6d2991d47a648b0ba5a7039842dbf883bbd735df793cce0d136023fbfc9be95";
                sig_s = "00d59783d8bd050cf728b3506c16ee4a78ac26c12fd33dadb6ee8146372e4fb2a880ef77eb20ac90f3a4275c1718a033a7c0b2df538eb35827330154191153cb";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "313233343030"_hex;
                sig_r = "61483c729369413144a6be0dd05c1ac29bc440bbdaf87e572aa987e9ca423639f339bcaaad99cb1fa80b7c35416a1834ec04bcf0fe7812c712eb1f06a16daca3";
                sig_s = "41bb956c339ebcf5e4e403c7d8928d5eb4fdf7d3f53a2c06d6c9fac347f603ac3209a2af37516f807b50363b5328bc98b94354af7d59966d160f68e80c6b2dc0";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // pseudorandom signature
                m = "0000000000000000000000000000000000000000"_hex;
                sig_r = "a620880bb7fab1180e3d8f393e4b3343dd4eb1c374f9d61252f8a201d9096ba836721f8e2d8b56cbf406960aae0e50325adfca6b1b529f06a81260bd8b15ff68";
                sig_s = "76537febbc0e24ab4992b576abf8bc0201cacf5ccf674ad3c3b1552c98ca64642eff5401afecab167ec0be195fe5ffa178f14567ef171b4827964a559d079b7a";
                r = true; // result = valid - flags: ['ValidSignature']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30a67deaaf0cee44aaeb903d8cdb24ad9dc191d375d7d6a60d2520e19306cfc47dde9dcb80aae0b040554bb98d601e019f9336e831cccb99f2d92cf4b91604b1", "1a4b00c74a5a61ac196faf4dc39acd41bf354def0a27529964359132a76f28654248d1ac004d11d811aba0acb9c26d2f4a54012c5d8a9a1e7c8b4a52" );
            {
                // y-coordinate of the public key is small
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "479ce8458b04b2dc127b46971e6c79831bf788f65ddc770620daaa15583f8d506f2a6652d82b38560ec1977586e11929b666f6d7012d816fd356d41e9304d60f";
                bn_t sig_s = "a750f73ccaeff5d994067e66e45c200892c607b329be5e64db5c383c7be711c97b5dd425a52250bc862477e28b3afa4ef3d831066a7b143432a5d15403021457";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "685b8b2929c9a0a9b0deb6baefd00e26f50d4c1fc3fed47d7ef812c52b66ec6f6d09f54e9bdb7202016570f75bb9912aab3a572bfb97ea589ace294ff0fe6662";
                sig_s = "4c286267cb87a6be56f4cd0080398c23e569f2ebda71d2cd1682080290deb4143bdc61e75b42abefbcbbddf4c794545a05378656a1858658e0a4595833fc40f6";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small
                m = "4d657373616765"_hex;
                sig_r = "811112d27ca1e434b00c0293320284b1c5369fd007f90e7a99d44c9c02013688d16e5e0a2fc3a077064a995c4244195c04f00323e33adea6b37701ad5cb36216";
                sig_s = "82dd5c3e3642fc43e5c4c652e3b2d00f6d137207be8c9b2125561c08703e4a84d2a82785f775abd18aab24e52f12c5f8cb56b28b915f9c0b1110c542ba92b313";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "30a67deaaf0cee44aaeb903d8cdb24ad9dc191d375d7d6a60d2520e19306cfc47dde9dcb80aae0b040554bb98d601e019f9336e831cccb99f2d92cf4b91604b1", "00aadd9db8c19ec3c3f57a85021a5a4cba0795c071f494841fcc3c4a310bfd773ed5de729b597d9696ae808f52d4f7e0396ebf91ffe32ec558cb1fc637dbaefea1" );
            {
                // y-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "39d0c5c4e48ca14064b2e9b3600deb0ec2fb3e0c65b3be5ce3f206166d76dfc5a5f6ea8702da3aecb13e7b55a87b1263c4884611e5de440f6c89ed12f88ae50f";
                bn_t sig_s = "6ae78398e7f942b35e7d87ef27ce830690f7327ad2a83df56e9d0288b51999454bd90f895e7849f35b2a652a3af97bf55795b4698e0b014ea6ff021a00878f3c";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "7c3ab2e3deafb823ee591dc53c97b389c6d18a8ca9a6ae20c74328606db2d7c7d2bb3ce26894e3f30785237b9e874350d615786381b0c8c420224d2f5e359468";
                sig_s = "34e703dd939b2b1a200872334e2f864dbf26688f8475c9e38a384102e08a18c27d4e30d802095fff3edda6dc1e03aa81aed96719cb49612471fa118875a15c18";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "4cd8a5f1977a3cf8e847a1377359cca7046c793ada0665f2c06908fdcec24e6cd55a1750ca576421b8a65aa99aed863cdaaa77d7f7cf84448ea58e95c57a133c";
                sig_s = "a340572d5d9683e72e157e683ab16d0e2a35030ff3e1641d1b4f801d80732c32b9fbb53fdcaea933f131136f8ab25311018b871f53753782989a87ef231a38ac";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "00aadd9db8bb4189a6d2ab7b5aae550fe8dc00be2e00f4b35b576d6f862c09869210fc82fbd15a54def1442979fa0da1c64408fd8437a60046930820748ecdfc66", "4a59a87eae338d22d0835523156f8f7d934710a747cf192d3e317bc45f0489d6979887c65ec17ab7b5e3da9f4cb110116ef0739849acc56d24e5a3365fcfb289" );
            {
                // x-coordinate of the public key is large
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "53192c28820ec266639fee09e214a55cc0efb07b22dc0d3f293bda2072fcf9b462da93ec9e7169ae1f1148705189f7f15d2cbec46d224197a3a7a924b0c00a32";
                bn_t sig_s = "1b664536aedbdc97bed4dee23eb94a49f23de3bd84a78f299e81edfe017a7d3ca3a7c8aace8d13b6b2eb477b922c439839eacdff2783070757754863582f715d";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "969058c15d675b1b262152a4520f7e803ab465a9e1eeef7b8a5d0fb3e88032b8e8f1be9f37c80f9c7b950f4da950baae9b216ecd6c793ddb1459cfdf49776bae";
                sig_s = "20e0d078a5a113e92facdfe5cb39243247254aa0a656b83e7baa343d36f7b14b86f15e54b71ba7506d5119ff52c47e0ee549927a008cbf2bbfe1916d1cc274b2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key is large
                m = "4d657373616765"_hex;
                sig_r = "1de5df621364436bed5cacf8dbe420e4e4e5d1b0434fcf9dc335645dd0aa07cc1d1ea30a8cafe2531cd4035dd972c0d6c3720f160e24264fd6c41521e44eb0cb";
                sig_s = "72e9abd54561bac89b234bf9e51a3f6003590af177098e25f0053a3ae18a6c74b389674a6eb80378ffd255cfe52323645cdfe9a10a965341b4e47fc0dd082e1e";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "24c10440e37a15d7ec9a3a48965a9ce9380221fc51155f1e992716cd9933d09ce0a5424471877e8994494a4c2ade0a81ef52952e395655157f0b743b3b219e2d", "628fd5ba510f610ee693a1e0d39ef39d91a6248379c622a175a23a5330a88b2d5a60dbf6d249702cd1504561535ea17e1be1b70a41dc463e8e1a1af000000000" );
            {
                // y-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "422fb18cdec966937145b0f160b8ce222b0ba16fab075e16f1dac839b8d7772fee27a283ad722225bebe83db2d5a8b25cb2cbe45248b3aa876554c6a37f81375";
                bn_t sig_s = "7a3889d53bb42a6d41f393eb00c43623937029d4cc1d367469f6ea4ec16658619d2935de0a655adae4cbb624f2ffe3ce41f024269d9149dbd83cb1c97aed41b8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "9836ee7ae0447ec07a6a216633e0a97de831fa04fcd760abe39e8f457796fdfce9c69ed13c827de0ca6b60d849ed6976ac091b7d90ce3e98d3c9144afe638d42";
                sig_s = "1c9d8e142baee857d6adec8eff84ea1d23b05f5482cc2950451586cf5de0cbf9e3a727a4a4e93e15b6cc0125e5fcd1910636898064a63813a0c75fee28041b88";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "0877d7a3ffacf4ef36cbedfd44e4cc0237bdeede8ce0bdfb330bb73b317b7d161c45bd1496e1233ced8f7dcfd05e0e1cc665fb1dc92b54fcbe9b0e55d9ba1be4";
                sig_s = "0f7ab871742ebf22e0b7674614d71569d5084ccc0c98c2e40d088ae88eab37820a89a2dbe49e1b67ec55ae1a34fe4822d691bbf5490fcc2c47e7c1ba4dc56e7a";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0ba18cc05572424a7a391f4b48258a871a0f6d8216c5cf82446c2d156d5586b4c196da0b2f3a23511b89eff31dd4f0c88dbb1a76c5e4b27c4276f8fbc74a1b9d", "00a28cc8c341ea2e3908ae6ab6825f956032c53e625697f80b7b4ee72dcc9f3cff730349e0d30de410917f3d0d1c8988562c1d55583b47f0dec234fda2ffffffff" );
            {
                // y-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "a7322046ba7473716d35742d961ac5f2fe2e1dd574ece7bd15da8c66a262b2e79b0d1df27619fdebbb41da1b27ba7c9a0370ef962ee8a45105f4416d16ebf13e";
                bn_t sig_s = "8418e445db45cfbdc8458055386d65e9bc07b497b8d4bef5f515e7947050d9ab9799fb520f322bf00fae4fae03c1269510ebb3e1dc8cca59298e26945862e9e6";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "1bb460ac42bb3640bfc739a0186ef3362ed27b254f548c073935caa211a1aa302e79a9466d7fece774d250c1aeaef9641b9a2f25e61ca37fada8ee07f49fd51e";
                sig_s = "3d918a07a36f578da8b0d42d30bad60ecfbd603a45d0c1a71bb01447ead81a5313265cc9b5860aba03f1c93a9cb9f3bdd9a85f270dd3691465941d2b8098f93c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "5b44e4fd4996f27a7dcf306bc9fff4a9c36e3fe09026fa72122b64a4ff65f861a5954ce8a41f69a3915c84a63db0c57c6dfecbac4fde99ea5fcb104d6967d613";
                sig_s = "088e7b846d6c5e093a7ba17427bcba0e925acb826e4e9b972b2d8a6d232f635cbe96bf6f163174db646c2f6623c89dc6e4a828d4e2e2fcf3c427c42bdb72efb7";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7f3327e34662274aa147953a007f30c2ee1b06d7bb053e8ce1c9b683f0f46563dd38db071d87433b30380434c92e8cb76d603d1936fba1e9317a06e200000000", "52ca478f0367ab24857e788576f17bfcd05e62d20d0fbefd1b2d954b996eaba67819023635e31483f5b0257f89b46a1d2b9cb2420e1cdb940ceaff5429dd8013" );
            {
                // x-coordinate of the public key has many trailing 0's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "73967eb24e20f0d4ba58895a49f812c28d24e5f0fd5e35f1075810a478d93717c8aa2605ac84226dd3d53c39c0d8c52eeac8e998bad931f5efdd664b57cee555";
                bn_t sig_s = "05b0031fb10dfc7c36ed89aafe66444835cd9c53e1c850af5f055e2b263d3e737a4e6a83cadb9d76dde535e809f447455324d4aee6f036485d4167a6e60eeda5";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "633f456914707923f4b0086ea318b8cebdba5fa14352e3d9c606bd8dabf032835bbda76aa514c1a6dde1b321803d27f253dfe1cae532a5bdcd9e93e5f94596d1";
                sig_s = "9b9c8ba074deeb03745d8ae37c73e02273071a35dcfe0f65e463e208bd11c6ccb3aded6be7313d7a656d5e871b8ea4d1d51b778467b6dde6578e105d56b617d4";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 0's
                m = "4d657373616765"_hex;
                sig_r = "40891a57b9b8f0bc6a8761d2424cb60b3f39de4e601bc8daf15ab3216c2c56ebcc760de30907e89294af5818f5a72a2df409bb6918f3d6e506ce5314602e50c1";
                sig_s = "68620756ee2a600a1467f29608ead019d0d516b79c8a756fc537a9fc734616bfec133839beb4778fdffd3fb4226e51ce4bc09627331c8daef1f711648a30fb06";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "12482f158e62e83467297b4edad930ad319048283f0949300605a4a2d19f72f924d41e1cc3ad2c246574f4a0eb637cdd386c1ebf4a00707b71a646dcffffffff", "18d851ef92835f7be92a25b988ae8d5f7ed42f312f7c896850a589f7bb7500330d138cc20dc5630a7d525926e8f717635ee72937035736ace88f0c491f31930d" );
            {
                // x-coordinate of the public key has many trailing 1's
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "4debd0683028f2335b233c49531b6096e7c5521f75fcb4b5f5e32241be081f3c2b8549b57f31217be9b7aa1a4687a72ec9a5d376307252ca7c1b9b610d25b4d0";
                bn_t sig_s = "04d1303f6b91ac01c91411a983f3abb04f3698b169f8a39ffd1931c061e66f43482fec795dfd0d0abe879fa8db885b618aca2ae013e693f154bb9d0a77adef4f";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "34ac9a4e6fb171f424bb592d1b845bee55173b42422fd5b5132f859a27ddcda5532fd38116e6277d9375639fb25b0f66f1e8a1accaa7800c91c87e7439987d58";
                sig_s = "75892be8e11d9bf3e81e8370af02d88bda83ce0ae9c21aeb487eef4c4c5458e51a99e4d788db84064cfbc48240f56612078769fde0e3b706125f46e2f26a3508";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's
                m = "4d657373616765"_hex;
                sig_r = "36b68b5cad7428803f606615505857aa7cfb683d1e9ce856d499fa6e13ee6a4f235edd00403429ff14bc578dd121fd256004794add4fb8195b43a9e1eefbd3a1";
                sig_s = "45c6affd607f5424a0e49c0f1a72ebf7948a80b482ef171ee161dc36515679e32fa9edaa92c57403e6e102643b77391aedeec2b054964315dedd4cc369f23f03";
                r = true; // result = valid - flags: ['EdgeCasePublicKey']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "727e75d63dceb1a84a7106d802e8eb34a204bc05353567a23ba8b6f54e50d2d8221c87fd8e5238a3374df958b3cf3e3f38c618c1cc8c5b9574b50e405d691218", "37f78918506ea9cc14f1492eb66c9e1c4e27f3cb00bb511d5dfdbea6f817a87bfd81de2955fa032f52873f799169cc445cb0391e46e57179ef84d50c85db5c97" );
            {
                // y-coordinate of the public key is small on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "5e1bf4b1debacba4725fc3cc8214534de5f6e592645b60f4c4a1dd2260d3357d8fb2ada7f72a48346a7e34395a6a181c694048ae8258f1cb3b6f63f4932829eb";
                bn_t sig_s = "5e3df0beee22fa96d4655833862f73b52f12e4c4c7d818b21846effb39d6f09fc35b2d0fac8f5cb3c4051ff45f5305e93b24138a0f95fad2fef1c10cd1dcf2cb";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "80400bee9a342f3afba2dbb029235ad511aedb30960c53bad670460b38304d7cbd706ff98f1296cb7e746f8ca3a43937a5cd035a00c63868001fa429b491bd8e";
                sig_s = "5c66941edcda56228edce77373a7b9dcdd464ed18075e7da1427911778784f8017bef6f18751cba12355bd90ba63b8d31ea373387f36494e3642008082d349d1";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is small on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "4768dfddae4cb83566f2c3a9340091c2608e0e270a4b3f48ded7c75b4aa15ab65cb050cfdb312c32bfaa7759869c9c0ce27f6cdf1fb584379f6398c95ebf8644";
                sig_s = "7e1a3aacd8d603faecf87902147b67435d992ee9e543f934dd4c40d8a12cd1e10366d0743d7862b9c8ba8b6816639c3509b5caa2a91533c0af50ece2fd2c530c";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "727e75d63dceb1a84a7106d802e8eb34a204bc05353567a23ba8b6f54e50d2d8221c87fd8e5238a3374df958b3cf3e3f38c618c1cc8c5b9574b50e405d691218", "72e614a08b7b1abf2ae39d7f7d5d5deb7d0899e8b30e80f17865de23781b5ff57fcbbcd745cc65135c4661b15539b4a1cbd1c610e69d550b39258b49d25eec5c" );
            {
                // y-coordinate of the public key is large on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "27d9c6c4db31aff288fa4e40159d6ee18c98139427484796f1f8745c9827dfc08d393abe144df6b7c12d48971fdd284b81e6e10860359ef71473b9e6bb84cb1e";
                bn_t sig_s = "07a0420c8a9b26911b63626540a85f60aa277afdef9990fc8dc1d3f1f2c5a927e1e4a29d81a701b48b366f000f962614899cbf193826ca8de4a425538de5ac62";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "49542eec3b96c476b59b2b94d5fc7ee08fd2a1b1e732e6609098ab2a7f250452fbc1057a6d3feccbcaeb00468b26222eb48065fcaad7647681823860451e1e91";
                sig_s = "37db336dee1e45d9ace550053511c9c3755657e78eca108d3dfd1e68fe83da626b8dacbb19f0ee232b0f8bfe8ddbe7d5e98b7a2eccd03f375d164ce828631896";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key is large on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "4f90ceb76bc72f0cca10705d3badab6caa6019ef6bfe7de1b75951d517d2b16168515bf305f0006292e4900598256141e45c19077fa447dd5f32daa62c250815";
                sig_s = "6712a784102802821e9708e349d03a88297b374ef81a4edc35016524cd2a22afea7b8b3171de60ac1b3882533650586dcad338ea48231486e10e3120ce3d2a59";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "0518ff14ba05188abed0a8c88db0f097b5660aac57e9a3cdbb9c833e2a7f9f613e49956b53a635952e29818e4a8015cb6a150cede636c2558f2d3602483963b9", "009ed9fe842f3ed418462c63e266944ca2747e15bd8f52844d6a1ce9815210421206805c6ed792356ec57d79fa3e36fff23e2fc6370c67bc51d3f8b555c9048d6d" );
            {
                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "459e3e6e671a6c342d585db689043d32a494ce0039ee71ac67ed6ec0861908ebae6b2d6e4a67caa7a8f0576a49889a4a63d4b0b8aa8845c9cf785b49412a7071";
                bn_t sig_s = "a5edd7abfce9d4413b22289397785b3d84b2c0d3719409255bb7128268e0bcd37d928bea5486bf56ffe259c7ec9f50b878e0155d73e3bde5cffe55e612f8d7b8";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "1b2f7ea40960e37e28b556b7e446c4641e2f3d8a829dcc4a349553e42cf9ce6272dc9cdcda013e3981cb73b10d46321c80501d6a34ad7fd959a0c78f891f33f0";
                sig_s = "7f195b7696edfc7687ff0126eaba13dad1e19563e8d395af32db3d6a7b4e82f28004501d92b7537da397845b7aa398a11051052e52264bd8cbcba9987ec6742b";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // x-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "1b5c1d2b2b06591a1fa516cffa9c8a57cf1fffc22cecb7249281670bc23883a68553e0caf1edd9f1703a25b74e0000a37e32e6cc3576939f458c3dd5c4dbcc9c";
                sig_s = "4b23d7ed7f8a6b7ba7d22aefa8fde030ecb3f2fed4a5f26f12d59a29d63cdd0ec03fae557d141c7b0e8712c306b0eebbd0cab27696012062622bb180043034ba";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "3f89e787b4d5d2599624513530e750ab3c5957dc9aa0e7b08a3e25356818e2037d062f336d4eed417c91bcb11b54b57d54a4f02a72fb74262f742cc6f3404401", "3a448b8e2d0d5a7c5b4f1b9f5b701a9d21ff55e3678ca119b6d7c511ba0aef89f31aeb195db00f248359aee924e7c860b76845f6512a2a4aadc1287a15095220" );
            {
                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "a952847acf213c86e231316d8f9130f7cbdf7f3952307a577076342d13939b4ab5a1313b34abb89204d3fd1f873885fffa683c5a493e5461c7f1400af86ae7fe";
                bn_t sig_s = "9a65a8a4150de593b29642b988b2ec2e23e15e156ecf0af5fde2fbd73208f69f2506d141e0b47c0e1f2fa09ef26b389a6bd2b0230930a16fd119767e382724b5";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "51bfb80aae30262a67bf0771a6b8d195e59aa04e87bd060fe5a9bd56d35385a5fc3da5dfc3ae8c67dbd408184482855e3563dedee72a21b60fafd73819aa837c";
                sig_s = "807f0d69385467ad6cd8a44d482ca3b6e18f7b352ef19a2bc980500b6d59045f0d6f7ab7e414c50d2b68d7f6e6c01d3e8353cdfd475f249b31842fe59955f414";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 0's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "4e8711b00de355f14c8eb91959c13c77f9155754765f10f2aaa8fdad6a14c6a4e62c5ed48a9d8ca403c902db0c2c0735426b33e67828ac32ae19b84e65986819";
                sig_s = "7d104ae5e5d0da26cb427d7951d40df429b4205086e633b800d7d7b8bde48a9bec4e43ddeb4226192b5c9b30ffa3efa7d2385ab28a190c165fb2a2c58572c2a2";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }

            pubkey = curve.make_point( "7860a4743bb48e7793c7f1416fbac6ca0b538210d743f24976af3efda97f28bc95913401ec4ca5e744a23d1a552653ff110ec8421b3de531f3bacda07bfb09d6", "03662f2f2475bbf5e20da48b50169d289c89c54ed0f97bbbc7f38016f1a955cb74c52727ef802055ea090fe1a49be58ddc6083bca3f7c02ff644775cd0027f06" );
            {
                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                auto m = "4d657373616765"_hex;
                bn_t sig_r = "4cd61754211d222371e552578ff705cc819a2f9fb2729f05d848caabf44a31fda1bd038f1b87efd28a8ce53222fdfec18d5929df926df27c2c7e7360bc5c0c70";
                bn_t sig_s = "5ce94c851db1807dc79dcc087c0830d70a0069cf52baffaf347aefa1ddba77f6f770c1483fdde38f5d74bdb32372e12fee843efff0f2dc9344ca1e3b26b9b051";
                auto r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                auto d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "48b4bde7befb1b1cad50cee6233cbf32812860c81d7ad5b0e9d6377202bcd34827c534da0ac9646ae0154689e38c608894bb3126e1025f69c824c69ab821274a";
                sig_s = "8369f5840f776668ebb435b33be05dce4adfabb8860ccc900d07db006a50195fd4de98632192fbe7319cedff26aa8682cf7bf5f1c02e58b9c163236103d9b314";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );

                // y-coordinate of the public key has many trailing 1's on brainpoolP512t1
                m = "4d657373616765"_hex;
                sig_r = "19524b15cf4ecb400b938ef5f752b86ec8f07c5903da5dba9c91ab7965b1223a8e262bef8cca8973ed98797f37a35e1c5999cf203e610ef773c6aa2786bba064";
                sig_s = "98cf7526f5a24a0e2f22f909f8190b13130451b15dd6774bdea9d929342d924bc7eba1df89919c1b9aee8d09203606d10cebff89904cb7e71a82d8972d755306";
                r = true; // result = valid - flags: ['EdgeCasePublicKey', 'GroupIsomorphism']
                d = eosio::sha512( (const char*)m.data(), m.size() );
                test_ecdsa_verification( r, pubkey, d, sig_r, sig_s, curve );
            }
        } // End of Google's Wycheproof tests ecdsa_brainpoolP512r1_sha512_p1363_test
    }
    EOSIO_TEST_END // ecdsa_brainpoolP512r1_test
}
