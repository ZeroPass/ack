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
    EOSIO_TEST_BEGIN( ecdsa_misc_test )
        constexpr auto& curve = ack::ec_curve::secp256r1;
        using point_type = std::remove_cvref_t<decltype(curve)>::point_type;
        using int_type = std::remove_cvref_t<decltype(curve)>::int_type;

        // Misc ECDSA key recovery tests
        {
            auto q = curve.make_point(
                "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
                "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"
            );

            auto     h     = from_hex( "d1b8ef21eb4182ee270638061063a3f3c16c114e33937f69fb232cc833965a94" );
            auto    md     = hash256( h );
            int_type r     = "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f";
            int_type s     = "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c";
            size_t recid = 1;

            // Test recovery succeeds
            REQUIRE_EQUAL( ecdsa_recover( curve, h, r, s, recid, /*verify=*/true ), q )

            // Test using invalid recid recovers different point than q
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/0, /*verify=*/true ) != q, true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/0, /*verify=*/true ) != q, true )
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/2, /*verify=*/true ) != q, true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/2, /*verify=*/true ) != q, true )
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/3, /*verify=*/true ) != q, true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/3, /*verify=*/true ) != q, true )

            // Test passing too big recid results in point at infinity
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/0x04, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/0x04, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/0xff, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/0xff, /*verify=*/true ).is_identity(), true )

            // Test passing too small and too big r
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, int_type( 0 ), s, recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, int_type( 0 ), s, recid, /*verify=*/true ).is_identity(), true )

            REQUIRE_EQUAL( ecdsa_recover( curve,  h, curve.n, s, recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, curve.n, s, recid, /*verify=*/true ).is_identity(), true )

            REQUIRE_EQUAL( ecdsa_recover( curve,  h, curve.n + 1, s, recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, curve.n + 1, s, recid, /*verify=*/true ).is_identity(), true )

            // Test passing too small and too big s
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, int_type( 0 ), recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, int_type( 0 ), recid, /*verify=*/true ).is_identity(), true )

            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, curve.n, recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, curve.n, recid, /*verify=*/true ).is_identity(), true )

            REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, curve.n + 1, recid, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, r, curve.n + 1, recid, /*verify=*/true ).is_identity(), true )

            // Test passing too big r when recovering second key
            REQUIRE_EQUAL( ecdsa_recover( curve,  h, curve.p_minus_n, s, 2, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, curve.p_minus_n, s, 2, /*verify=*/true ).is_identity(), true )

            REQUIRE_EQUAL( ecdsa_recover( curve,  h, curve.p_minus_n + 1, s, 2, /*verify=*/true ).is_identity(), true )
            REQUIRE_EQUAL( ecdsa_recover( curve, md, curve.p_minus_n + 1, s, 2, /*verify=*/true ).is_identity(), true )

            // Test recovery fails when signed message changes
            q = curve.make_point(
                "69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214",
                "d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f"
            );
            h  = from_hex( "d80e9933e86769731ec16ff31e6821531bcf07fcbad9e2ac16ec9e6cb343a870" );
            md = hash256( h );
            r  = "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790";
            s  = "247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979";
            for ( std::size_t i = 0; i < 4; i++ ) {
                REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/i, /*verify=*/false ) != q, true )
                REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/i, /*verify=*/false ) != q, true )
                REQUIRE_EQUAL( ecdsa_recover( curve,  h, r, s, /*recid=*/i, /*verify=*/true  ) != q, true )
                REQUIRE_EQUAL( ecdsa_recover( curve, md, r, s, /*recid=*/i, /*verify=*/true  ) != q, true )
            }
        }

        // Misc ECDSA sigver tests
        {
            auto q = curve.make_point(
                "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
                "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"
            );

            auto     h     = from_hex( "d1b8ef21eb4182ee270638061063a3f3c16c114e33937f69fb232cc833965a94" );
            auto    md    = hash256( h );
            int_type r     = "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f";
            int_type s     = "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c";
            size_t   recid = 1;

            // Test verification ECDSA signature succeeds
            REQUIRE_EQUAL( ecdsa_verify( q, h,  r, s ), true )
            REQUIRE_EQUAL( ecdsa_verify( q, md, r, s ), true )
            assert_ecdsa( q, h, r, s,
                "ECDSA signature verification failed"
            );
            assert_ecdsa( q, md, r, s,
                "ECDSA signature verification failed"
            );

            // Test verification fails when passing identity q
            REQUIRE_EQUAL( ecdsa_verify( point_type{}, h,  r, s ), false )
            REQUIRE_EQUAL( ecdsa_verify( point_type{}, md, r, s ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( point_type{}, h, r, s,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( point_type{}, md, r, s,
                    "ECDSA signature verification failed"
                );
            })

            // Test passing too small and too big r
            REQUIRE_EQUAL( ecdsa_verify( q, h,  int_type( 0 ), s ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, int_type( 0 ), s ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, int_type( 0 ), s,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, int_type( 0 ), s,
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_EQUAL( ecdsa_verify( q, h,  curve.n, s ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, curve.n, s ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, curve.n, s,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, curve.n, s,
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_EQUAL( ecdsa_verify( q, h,  curve.n + 1, s ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, curve.n + 1, s ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, curve.n + 1, s,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, curve.n + 1, s,
                    "ECDSA signature verification failed"
                );
            })

            // Test passing too small and too big s
            REQUIRE_EQUAL( ecdsa_verify( q, h,  r, int_type( 0 ) ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, r, int_type( 0 ) ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, r, int_type( 0 ),
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, r, int_type( 0 ),
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_EQUAL( ecdsa_verify( q, h,  r, curve.n ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, r, curve.n ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, r, curve.n,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, r, curve.n,
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_EQUAL( ecdsa_verify( q, h,  r, curve.n + 1 ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, md, r, curve.n + 1 ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, h, r, curve.n + 1,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, md, r, curve.n + 1,
                    "ECDSA signature verification failed"
                );
            })
        }
    EOSIO_TEST_END
}