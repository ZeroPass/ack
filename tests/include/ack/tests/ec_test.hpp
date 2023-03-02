// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/tester.hpp>

#include <ack/ec.hpp>
#include <ack/ec_curve.hpp>
#include <ack/utils.hpp>
#include <ack/tests/utils.hpp>

namespace ack::tests {
    namespace detail {
        using c23_bigint = ec_fixed_bigint<32>;

        struct c23_tag{};
        static constexpr auto c23 = ec_curve_fp<c23_bigint, c23_tag>(
            /*p =*/ 23,
            /*a =*/ 1,
            /*b =*/ 1,
            /*g =*/ { /*x =*/ 13, /*y =*/ 7 },
            /*n =*/ 7,
            /*h =*/ 0
        );

        using c23_point  = typename decltype(c23)::point_type;
    }

    EOSIO_TEST_BEGIN( ec_double_test )
        using namespace detail;
        using namespace ec_curve;
        // Custom curve
        {
            constexpr c23_point p1 = c23.make_point(3,  10);
            constexpr c23_point p2 = c23.make_point(7,  12);
            const auto r = p1.doubled();
            REQUIRE_EQUAL( r, p2 )
            REQUIRE_EQUAL( r.is_identity(), false )
            REQUIRE_EQUAL( r.is_on_curve(), true  )
        }

        // Custom test on secp256k1
        {
            constexpr auto Q = secp256k1.make_point(
                "ea8768570fbb4515f1dccb4b10f6e488b67645f51e90ca332ada1a8064b11346",
                "ce48d7b7f4861f1c62c33e8922d8003e19fbc5f4f2759155a550e38377d97929"
            );

            constexpr auto R = secp256k1.make_point( // Result of Q + Q
                "892765a578fdc85dc700a6f17e880f4ed4bd8dd172b020c766b969c64a960aaf",
                "11b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"
            );

            auto Rc = Q.doubled();
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
        }
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( ec_add_test )
        using namespace detail;
        using namespace ec_curve;

        // Custom curve
        // Test vectors were generated using https://graui.de/code/elliptic2/
        // and https://andrea.corbellini.name/ecc/interactive/modk-add.html
        {
            // {17, 20} = {3, 10} + {9, 7}
            c23_point p1 = c23.make_point( 3, 10 );
            c23_point p2 = c23.make_point( 9,  7  );
            c23_point p3 = c23.make_point( 17, 20 );

            auto r = p1 + p2;
            REQUIRE_EQUAL( r, p3 )
            REQUIRE_EQUAL( r.is_identity(), false )
            REQUIRE_EQUAL( r.is_on_curve(), true  )

            // Adding point to its inverse should result in identity
            r = p1 + p1.invert();
            REQUIRE_EQUAL( r.is_identity(), true )
            REQUIRE_EQUAL( r.is_on_curve(), true )
            REQUIRE_EQUAL( p1 - p1, r )
            REQUIRE_EQUAL( r + -r , r )

            // O = {1, 16} + {1, 7}
            p1 = c23.make_point( 1, 16 );
            p2 = c23.make_point( 1, 7  );
            p3 = c23_point();

           r = p1 + p2;
           REQUIRE_EQUAL( r, p3 )
           REQUIRE_EQUAL( r.is_identity(), true )
           REQUIRE_EQUAL( r.is_on_curve(), true )
        }

        // Custom test cases on secp256k1 curve

        {
            constexpr auto Q = secp256k1.make_point(
                "a7e7f4d5bbfd8f6f8d4518344bf2f01756d59bd5f3779f7240424620e695ad09",
                "2cd0923e06007396d4987ece9079e5064d683c6c1cc242144a3db00879774b48"
            );

            constexpr auto P = secp256k1.make_point(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            );

            constexpr auto R = secp256k1.make_point( // Result of Q + P
                "39b9436a21d1a401e3f8f1819488d9dc2e03a7765b8eaf7119535b7348dae01d",
                "d5f2f36edd13baebdddfa12530f01ac9551bed157e071aaa5921af9628f24b31"
            );

            auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
        }
        {
            constexpr auto  Q = secp256k1.make_point(
                "892765a578fdc85dc700a6f17e880f4ed4bd8dd172b020c766b969c64a960aaf",
                "11b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"
            );

            constexpr auto P = secp256k1.make_point(
                "bf355d2f32a5762db38c7a3a349a78b98202554d3ca34c1f921b3e38805f5b62",
                "21bf42cbb1253d8f7e25c6bfa4104ffbc00732f08a0c6641b7e661391bd401b2"
            );

            constexpr auto R = secp256k1.make_point( // Result of Q + P
                "540534b72d8bf3010a7c838d97104fdf9e5089c567ffd428826b225e7c664bb0",
                "069958958dcf0782facb05dfd6893eadf4329fea8df095393f188b7fe66f76dd"
            );

            auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
        }
        {
            constexpr auto Q = secp256k1.make_point(
                "6c061a03e3be697b1ab29e3def69532e5558524a545112728e090bba8bb82ab5",
                "7cd45e03b81ce24ab0a8b070c5c86e2ed2b352aeb7b9b014484ea7f03c8bc775"
            );

            constexpr auto P = secp256k1.make_point(
                "ea8768570fbb4515f1dccb4b10f6e488b67645f51e90ca332ada1a8064b11346",
                "ce48d7b7f4861f1c62c33e8922d8003e19fbc5f4f2759155a550e38377d97929"
            );

            constexpr auto R = secp256k1.make_point( // Result of Q + P
                "0e55ab80d2db92e889f545d36ca50a3edf713dd6f41591d9d329a37073cc5c53",
                "31e2043a974111a52d86472e17692d4d48ac73ed5b25b3ffa6efa9baeaa0b8dc"
            );

            auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
        }
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( ec_test )
        EOSIO_TEST( ec_double_test )
        EOSIO_TEST( ec_add_test )
    EOSIO_TEST_END
}
