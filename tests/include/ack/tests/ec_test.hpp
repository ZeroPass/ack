// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/ec_curve.hpp>
#include <ack/utils.hpp>
#include <ack/tests/utils.hpp>

#include <eosio/tester.hpp>
#include <variant>

namespace ack::tests {
    namespace detail {
        using namespace ec_curve;

        using secp256k1_t            = std::remove_cv_t<decltype(secp256k1)>;
        using secp256k1_point        = typename secp256k1_t::point_type;
        using secp256k1_point_proj   = ec_point_fp_proj<secp256k1_t>;
        using secp256k1_point_jacobi = ec_point_fp_jacobi<secp256k1_t>;

        using secp256r1_t            = std::remove_cv_t<decltype(secp256r1)>;
        using secp256r1_point        = typename secp256r1_t::point_type;
        using secp256r1_point_proj   = ec_point_fp_proj<secp256r1_t>;
        using secp256r1_point_jacobi = ec_point_fp_jacobi<secp256r1_t>;

        using c23_bigint = ec_fixed_bigint<32>;
        struct c23_tag{};
        static constexpr auto c23 = ec_curve_fp<c23_bigint, c23_tag>(
            /*p =*/ 23,
            /*a =*/ 1,
            /*b =*/ 1,
            /*g =*/ { /*x =*/ 5, /*y =*/ 4 },
            /*n =*/ 21,
            /*h =*/ 1
        );

        using c23_t            = std::remove_cv_t<decltype(c23)>;
        using c23_point        = typename c23_t::point_type;
        using c23_point_proj   = ec_point_fp_proj<c23_t>;
        using c23_point_jacobi = ec_point_fp_jacobi<c23_t>;

        using curve_ref_t = std::variant<
            const secp256k1_t*,
            const secp256r1_t*,
            const c23_t*
        >;

        constexpr std::array<curve_ref_t, 3> curves = {
            &c23,
            &secp256k1,
            &secp256r1,
        };

        template<typename Lambda>
        void static for_each_curve_do( Lambda&& lambda ) {
            for( const auto& curve : curves ) {
                std::visit( [&]( auto&& c ) {
                    lambda( *c );
                }, curve );
            }
        }
    }

    EOSIO_TEST_BEGIN( ec_general_test )
        using namespace detail;
        using namespace std::string_view_literals;

        // Test GF(p) points and curve over GF(p).
        // Some point were taken from https://graui.de/code/elliptic2/ using c23 params.
        //
        // Note: validity of point addition and multiplication
        //       required for generating point is tested in other test cases
        {
            // Test creating field element from valid value succeeds
                {
                auto f1 = c23.make_field_element( 0 );
                REQUIRE_EQUAL( f1, 0 )

                c23_bigint fev = 0;
                f1 = c23.make_field_element( fev ); // const ref overload
                REQUIRE_EQUAL( f1, fev )

                f1 = c23.make_field_element( 3 );
                REQUIRE_EQUAL( f1, 3 )

                fev = 3;
                f1 = c23.make_field_element( fev ); // const ref overload
                REQUIRE_EQUAL( f1, fev )

                f1 = c23.make_field_element( c23.n );
                REQUIRE_EQUAL( f1, c23.n )

                fev = c23.n;
                f1 = c23.make_field_element( fev ); // const ref overload
                REQUIRE_EQUAL( f1, fev )

                f1 = c23.make_field_element( c23.n + 1 );
                REQUIRE_EQUAL( f1, c23.n + 1 )

                fev = c23.n + 1;
                f1 = c23.make_field_element( fev ); // const ref overload
                REQUIRE_EQUAL( f1, fev )

                f1 = c23.make_field_element( c23.p - 1 );
                REQUIRE_EQUAL( f1, c23.p - 1 )

                fev = c23.p - 1;
                f1 = c23.make_field_element( fev ); // const ref overload
                REQUIRE_EQUAL( f1, fev )
            }

            // Test identity point
            {
                REQUIRE_EQUAL( c23_point().is_identity(), true  )
                REQUIRE_EQUAL( ( c23_point().x == 0 ) && ( c23_point().y == 0 ), true  )
                REQUIRE_EQUAL( c23_point().is_on_curve(), true  )
                REQUIRE_EQUAL( c23_point().is_valid()   , false )

                REQUIRE_EQUAL( c23_point_proj().is_identity(), true  )
                REQUIRE_EQUAL( ( c23_point_proj().x == 0 ) && ( c23_point_proj().y == 1 ) && ( c23_point_proj().z == 0 ), true  )
                REQUIRE_EQUAL( c23_point_proj().is_on_curve(), true  )
                REQUIRE_EQUAL( c23_point_proj().is_valid()   , false )

                REQUIRE_EQUAL( c23_point_jacobi().is_identity(), true  )
                REQUIRE_EQUAL( ( c23_point_jacobi().x == 0 ) && ( c23_point_jacobi().y == 1 ) && ( c23_point_jacobi().z == 0 ), true  )
                REQUIRE_EQUAL( c23_point_jacobi().is_on_curve(), true  )
                REQUIRE_EQUAL( c23_point_jacobi().is_valid()   , false )

                c23_point p1 = c23.make_point( 0, 0 );
                p1 = c23.make_point( 0, 0, /*verify=*/ false );
                REQUIRE_EQUAL( ( p1.x == 0 ) && (p1.y == 0 ), true )
                REQUIRE_EQUAL( p1.is_identity(), true  )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                c23_bigint x = 0, y = 0;
                p1 = c23.make_point( x, y ); // const ref overload
                p1 = c23.make_point( x, y, /*verify=*/ false ); // const ref overload
                REQUIRE_EQUAL( ( p1.x == x ) && (p1.y == y ), true )
                REQUIRE_EQUAL( p1.is_identity(), true  )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                auto p1_proj = ec_point_fp_proj( p1 );
                REQUIRE_EQUAL( ( p1_proj.x == 0 ) && ( p1_proj.y == 1 ) && ( p1_proj.z == 0 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), true  )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false )
                REQUIRE_EQUAL( p1_proj.to_affine()  , p1    )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                REQUIRE_EQUAL( ( p1_jacobi.x == 0 ) && ( p1_jacobi.y == 1 ) && ( p1_jacobi.z == 0 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false )
                REQUIRE_EQUAL( p1_jacobi.to_affine()  , p1    )
            }

            // Test creating point not on curve succeeds
            {
                auto p1 = c23.make_point( 3, 7 );
                p1 = c23.make_point( 3, 7, /*verify=*/ false );
                REQUIRE_EQUAL( ( p1.x == 3 ) && (p1.y == 7 ), true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), false )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                auto x = 3, y = 7;
                p1 = c23.make_point( x, y ); // const ref overload
                p1 = c23.make_point( x, y, /*verify=*/ false ); // const ref overload
                REQUIRE_EQUAL( ( p1.x == x ) && (p1.y == y ), true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 3, 7 ) , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 3, 7 ) , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), false )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                auto p1_proj = ec_point_fp_proj( p1 );
                REQUIRE_EQUAL( ( p1_proj.x == 3 ) && ( p1_proj.y == 7 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), false )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false )
                REQUIRE_EQUAL( p1_proj.to_affine()  , p1    )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                REQUIRE_EQUAL( ( p1_jacobi.x == 3 ) && ( p1_jacobi.y == 7 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), false )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false )
                REQUIRE_EQUAL( p1_jacobi.to_affine()  , p1    )
            }

            // Test creating point on curve succeeds
            {
                auto p1 = c23.make_point( 3, 10 );
                p1 = c23.make_point( 3, 10, /*verify=*/ false );
                REQUIRE_EQUAL( ( p1.x == 3 ) && (p1.y == 10 ), true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , false ) // point not generated by base point

                auto x = 3, y = 10;
                p1 = c23.make_point( x, y ); // const ref overload
                p1 = c23.make_point( x, y, /*verify=*/ false ); // const ref overload
                REQUIRE_EQUAL( ( p1.x == x ) && (p1.y == y ), true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 3, 10 ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 3, 10 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , false ) // point not generated by base point

                auto p1_proj = ec_point_fp_proj( p1 );
                REQUIRE_EQUAL( ( p1_proj.x == 3 ) && ( p1_proj.y == 10 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false ) // point not generated by base point
                REQUIRE_EQUAL( p1_proj.to_affine()  , p1    )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                REQUIRE_EQUAL( ( p1_jacobi.x == 3 ) && ( p1_jacobi.y == 10 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false ) // point not generated by base point
                REQUIRE_EQUAL( p1_jacobi.to_affine()  , p1    )
            }

            // Test creating point with coordinates with p - 1 succeeds
            {
                auto p1 = c23.make_point( c23.p - 1, c23.p - 1 );
                p1 = c23.make_point( c23.p - 1, c23.p - 1, /*verify=*/ false );
                REQUIRE_EQUAL( ( p1.x == 22 ) && (p1.y == 22 ), true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), false )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                auto x = c23.p - 1, y = c23.p - 1;
                p1 = c23.make_point( x, y ); // const ref overload
                p1 = c23.make_point( x, y, /*verify=*/ false ); // const ref overload
                REQUIRE_EQUAL( ( p1.x == x ) && (p1.y == y ), true )
                REQUIRE_EQUAL( p1 == c23.make_point( c23.p - 1, c23.p - 1 ) , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( c23.p - 1, c23.p - 1 ) , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), false )
                REQUIRE_EQUAL( p1.is_valid()   , false )

                auto p1_proj = ec_point_fp_proj( p1 );
                REQUIRE_EQUAL( ( p1_proj.x == 22 ) && ( p1_proj.y == 22 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), false )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false )
                REQUIRE_EQUAL( p1_proj.to_affine()  , p1    )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                REQUIRE_EQUAL( ( p1_jacobi.x == 22 ) && ( p1_jacobi.y == 22 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), false )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false )
                REQUIRE_EQUAL( p1_jacobi.to_affine()  , p1    )
            }

            // Test creating point with coordinates generated from base point succeeds
            {
                auto p1 = c23.make_point( 5, 4 );
                p1 = c23.make_point( 5, 4, /*verify=*/ true );
                REQUIRE_EQUAL( ( p1.x == 5 ) && (p1.y == 4 ), true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                auto x = 5, y = 4;
                p1 = c23.make_point( x, y ); // const ref overload
                p1 = c23.make_point( x, y, /*verify=*/ true ); // const ref overload
                REQUIRE_EQUAL( ( p1.x == x ) && (p1.y == y ), true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 5, 4 ) , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 5, 4 ) , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                auto p1_proj = ec_point_fp_proj( p1 );
                REQUIRE_EQUAL( ( p1_proj.x == 5 ) && ( p1_proj.y == 4 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                REQUIRE_EQUAL( ( p1_jacobi.x == 5 ) && ( p1_jacobi.y == 4 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )
            }

            // Test miscellaneous point functions
            // Note: generate_point does multiplication which is tested in ec_mul_test and ec_double_test
            {
                // Test generating point from base point with scalar 1
                auto p1 = c23.generate_point( 1 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 4 )    , true  )
                REQUIRE_EQUAL( c23.generate_point( "1" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "1"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 5, 4 )      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 5, 4  )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                auto p1_proj = c23.generate_point<c23_point_proj>( 1 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "1" )   == p1_proj , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "1"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj, ec_point_fp_proj( p1 )          ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 5 ) && ( p1_proj.y == 4 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                auto p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                auto p1_jacobi = c23.generate_point<c23_point_jacobi>( 1 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "1" )   == p1_jacobi , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "1"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi, ec_point_fp_jacobi( p1 )               ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()           , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()           , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 5 ) && ( p1_jacobi.y == 4 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                auto p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine()            , p1   )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 2
                p1 = c23.generate_point( 2 );
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 20 )  , true  )
                REQUIRE_EQUAL( c23.generate_point( "2" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "2"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 17, 20 )    , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 17, 20 )    , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 2 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "2" ) == p1_proj   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "2"sv ) == p1_proj , true  )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 10 ) && ( p1_proj.y == 5 ) && ( p1_proj.z == 6 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 2 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "2" ) == p1_jacobi   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "2"sv ) == p1_jacobi , true  )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()           , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()           , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 7 ) && ( p1_jacobi.y == 5 ) && ( p1_jacobi.z == 8 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 3
                p1 = c23.generate_point( 3 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 16 )  , true )
                REQUIRE_EQUAL( c23.generate_point( "3" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "3"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 13, 16 )    , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 13, 16 )    , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23.make_point( 14, 16 )    , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 14, 16 )    , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 3 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "3" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "3"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 10 ) && ( p1_proj.y == 7 ) && ( p1_proj.z == 22 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 3 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "3" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "3"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 13 ) && ( p1_jacobi.y == 16 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 4
                p1 = c23.generate_point( 4 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 7 )   , true  )
                REQUIRE_EQUAL( c23.generate_point( "4" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "4"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 13, 7 )     , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 13, 7 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23.make_point( 13, 8 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 13, 8 )     , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 4 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "4" ) == p1_proj   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "4"sv ) == p1_proj , true  )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 22 ) && ( p1_proj.y == 3 ) && ( p1_proj.z == 7 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 4 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "4" ) == p1_jacobi   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "4"sv ) == p1_jacobi , true  )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 9 ) && ( p1_jacobi.y == 2 ) && ( p1_jacobi.z == 11 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 5
                p1 = c23.generate_point( 5 );
                REQUIRE_EQUAL( c23.generate_point( "5" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "5"sv ) == p1 , true  )
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 3 )   , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 17, 3 )     , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 17, 3 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23.make_point( 18, 4 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 18, 4 )     , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 5 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "5" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "5"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 2 ) && ( p1_proj.y == 22 ) && ( p1_proj.z == 15 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 5 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "5" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "5"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 17 ) && ( p1_jacobi.y == 3 ) && ( p1_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true ) // Equal due to p1_jacobi is already normalized
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 6
                p1 = c23.generate_point( 6 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 19 )   , true  )
                REQUIRE_EQUAL( c23.generate_point( "6" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "6"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 5, 19 )     , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 5, 19 )     , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()                 , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()                 , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 6 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "6" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "6"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 17 ) && ( p1_proj.y == 14 ) && ( p1_proj.z == 8 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 6 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "6" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "6"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 14 ) && ( p1_jacobi.y == 5 ) && ( p1_jacobi.z == 9 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 7 (results in identity)
                p1 = c23.generate_point( 7 );
                REQUIRE_EQUAL( ( p1.x == 0 ) && ( p1.y == 0 )    , true  )
                REQUIRE_EQUAL( c23.generate_point( "7" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "7"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 0, 0 )      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 0, 0 )      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()                 , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()                 , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), true   )
                REQUIRE_EQUAL( p1.is_on_curve(), true   )
                REQUIRE_EQUAL( p1.is_valid()   , false  )

                p1_proj = c23.generate_point<c23_point_proj>( 7 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "7" ) == p1_proj   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "7"sv ) == p1_proj , true  )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 0 ) && ( p1_proj.y == 1 ) && ( p1_proj.z == 0 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), true  )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_zero()   , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1.y     , true ) // y is 1s
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 7 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "7" ) == p1_jacobi   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "7"sv ) == p1_jacobi , true  )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 0 ) && ( p1_jacobi.y == 1 ) && ( p1_jacobi.z == 0 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_zero()     , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1.y       , true ) // y is 1s
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 8
                p1 = c23.generate_point( 8 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 4 )    , true  )
                REQUIRE_EQUAL( c23.generate_point( "8" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "8"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 5, 4 )  , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 5, 4 )  , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()             , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()             , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 8 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "8" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "8"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 2 ) && ( p1_proj.y == 20 ) && ( p1_proj.z == 5 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 8 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "8" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "8"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 20 ) && ( p1_jacobi.y == 14 ) && ( p1_jacobi.z == 21 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 9
                p1 = c23.generate_point( 9 );
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 20 )  , true  )
                REQUIRE_EQUAL( c23.generate_point( "9" ) == p1   , true  )
                REQUIRE_EQUAL( c23.generate_point( "9"sv ) == p1 , true  )
                REQUIRE_EQUAL( p1 == c23.make_point( 17, 20 )  , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 17, 20 )  , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()               , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()               , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 9 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "9" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "9"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()           , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()           , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 10 ) && ( p1_proj.y == 5 ) && ( p1_proj.z == 6 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 19 );
                auto p1_inv_jacobi = p1_jacobi.inverted();

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 9 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 10 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 11 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 12 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 13 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 14 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 15 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 16 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 17 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 18 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 19 );
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 20 );

                p1_jacobi = ec_point_fp_jacobi( c23.make_point( 5, 4 ) ).inverted();
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 19 ).inverted();
                p1_jacobi = c23.generate_point<c23_point_jacobi>( 20 ).inverted();


                p1_jacobi = c23.generate_point<c23_point_jacobi>( 9 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "9" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "9"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 21 ) && ( p1_jacobi.y == 10 ) && ( p1_jacobi.z == 13 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 10
                p1 = c23.generate_point( 10 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 16 )   , true )
                REQUIRE_EQUAL( c23.generate_point( "0a" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0a"sv ) == p1 , true )
                REQUIRE_EQUAL( p1 == c23.make_point( 13, 16 )  , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 13, 16 )  , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()               , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()               , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 10 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0a" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0a"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()           , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()           , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 6 ) && ( p1_proj.y == 18 ) && ( p1_proj.z == 4 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 10 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0a" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0a"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 8 ) && ( p1_jacobi.y == 6 ) && ( p1_jacobi.z == 6 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 11
                p1 = c23.generate_point( 11 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 7 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "0b" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0b"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 11 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0b" ) == p1_proj   , true  )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0b"sv ) == p1_proj , true  )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()           , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()           , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 13 ) && ( p1_proj.y == 7 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 11 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0b" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0b"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 1 ) && ( p1_jacobi.y == 11 ) && ( p1_jacobi.z == 4 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 12
                p1 = c23.generate_point( 12 );
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 3 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "0c" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0c"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 12 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0c" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0c"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 15 ) && ( p1_proj.y == 4 ) && ( p1_proj.z == 9 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 12 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0c" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0c"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 22 ) && ( p1_jacobi.y == 22 ) && ( p1_jacobi.z == 21 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 13
                p1 = c23.generate_point( 13 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 19 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "0d" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0d"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 13 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0d" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0d"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 5 ) && ( p1_proj.y == 19 ) && ( p1_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 13 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0d" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0d"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 11 ) && ( p1_jacobi.y == 20 ) && ( p1_jacobi.z == 4 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 14
                p1 = c23.generate_point( 14 );
                REQUIRE_EQUAL( ( p1.x == 0 ) && ( p1.y == 0 )     , true )
                REQUIRE_EQUAL( c23.generate_point( "0e" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0e"sv ) == p1 , true )
                REQUIRE_EQUAL( p1 == c23.make_point( 0, 0 )  , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23.make_point( 0, 0 )  , false ) // Test comparison operator
                REQUIRE_EQUAL( p1 == c23_point()             , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1 != c23_point()             , false ) // Test comparison operator
                REQUIRE_EQUAL( p1.is_identity(), true   )
                REQUIRE_EQUAL( p1.is_on_curve(), true   )
                REQUIRE_EQUAL( p1.is_valid()   , false  )

                p1_proj = c23.generate_point<c23_point_proj>( 14 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0e" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0e"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 0 ) && ( p1_proj.y == 1 ) && ( p1_proj.z == 0 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), true  )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , false )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_zero()   , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1.y     , true ) // y is 1
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 14 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0e" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0e"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 0 ) && ( p1_jacobi.y == 1 ) && ( p1_jacobi.z == 0 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , false )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_zero()     , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1.y       , true ) // y is 1
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 15
                p1 = c23.generate_point( 15 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 4 )     , true )
                REQUIRE_EQUAL( c23.generate_point( "0f" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "0f"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 15 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0f" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "0f"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 2 ) && ( p1_proj.y == 20 ) && ( p1_proj.z == 5 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 15 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0f" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "0f"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 19 ) && ( p1_jacobi.y == 10 ) && ( p1_jacobi.z == 17 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 16
                p1 = c23.generate_point( 16 );
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 20 )   , true )
                REQUIRE_EQUAL( c23.generate_point( "10" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "10"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 16 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "10" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "10"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 11 ) && ( p1_proj.y == 17 ) && ( p1_proj.z == 2 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 16 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "10" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "10"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 21 ) && ( p1_jacobi.y == 10 ) && ( p1_jacobi.z == 13 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 17
                p1 = c23.generate_point( 17 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 16 )   , true )
                REQUIRE_EQUAL( c23.generate_point( "11" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "11"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 17 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "11" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "11"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 20 ) && ( p1_proj.y == 14 ) && ( p1_proj.z == 21 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 17 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "11" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "11"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 8 ) && ( p1_jacobi.y == 17 ) && ( p1_jacobi.z == 17 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 18
                p1 = c23.generate_point( 18 );
                REQUIRE_EQUAL( ( p1.x == 13 ) && ( p1.y == 7 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "12" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "12"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 18 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "12" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "12"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 22 ) && ( p1_proj.y == 3 ) && ( p1_proj.z == 7 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 18 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "12" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "12"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 16 ) && ( p1_jacobi.y == 9 ) && ( p1_jacobi.z == 7 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 19
                p1 = c23.generate_point( 19 );
                REQUIRE_EQUAL( ( p1.x == 17 ) && ( p1.y == 3 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "13" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "13"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 19 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "13" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "13"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 3 ) && ( p1_proj.y == 10 ) && ( p1_proj.z == 11 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 19 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "13" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "13"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 19 ) && ( p1_jacobi.y == 15 ) && ( p1_jacobi.z == 19 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )

                // Test generating point from base point with scalar 20
                p1 = c23.generate_point( 20 );
                REQUIRE_EQUAL( ( p1.x == 5 ) && ( p1.y == 19 )    , true )
                REQUIRE_EQUAL( c23.generate_point( "14" ) == p1   , true )
                REQUIRE_EQUAL( c23.generate_point( "14"sv ) == p1 , true )
                REQUIRE_EQUAL( p1.is_identity(), false )
                REQUIRE_EQUAL( p1.is_on_curve(), true  )
                REQUIRE_EQUAL( p1.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 20 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "14" ) == p1_proj   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_proj>( "14"sv ) == p1_proj , true )
                REQUIRE_EQUAL( p1_proj == ec_point_fp_proj( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_proj != ec_point_fp_proj( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj == c23_point_proj()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_proj != c23_point_proj()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_proj.x == 12 ) && ( p1_proj.y == 18 ) && ( p1_proj.z == 7 ), true )
                REQUIRE_EQUAL( p1_proj.is_identity(), false )
                REQUIRE_EQUAL( p1_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_proj.is_valid()   , true  )

                p1_proj_normal = p1_proj.normalized();
                REQUIRE_EQUAL( p1_proj_normal.z.is_one()    , true )
                REQUIRE_EQUAL( p1_proj_normal == p1_proj    , true )
                REQUIRE_EQUAL( p1_proj_normal.x != p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y != p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z != p1_proj.z, true )
                REQUIRE_EQUAL( p1_proj_normal.x == p1.x     , true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1.y     , true )
                REQUIRE_EQUAL( p1_proj.to_affine(), p1             )

                p1_proj.normalize();
                REQUIRE_EQUAL( p1_proj_normal, p1_proj             )
                REQUIRE_EQUAL( p1_proj_normal.x == p1_proj.x, true )
                REQUIRE_EQUAL( p1_proj_normal.y == p1_proj.y, true )
                REQUIRE_EQUAL( p1_proj_normal.z == p1_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 20 );
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "14" ) == p1_jacobi   , true )
                REQUIRE_EQUAL( c23.generate_point<c23_point_jacobi>( "14"sv ) == p1_jacobi , true )
                REQUIRE_EQUAL( p1_jacobi == ec_point_fp_jacobi( p1 ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_jacobi != ec_point_fp_jacobi( p1 ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi == c23_point_jacobi()      , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_jacobi != c23_point_jacobi()      , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_jacobi.x == 22 ) && ( p1_jacobi.y == 7 ) && ( p1_jacobi.z == 3 ), true )
                REQUIRE_EQUAL( p1_jacobi.is_identity(), false )
                REQUIRE_EQUAL( p1_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_jacobi.is_valid()   , true  )

                p1_jacobi_normal = p1_jacobi.normalized();
                REQUIRE_EQUAL( p1_jacobi_normal.z.is_one()      , true )
                REQUIRE_EQUAL( p1_jacobi_normal == p1_jacobi    , true )
                REQUIRE_EQUAL( p1_jacobi_normal.x != p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y != p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z != p1_jacobi.z, true )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1.x       , true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1.y       , true )
                REQUIRE_EQUAL( p1_jacobi.to_affine(), p1               )

                p1_jacobi.normalize();
                REQUIRE_EQUAL( p1_jacobi_normal, p1_jacobi             )
                REQUIRE_EQUAL( p1_jacobi_normal.x == p1_jacobi.x, true )
                REQUIRE_EQUAL( p1_jacobi_normal.y == p1_jacobi.y, true )
                REQUIRE_EQUAL( p1_jacobi_normal.z == p1_jacobi.z, true )
            }

            // Test point inversion from pre-calculated point
            {
                auto p1 = c23.make_point( 5, 4 );
                auto p1_inv = p1.inverted();
                REQUIRE_EQUAL( -p1, p1_inv ) // Test '-' operator
                REQUIRE_EQUAL( ( p1_inv.x == 5 ) && ( p1_inv.y == 19 ), true )
                REQUIRE_EQUAL( p1_inv.is_identity(), false )
                REQUIRE_EQUAL( p1_inv.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_inv.is_valid()   , true  )

                auto p1_proj = ec_point_fp_proj( p1 );
                auto p1_inv_proj = p1_proj.inverted();
                REQUIRE_EQUAL( -p1_proj, p1_inv_proj ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_proj == ec_point_fp_proj( p1_inv ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj != ec_point_fp_proj( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj == c23_point_proj()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj != c23_point_proj()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_proj.x == 5 ) && ( p1_inv_proj.y == 19 ) && ( p1_inv_proj.z == 1 ), true )
                REQUIRE_EQUAL( p1_inv_proj.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_proj.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_proj.is_valid()   , true   )

                auto p1_inv_proj_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_proj_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z == p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_proj.to_affine(), p1_inv             )

                p1_inv_proj.normalize();
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z == p1_inv_proj.z, true )

                auto p1_jacobi = ec_point_fp_jacobi( p1 );
                auto p1_inv_jacobi = p1_jacobi.inverted();
                REQUIRE_EQUAL( -p1_jacobi, p1_inv_jacobi ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_jacobi == ec_point_fp_jacobi( p1_inv ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != ec_point_fp_jacobi( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi == c23_point_jacobi()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != c23_point_jacobi()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_jacobi.x == 5 ) && ( p1_inv_jacobi.y == 19 ) && ( p1_inv_jacobi.z == 1 ), true )
                REQUIRE_EQUAL( p1_inv_jacobi.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_jacobi.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_jacobi.is_valid()   , true   )

                auto p1_inv_jacobi_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.to_affine(), p1_inv      )

                p1_inv_jacobi.normalize();
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )

                // Test point inversion from generated point with scalar 20
                p1 = c23.generate_point( 20 );
                p1_inv = p1.inverted();
                REQUIRE_EQUAL( -p1, p1_inv ) // Test '-' operator
                REQUIRE_EQUAL( ( p1_inv.x == 5 ) && ( p1_inv.y == 4 ), true )
                REQUIRE_EQUAL( p1_inv.is_identity(), false )
                REQUIRE_EQUAL( p1_inv.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_inv.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 20 );
                p1_inv_proj = p1_proj.inverted();
                REQUIRE_EQUAL( -p1_proj, p1_inv_proj ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_proj == ec_point_fp_proj( p1_inv ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_inv_proj != ec_point_fp_proj( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj == c23_point_proj()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj != c23_point_proj()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_proj.x == 12 ) && ( p1_inv_proj.y == 5 ) && ( p1_inv_proj.z == 7 ), true )
                REQUIRE_EQUAL( p1_inv_proj.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_proj.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_proj.is_valid()   , true   )

                p1_inv_proj_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_proj_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x != p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y != p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z != p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_proj.to_affine(), p1_inv             )

                p1_inv_proj.normalize();
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z == p1_inv_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 20 );
                p1_inv_jacobi = p1_jacobi.inverted();
                REQUIRE_EQUAL( -p1_jacobi, p1_inv_jacobi ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_jacobi == ec_point_fp_jacobi( p1_inv ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != ec_point_fp_jacobi( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi == c23_point_jacobi()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != c23_point_jacobi()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_jacobi.x == 22 ) && ( p1_inv_jacobi.y == 16 ) && ( p1_inv_jacobi.z == 3 ), true )
                REQUIRE_EQUAL( p1_inv_jacobi.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_jacobi.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_jacobi.is_valid()   , true   )

                p1_inv_jacobi_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.to_affine(), p1_inv      )

                p1_inv_jacobi.normalize();
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )

                // Test point inversion from generated point with scalar 19
                p1 = c23.generate_point( 19 );
                p1_inv = p1.inverted();
                REQUIRE_EQUAL( -p1, p1_inv ) // Test '-' operator
                REQUIRE_EQUAL( ( p1_inv.x == 17 ) && ( p1_inv.y == 20 ), true )
                REQUIRE_EQUAL( p1_inv.is_identity(), false )
                REQUIRE_EQUAL( p1_inv.is_on_curve(), true  )
                REQUIRE_EQUAL( p1_inv.is_valid()   , true  )

                p1_proj = c23.generate_point<c23_point_proj>( 19 );
                p1_inv_proj = p1_proj.inverted();
                REQUIRE_EQUAL( -p1_proj, p1_inv_proj ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_proj == ec_point_fp_proj( p1_inv ), true  ) // Different z coordinate
                REQUIRE_EQUAL( p1_inv_proj != ec_point_fp_proj( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj == c23_point_proj()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_proj != c23_point_proj()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_proj.x == 3 ) && ( p1_inv_proj.y == 13 ) && ( p1_inv_proj.z == 11 ), true )
                REQUIRE_EQUAL( p1_inv_proj.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_proj.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_proj.is_valid()   , true   )

                p1_inv_proj_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_proj_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x != p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y != p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z != p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_proj.to_affine(), p1_inv             )

                p1_inv_proj.normalize();
                REQUIRE_EQUAL( p1_inv_proj_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_proj_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_proj_normal.z == p1_inv_proj.z, true )

                p1_jacobi = c23.generate_point<c23_point_jacobi>( 19 );
                p1_inv_jacobi = p1_jacobi.inverted();
                REQUIRE_EQUAL( -p1_jacobi, p1_inv_jacobi ) // Test '-' operator
                REQUIRE_EQUAL( p1_inv_jacobi == ec_point_fp_jacobi( p1_inv ), true  ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != ec_point_fp_jacobi( p1_inv ), false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi == c23_point_jacobi()          , false ) // Test comparison operator
                REQUIRE_EQUAL( p1_inv_jacobi != c23_point_jacobi()          , true  ) // Test comparison operator
                REQUIRE_EQUAL( ( p1_inv_jacobi.x == 19 ) && ( p1_inv_jacobi.y == 8 ) && ( p1_inv_jacobi.z == 19 ), true )
                REQUIRE_EQUAL( p1_inv_jacobi.is_identity(), false  )
                REQUIRE_EQUAL( p1_inv_jacobi.is_on_curve(), true   )
                REQUIRE_EQUAL( p1_inv_jacobi.is_valid()   , true   )

                p1_inv_jacobi_normal = p1_inv_proj.normalized();
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z.is_one()        , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv.x     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv.y     , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.to_affine(), p1_inv      )

                p1_inv_jacobi.normalize();
                REQUIRE_EQUAL( p1_inv_jacobi_normal == p1_inv_proj    , true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.x == p1_inv_proj.x, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.y == p1_inv_proj.y, true )
                REQUIRE_EQUAL( p1_inv_jacobi_normal.z == p1_inv_proj.z, true )
            }

            // Test retrieving curve reference from point at infinity fails
            REQUIRE_ASSERT( "curve is null", [&]() {
                auto& cr = c23_point().curve();
            })

            REQUIRE_ASSERT( "curve is null", [&]() {
                auto& cr = c23_point_proj().curve();
            })

            // Test creating field element with value not in range fails
            REQUIRE_ASSERT( "Invalid field element value", [&]() {
                auto aa = c23.make_field_element( -3 );
            })

            REQUIRE_ASSERT( "Invalid field element value", [&]() { // test const ref overload
                auto x = -3;
                auto aa = c23.make_field_element( x );
            })

            REQUIRE_ASSERT( "Invalid field element value", [&]() {
                auto aa = c23.make_field_element( c23.p ); // const ref overload
            })

            REQUIRE_ASSERT( "Invalid field element value", [&]() {
                auto aa = c23.make_field_element( c23.p + 1 );
            })

            REQUIRE_ASSERT( "Invalid field element value", [&]() { // test const ref overload
                auto x = c23.p + 1;
                auto aa = c23.make_field_element( x );
            })

            // Test creating point with coordinates not in range fails
            REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                auto aa = c23.make_point( -3, 10 );
            })

            REQUIRE_ASSERT( "Invalid point x coordinate", [&]() { // test const ref overload
                auto x = -3;
                auto aa = c23.make_point( x, 10 );
            })

            REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                auto aa = c23.make_point( c23.p, 10 ); //  const ref overload
            })

            REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                auto aa = c23.make_point( c23.p + 1, 10 );
            })

           REQUIRE_ASSERT( "Invalid point x coordinate", [&]() { // test const ref overload
                auto x = c23.p + 1;
                auto aa = c23.make_point( x, 10 );
            })

            REQUIRE_ASSERT( "Invalid point y coordinate", [&]() {
                auto aa = c23.make_point( 3, -10 );
            })

            REQUIRE_ASSERT( "Invalid point y coordinate", [&]() { // test const ref overload
                auto y = -10;
                auto aa = c23.make_point( 3, y );
            })

            REQUIRE_ASSERT( "Invalid point y coordinate", [&]() {
                auto aa = c23.make_point( 3, c23.p ); // const ref overload
            })

            REQUIRE_ASSERT( "Invalid point y coordinate", [&]() {
                auto aa = c23.make_point( 3, c23.p + 1 );
            })

            REQUIRE_ASSERT( "Invalid point y coordinate", [&]() { // test const ref overload
                auto y = c23.p + 1;
                auto aa = c23.make_point( 3, y );
            })

            // Test that verifying point not on curve fails
            REQUIRE_ASSERT( "Invalid point", [&]() {
                auto aa = c23.make_point( 3, 7, /*verify=*/ true );
            })

            REQUIRE_ASSERT( "Invalid point", [&]() { // test const ref overload
                auto x = 3, y = 7;
                auto aa = c23.make_point( x, y, /*verify=*/ true );
            })

            // Test that verifying point on curve but not generated with base point fails
            REQUIRE_ASSERT( "Invalid point", [&]() {
                auto aa = c23.make_point( 3, 10, /*verify=*/ true );
            })

            REQUIRE_ASSERT( "Invalid point", [&]() { // test const ref overload
                auto x = 3, y = 10;
                auto aa = c23.make_point( x, y, /*verify=*/ true );
            })

            // Test generating point from invalid scalar fails
            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point( -1 );
            })

             REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point<c23_point_proj>( -1 );
            })

            // Test generating point from invalid scalar fails
            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point( 0 );
            })

            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point<c23_point_proj>( 0 );
            })

            // Test generating point from invalid scalar fails
            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point( c23.n );
            })

            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point<c23_point_proj>( c23.n );
            })

            // Test generating point from invalid scalar fails
            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point( c23.n + 1 );
            })

            REQUIRE_ASSERT( "x must be in range [1, n-1]", [&]() {
                auto aa = c23.generate_point<c23_point_proj>( c23.n + 1 );
            })
        }
    EOSIO_TEST_END // ec_test

    EOSIO_TEST_BEGIN(ec_pkv_secp256r1_test)
        {
            // Generated from: 'PKV.rsp'
            // CAVS 11.0
            // "PKV" information
            // Curves selected: P-192 P-224 P-256 P-384 P-521 K-163 K-233 K-283 K-409 K-571 B-163 B-233 B-283 B-409 B-571
            // Generated on Wed Mar 16 16:16:42 2011
            //
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip

            using bn_t = ec_fixed_bigint<256>;
            const auto& curve = ec_curve::secp256r1;
            // [P-256]
            {
                // Result = P (0 )
                auto q = curve.make_point( "e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7", "86d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0", /*verify=*/ true );
                REQUIRE_EQUAL( q.is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), true )

                // Result = F (1 - Q_x or Q_y out of range)
                REQUIRE_ASSERT( "Invalid point y coordinate", [&]() {
                    auto  qi = curve.make_point( "d17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9", "01eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d0701066231c", /*verify=*/ false );
                })

                REQUIRE_ASSERT( "Invalid point y coordinate", [&]() {
                    auto  qi = curve.make_point( "d17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9", "01eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d0701066231c", /*verify=*/ true );
                })

                // Result = F (1 - Q_x or Q_y out of range)
                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "017875397ae87369365656d490e8ce956911bd97607f2aff41b56f6f3a61989826", "980a3c4f61b9692633fbba5ef04c9cb546dd05cdec9fa8428b8849670e2fba92", /*verify=*/ false );
                })

                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "017875397ae87369365656d490e8ce956911bd97607f2aff41b56f6f3a61989826", "980a3c4f61b9692633fbba5ef04c9cb546dd05cdec9fa8428b8849670e2fba92", /*verify=*/ true );
                })

                // Result = F (2 - Point not on curve)
                REQUIRE_ASSERT( "Invalid point", [&]() {
                    auto  qi = curve.make_point( "f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273", "32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd", /*verify=*/ true );
                })

                q = curve.make_point( "f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273", "32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd", /*verify=*/ false );
                REQUIRE_EQUAL( q.is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), false )

                // Result = F (1 - Q_x or Q_y out of range)
                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "010b0ca230fff7c04768f4b3d5c75fa9f6c539bea644dffbec5dc796a213061b58", "f5edf37c11052b75f771b7f9fa050e353e464221fec916684ed45b6fead38205", /*verify=*/ false );
                })

                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "010b0ca230fff7c04768f4b3d5c75fa9f6c539bea644dffbec5dc796a213061b58", "f5edf37c11052b75f771b7f9fa050e353e464221fec916684ed45b6fead38205", /*verify=*/ true );
                })

                // Result = P (0 )
                q = curve.make_point( "2c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525da", "ced9783713a8a2a09eff366987639c625753295d9a85d0f5325e32dedbcada0b", /*verify=*/ true );
                REQUIRE_EQUAL( q.is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), true )

                // Result = F (2 - Point not on curve)
                REQUIRE_ASSERT( "Invalid point", [&]() {
                    auto  qi = curve.make_point( "a40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f", "503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3", /*verify=*/ true );
                })

                q = curve.make_point( "a40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f", "503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3", /*verify=*/ false );
                REQUIRE_EQUAL( q.is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), false )

                // Result = P (0 )
                q = curve.make_point( "2633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0a", "d6b2f738e3873cc8364a2d364038ce7d0798bb092e3dd77cbdae7c263ba618d2", /*verify=*/ true );
                REQUIRE_EQUAL( q.is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), true )

                // Result = F (1 - Q_x or Q_y out of range)
                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "014bf57f76c260b51ec6bbc72dbd49f02a56eaed070b774dc4bad75a54653c3d56", "7a231a23bf8b3aa31d9600d888a0678677a30e573decd3dc56b33f365cc11236", /*verify=*/ false );
                })

                REQUIRE_ASSERT( "Invalid point x coordinate", [&]() {
                    auto  qi = curve.make_point( "014bf57f76c260b51ec6bbc72dbd49f02a56eaed070b774dc4bad75a54653c3d56", "7a231a23bf8b3aa31d9600d888a0678677a30e573decd3dc56b33f365cc11236", /*verify=*/ true );
                })

                // Result = P (0 )
                q = curve.make_point( "2fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f1", "5b994346137988c58c14ae2152ac2f6ad96d97decb33099bd8a0210114cd1141", /*verify=*/ true );
                REQUIRE_EQUAL( q.is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), true )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), true )

                // Result = F (2 - Point not on curve)
                REQUIRE_ASSERT( "Invalid point", [&]() {
                    auto  qi = curve.make_point( "f8c6dd3181a76aa0e36c2790bba47041acbe7b1e473ff71eee39a824dc595ff0", "9c965f227f281b3072b95b8daf29e88b35284f3574462e268e529bbdc50e9e52", /*verify=*/ true );
                })

                q = curve.make_point( "f8c6dd3181a76aa0e36c2790bba47041acbe7b1e473ff71eee39a824dc595ff0", "9c965f227f281b3072b95b8daf29e88b35284f3574462e268e529bbdc50e9e52", /*verify=*/ false );
                REQUIRE_EQUAL( q.is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), false )

                // Result = F (2 - Point not on curve)
                REQUIRE_ASSERT( "Invalid point", [&]() {
                    auto  qi = curve.make_point( "7a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be38", "08862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb", /*verify=*/ true );
                })

                q = curve.make_point( "7a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be38", "08862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb", /*verify=*/ false );
                REQUIRE_EQUAL( q.is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_proj( q ).is_valid(), false )
                REQUIRE_EQUAL( ec_point_fp_jacobi( q ).is_valid(), false )
            }
        }
    EOSIO_TEST_END // ec_pkv_secp256r1_test

    EOSIO_TEST_BEGIN( ec_double_test )
        using namespace detail;

        // General test
        for_each_curve_do( []<typename CurveT>(const CurveT& c) {
            using point_type        = typename CurveT::point_type;
            using point_proj_type   = ec_point_fp_proj<CurveT>;
            using point_jacobi_type = ec_point_fp_jacobi<CurveT>;

            // Test doubling identity results in identity
            point_type p = point_type().doubled();
            REQUIRE_EQUAL( p, point_type()        )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            point_proj_type p_proj = point_proj_type().doubled();
            REQUIRE_EQUAL( p_proj, point_proj_type()   )
            REQUIRE_EQUAL( p_proj.is_identity(), true  )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , false )
            REQUIRE_EQUAL( p_proj.to_affine()  , p     )

            point_jacobi_type p_jacobi = point_jacobi_type().doubled();
            REQUIRE_EQUAL( p_jacobi, point_jacobi_type() )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true  )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p     )

            // Test doubling point with y = 0 results in identity
            p = c.make_point( 4, 0 ).doubled();
            REQUIRE_EQUAL( p, point_type()        )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            p_proj = point_proj_type( c.make_point( 4, 0 ) ).doubled();
            REQUIRE_EQUAL( p_proj, point_proj_type()   )
            REQUIRE_EQUAL( p_proj.is_identity(), true  )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , false )
            REQUIRE_EQUAL( p_proj.to_affine()  , p     )

            p_jacobi = point_jacobi_type( c.make_point( 4, 0 ) ).doubled();
            REQUIRE_EQUAL( p_jacobi, point_jacobi_type() )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true  )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p     )
        });

        // Custom curve tests
        {
            constexpr c23_point p1 = c23.make_point( 3, 10 );
            constexpr c23_point p2 = c23.make_point( 7, 12 );
            const auto r = p1.doubled();
            REQUIRE_EQUAL( r, p2                  )
            REQUIRE_EQUAL( r.is_identity(), false )
            REQUIRE_EQUAL( r.is_on_curve(), true  )
            REQUIRE_EQUAL( r.is_valid()   , false ) // not generated with generator point

            const auto p1_proj = ec_point_fp_proj( p1 );
            const auto r_proj  = ec_point_fp_proj( p2 );
            REQUIRE_EQUAL( r_proj.is_identity(), false )
            REQUIRE_EQUAL( r_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( r_proj.is_valid()   , false ) // not generated with generator point
            REQUIRE_EQUAL( r_proj.to_affine()  , p2    )
            REQUIRE_EQUAL( p1_proj.doubled().to_affine() , p2 )

            const auto p1_jacobi = ec_point_fp_jacobi( p1 );
            const auto r_jacobi  = ec_point_fp_jacobi( p2 );
            REQUIRE_EQUAL( r_jacobi.is_identity(), false )
            REQUIRE_EQUAL( r_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( r_jacobi.is_valid()   , false ) // not generated with generator point
            REQUIRE_EQUAL( r_jacobi.to_affine()  , p2    )
            REQUIRE_EQUAL( p1_jacobi.doubled().to_affine() , p2 )
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

            const auto Rc = Q.doubled();
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )

            const auto Rc_proj = ec_point_fp_proj( Q ).doubled();
            REQUIRE_EQUAL( Rc_proj.is_identity(), false )
            REQUIRE_EQUAL( Rc_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_proj.to_affine()  , R     )

            const auto Rc_jacobi = ec_point_fp_jacobi( Q ).doubled();
            REQUIRE_EQUAL( Rc_jacobi.is_identity(), false )
            REQUIRE_EQUAL( Rc_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_jacobi.to_affine()  , R     )
        }
    EOSIO_TEST_END // ec_double_test

    EOSIO_TEST_BEGIN( ec_add_test )
        using namespace detail;

        // General test
        for_each_curve_do( []<typename CurveT>(const CurveT& c) {
            using point_type        = typename CurveT::point_type;
            using point_proj_type   = ec_point_fp_proj<CurveT>;
            using point_jacobi_type = ec_point_fp_jacobi<CurveT>;

            // Test summing identity point results in identity
            point_type p = point_type() + point_type();
            REQUIRE_EQUAL( p, point_type()        )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            point_proj_type p_proj = point_proj_type() + point_proj_type();
            REQUIRE_EQUAL( p_proj, point_proj_type()   )
            REQUIRE_EQUAL( p_proj.is_identity(), true  )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , false )
            REQUIRE_EQUAL( p_proj.to_affine()  , p     )

            point_jacobi_type p_jacobi = point_jacobi_type() + point_jacobi_type();
            REQUIRE_EQUAL( p_jacobi, point_jacobi_type() )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true  )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p     )

            // Test adding identity to point results in point
            p = c.g + point_type();
            REQUIRE_EQUAL( c.g.add( point_type() ), p )
            REQUIRE_EQUAL( p, c.g                     )
            REQUIRE_EQUAL( p.is_identity(), false     )
            REQUIRE_EQUAL( p.is_on_curve(), true      )
            REQUIRE_EQUAL( p.is_valid()   , true      )

            const auto g_proj = ec_point_fp_proj( c.g );
            p_proj = g_proj + point_proj_type();
            REQUIRE_EQUAL( g_proj.add( point_proj_type()),  p_proj )
            REQUIRE_EQUAL( p_proj, g_proj              )
            REQUIRE_EQUAL( p_proj.is_identity(), false )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , true  )
            REQUIRE_EQUAL( p_proj.to_affine()  , c.g   )

            const auto g_jacobi = ec_point_fp_jacobi( c.g );
            p_jacobi = g_jacobi + point_jacobi_type();
            REQUIRE_EQUAL( g_jacobi.add( point_jacobi_type()),  p_jacobi )
            REQUIRE_EQUAL( p_jacobi, g_jacobi            )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , c.g   )

            // Test adding point to identity results in point
            p = point_type() + c.g;
            REQUIRE_EQUAL( point_type().add( c.g ), p )
            REQUIRE_EQUAL( p, c.g                     )
            REQUIRE_EQUAL( p.is_identity(), false     )
            REQUIRE_EQUAL( p.is_on_curve(), true      )
            REQUIRE_EQUAL( p.is_valid()   , true      )

            p_proj = point_proj_type() + g_proj;
            REQUIRE_EQUAL( point_proj_type().add( g_proj ),  p_proj )
            REQUIRE_EQUAL( p_proj, g_proj              )
            REQUIRE_EQUAL( p_proj.is_identity(), false )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , true  )
            REQUIRE_EQUAL( p_proj.to_affine()  , c.g   )

            p_jacobi = point_jacobi_type() + g_jacobi;
            REQUIRE_EQUAL( point_jacobi_type().add( g_jacobi ),  p_jacobi )
            REQUIRE_EQUAL( p_jacobi, g_jacobi              )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , c.g   )

            // Test adding point to itself results in point doubled
            p = c.g + c.g;
            REQUIRE_EQUAL( c.g.add( c.g ), p      )
            REQUIRE_EQUAL( p, c.g.doubled()       )
            REQUIRE_EQUAL( p.is_identity(), false )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , true  )

            p_proj = g_proj + g_proj;
            REQUIRE_EQUAL( g_proj.add( g_proj  ),  p_proj )
            REQUIRE_EQUAL( p_proj, g_proj.doubled()       )
            REQUIRE_EQUAL( p_proj.is_identity(), false    )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true     )
            REQUIRE_EQUAL( p_proj.is_valid()   , true     )
            REQUIRE_EQUAL( p_proj.to_affine()  , p        )

            p_jacobi = g_jacobi + g_jacobi;
            REQUIRE_EQUAL( g_jacobi.add( g_jacobi  ),  p_jacobi )
            REQUIRE_EQUAL( p_jacobi, g_jacobi.doubled()         )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false        )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true         )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true         )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p            )

            // Test commutativity
            p = c.g + c.g.doubled() ;
            REQUIRE_EQUAL( c.g.add( c.g.doubled() ), p )
            REQUIRE_EQUAL( p, c.g.doubled() + c.g      )
            REQUIRE_EQUAL( p, c.g.doubled().add( c.g ) )
            REQUIRE_EQUAL( p.is_identity(), false      )
            REQUIRE_EQUAL( p.is_on_curve(), true       )
            REQUIRE_EQUAL( p.is_valid()   , true       )

            p_proj = g_proj + g_proj.doubled();
            REQUIRE_EQUAL( g_proj.add( g_proj.doubled() ),  p_proj )
            REQUIRE_EQUAL( p_proj, g_proj.doubled() + g_proj       )
            REQUIRE_EQUAL( p_proj, g_proj.doubled().add( g_proj )  )
            REQUIRE_EQUAL( p_proj.is_identity(), false             )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true              )
            REQUIRE_EQUAL( p_proj.is_valid()   , true              )

            p_jacobi = g_jacobi + g_jacobi.doubled();
            REQUIRE_EQUAL( g_jacobi.add( g_jacobi.doubled() ),  p_jacobi )
            REQUIRE_EQUAL( p_jacobi, g_jacobi.doubled() + g_jacobi       )
            REQUIRE_EQUAL( p_jacobi, g_jacobi.doubled().add( g_jacobi )  )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false                 )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true                  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true                  )
        });

        // Custom curve
        // Test vectors were generated using https://graui.de/code/elliptic2/
        // and https://andrea.corbellini.name/ecc/interactive/modk-add.html
        {
            // {17, 20} = {3, 10} + {9, 7}
            c23_point p1 = c23.make_point( 3, 10  );
            c23_point p2 = c23.make_point( 9,  7  );
            c23_point p3 = c23.make_point( 17, 20 );

            auto p1_proj = ec_point_fp_proj( p1 );
            auto p2_proj = ec_point_fp_proj( p2 );

            auto p1_jacobi = ec_point_fp_jacobi( p1 );
            auto p2_jacobi = ec_point_fp_jacobi( p2 );

            auto r = p1 + p2;
            REQUIRE_EQUAL( r, p3 )
            REQUIRE_EQUAL( r.is_identity(), false )
            REQUIRE_EQUAL( r.is_on_curve(), true  )
            REQUIRE_EQUAL( r.is_valid()   , true  )

            auto r_proj = p1_proj + p2_proj;
            REQUIRE_EQUAL( r_proj.is_identity(), false )
            REQUIRE_EQUAL( r_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( r_proj.is_valid()   , true  )
            REQUIRE_EQUAL( r_proj.to_affine()  , p3    )

            auto r_jacobi = p1_jacobi + p2_jacobi;
            REQUIRE_EQUAL( r_jacobi.is_identity(), false )
            REQUIRE_EQUAL( r_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( r_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( r_jacobi.to_affine()  , p3    )

            // Adding point to its inverse should result in identity
            r = p1 + p1.inverted();
            REQUIRE_EQUAL( r.is_identity(), true  )
            REQUIRE_EQUAL( r.is_on_curve(), true  )
            REQUIRE_EQUAL( r.is_valid()   , false )
            REQUIRE_EQUAL( p1 - p1, r )
            REQUIRE_EQUAL( r + -r , r )

            r_proj = p1_proj + p1_proj.inverted();
            REQUIRE_EQUAL( r_proj.is_identity(), true  )
            REQUIRE_EQUAL( r_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( r_proj.is_valid()   , false )
            REQUIRE_EQUAL( r_proj.to_affine()  , r     )
            REQUIRE_EQUAL( p1_proj - p1_proj   , r_proj )
            REQUIRE_EQUAL( p1_proj + -p1_proj  , r_proj )

            r_jacobi = p1_jacobi + p1_jacobi.inverted();
            REQUIRE_EQUAL( r_jacobi.is_identity() , true     )
            REQUIRE_EQUAL( r_jacobi.is_on_curve() , true     )
            REQUIRE_EQUAL( r_jacobi.is_valid()    , false    )
            REQUIRE_EQUAL( r_jacobi.to_affine()   , r        )
            REQUIRE_EQUAL( p1_jacobi - p1_jacobi  , r_jacobi )
            REQUIRE_EQUAL( p1_jacobi + -p1_jacobi , r_jacobi )

            // O = {1, 16} + {1, 7}
            p1 = c23.make_point( 1, 16 );
            p2 = c23.make_point( 1, 7  );
            p3 = c23_point();

            p1_proj = ec_point_fp_proj( p1 );
            p2_proj = ec_point_fp_proj( p2 );

            p1_jacobi = ec_point_fp_jacobi( p1 );
            p2_jacobi = ec_point_fp_jacobi( p2 );

            r = p1 + p2;
            REQUIRE_EQUAL( r, p3 )
            REQUIRE_EQUAL( r.is_identity(), true  )
            REQUIRE_EQUAL( r.is_on_curve(), true  )
            REQUIRE_EQUAL( r.is_valid()   , false )

            r_proj = p1_proj + p2_proj;
            REQUIRE_EQUAL( r_proj, c23_point_proj()    )
            REQUIRE_EQUAL( r_proj.is_identity(), true  )
            REQUIRE_EQUAL( r_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( r_proj.is_valid()   , false )
            REQUIRE_EQUAL( r_proj.to_affine()  , p3    )

            r_jacobi = p1_jacobi + p2_jacobi;
            REQUIRE_EQUAL( r_jacobi, c23_point_jacobi()  )
            REQUIRE_EQUAL( r_jacobi.is_identity(), true  )
            REQUIRE_EQUAL( r_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( r_jacobi.is_valid()   , false )
            REQUIRE_EQUAL( r_jacobi.to_affine()  , p3    )
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

            const auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc.is_valid()   , true  )

            const auto Q_proj = ec_point_fp_proj( Q );
            const auto P_proj = ec_point_fp_proj( P );
            const auto Rc_proj = Q_proj + P_proj;
            REQUIRE_EQUAL( Rc_proj.is_identity(), false )
            REQUIRE_EQUAL( Rc_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_proj.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_proj.to_affine()  , R     );

            const auto Q_jacobi = ec_point_fp_jacobi( Q );
            const auto P_jacobi = ec_point_fp_jacobi( P );
            const auto Rc_jacobi = Q_jacobi + P_jacobi;
            REQUIRE_EQUAL( Rc_jacobi.is_identity(), false )
            REQUIRE_EQUAL( Rc_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_jacobi.to_affine()  , R     );
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

            const auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc.is_valid()   , true  )

            const auto Q_proj = ec_point_fp_proj( Q );
            const auto P_proj = ec_point_fp_proj( P );
            const auto Rc_proj = Q_proj + P_proj;
            REQUIRE_EQUAL( Rc_proj.is_identity(), false )
            REQUIRE_EQUAL( Rc_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_proj.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_proj.to_affine()  , R     );

            const auto Q_jacobi = ec_point_fp_jacobi( Q );
            const auto P_jacobi = ec_point_fp_jacobi( P );
            const auto Rc_jacobi = Q_jacobi + P_jacobi;
            REQUIRE_EQUAL( Rc_jacobi.is_identity(), false )
            REQUIRE_EQUAL( Rc_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_jacobi.to_affine()  , R     );
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

            const auto Rc = Q + P;
            REQUIRE_EQUAL( Rc , R );
            REQUIRE_EQUAL( Rc.is_identity(), false )
            REQUIRE_EQUAL( Rc.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc.is_valid()   , true  )

            const auto Q_proj = ec_point_fp_proj( Q );
            const auto P_proj = ec_point_fp_proj( P );
            const auto Rc_proj = Q_proj + P_proj;
            REQUIRE_EQUAL( Rc_proj.is_identity(), false )
            REQUIRE_EQUAL( Rc_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_proj.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_proj.to_affine()  , R     );

            const auto Q_jacobi = ec_point_fp_jacobi( Q );
            const auto P_jacobi = ec_point_fp_jacobi( P );
            const auto Rc_jacobi = Q_jacobi + P_jacobi;
            REQUIRE_EQUAL( Rc_jacobi.is_identity(), false )
            REQUIRE_EQUAL( Rc_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( Rc_jacobi.is_valid()   , true  )
            REQUIRE_EQUAL( Rc_jacobi.to_affine()  , R     );
        }
    EOSIO_TEST_END //ec_add_test

    EOSIO_TEST_BEGIN( ec_sub_test )
        using namespace detail;

        // General test
        for_each_curve_do( []<typename CurveT>(const CurveT& c) {
            using point_type        = typename CurveT::point_type;
            using point_proj_type   = ec_point_fp_proj<CurveT>;
            using point_jacobi_type = ec_point_fp_jacobi<CurveT>;

            // Test summing identity point results in identity
            point_type p = point_type() - point_type();
            REQUIRE_EQUAL( p, point_type()        )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            point_proj_type p_proj = point_proj_type() - point_proj_type();
            REQUIRE_EQUAL( p_proj, point_proj_type()   )
            REQUIRE_EQUAL( p_proj.is_identity(), true  )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
            REQUIRE_EQUAL( p_proj.is_valid()   , false )
            REQUIRE_EQUAL( p_proj.to_affine()  , p     )

            point_jacobi_type p_jacobi = point_jacobi_type() - point_jacobi_type();
            REQUIRE_EQUAL( p_jacobi, point_jacobi_type() )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true  )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p     )

            // Test subtracting identity from point results in point
            p = c.g - point_type();
            REQUIRE_EQUAL( p, c.g                 )
            REQUIRE_EQUAL( p.is_identity(), false )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , true  )

            const auto g_proj = ec_point_fp_proj( c.g );
            p_proj = g_proj - point_proj_type();
            REQUIRE_EQUAL( p_proj              , g_proj )
            REQUIRE_EQUAL( p_proj.is_identity(), false  )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true   )
            REQUIRE_EQUAL( p_proj.is_valid()   , true   )
            REQUIRE_EQUAL( p_proj.to_affine()  , c.g    )

            const auto g_jacobi = ec_point_fp_jacobi( c.g );
            p_jacobi = g_jacobi - point_jacobi_type();
            REQUIRE_EQUAL( p_jacobi              , g_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false    )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true     )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , c.g      )

            // Test subtracting point from identity results in inverse of point
            p = point_type() - c.g;
            REQUIRE_EQUAL( point_type().sub( c.g ), p )
            REQUIRE_EQUAL( p, -c.g                )
            REQUIRE_EQUAL( p.is_identity(), false )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , true  )

            p_proj = point_proj_type() - g_proj;
            REQUIRE_EQUAL( point_proj_type().sub( g_proj ),  p_proj )
            REQUIRE_EQUAL( p_proj              , -g_proj )
            REQUIRE_EQUAL( p_proj.is_identity(), false   )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true    )
            REQUIRE_EQUAL( p_proj.is_valid()   , true    )
            REQUIRE_EQUAL( p_proj.to_affine()  , -c.g    )

            p_jacobi = point_jacobi_type() - g_jacobi;
            REQUIRE_EQUAL( point_jacobi_type().sub( g_jacobi ),  p_jacobi )
            REQUIRE_EQUAL( p_jacobi              , -g_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity(), false     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true      )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , true      )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , -c.g      )

            // Test subtracting point from itself results in identity
            p = c.g - c.g;
            REQUIRE_EQUAL( c.g.sub( c.g ), p )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            p_proj = g_proj - g_proj;
            REQUIRE_EQUAL( g_proj.sub( g_proj ),  p_proj )
            REQUIRE_EQUAL( p_proj.is_identity(), true    )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true    )
            REQUIRE_EQUAL( p_proj.is_valid()   , false   )
            REQUIRE_EQUAL( p_proj.to_affine()  , p       )

            p_jacobi = g_jacobi - g_jacobi;
            REQUIRE_EQUAL( g_jacobi.sub( g_jacobi ) ,  p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()   , true      )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()   , true      )
            REQUIRE_EQUAL( p_jacobi.is_valid()      , false     )
            REQUIRE_EQUAL( p_jacobi.to_affine()     , p         )
        });
    EOSIO_TEST_END //ec_sub_test

    EOSIO_TEST_BEGIN( ec_mul_test )
        using namespace detail;

        // General test
        for_each_curve_do( []<typename CurveT>(const CurveT& c) {
            using point_type        = typename CurveT::point_type;
            using point_proj_type   = ec_point_fp_proj<CurveT>;
            using point_jacobi_type = ec_point_fp_jacobi<CurveT>;

            // Test multiplying identity point results in identity
            point_type p = point_type() * 0;
            REQUIRE_EQUAL( point_type().mul( 0 ), p     )
            REQUIRE_EQUAL( p.is_identity()      , true  )
            REQUIRE_EQUAL( p.is_on_curve()      , true  )
            REQUIRE_EQUAL( p.is_valid()         , false )

            point_proj_type p_proj = point_proj_type() * 0;
            REQUIRE_EQUAL( point_proj_type().mul( 0 ), p_proj )
            REQUIRE_EQUAL( p_proj.is_identity()      , true   )
            REQUIRE_EQUAL( p_proj.is_on_curve()      , true   )
            REQUIRE_EQUAL( p_proj.is_valid()         , false  )
            REQUIRE_EQUAL( p_proj.to_affine()        , p      )

            point_jacobi_type p_jacobi = point_jacobi_type() * 0;
            REQUIRE_EQUAL( point_jacobi_type().mul( 0 ), p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()         , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()        , p        )

            p = point_type() * 1;
            REQUIRE_EQUAL( point_type().mul( 1 ), p     )
            REQUIRE_EQUAL( p.is_identity()      , true  )
            REQUIRE_EQUAL( p.is_on_curve()      , true  )
            REQUIRE_EQUAL( p.is_valid()         , false )

            p_proj = point_proj_type() * 1;
            REQUIRE_EQUAL( point_proj_type().mul( 1 ), p_proj )
            REQUIRE_EQUAL( p_proj.is_identity()      , true   )
            REQUIRE_EQUAL( p_proj.is_on_curve()      , true   )
            REQUIRE_EQUAL( p_proj.is_valid()         , false  )
            REQUIRE_EQUAL( p_proj.to_affine()        , p      )

            p_jacobi = point_jacobi_type() * 1;
            REQUIRE_EQUAL( point_jacobi_type().mul( 1 ), p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()         , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()        , p        )

            p = point_type() * 2;
            REQUIRE_EQUAL( point_type().mul( 2 ), p     )
            REQUIRE_EQUAL( p.is_identity()      , true  )
            REQUIRE_EQUAL( p.is_on_curve()      , true  )
            REQUIRE_EQUAL( p.is_valid()         , false )

            p_proj = point_proj_type() * 2;
            REQUIRE_EQUAL( point_proj_type().mul( 2 ), p_proj )
            REQUIRE_EQUAL( p_proj.is_identity()      , true   )
            REQUIRE_EQUAL( p_proj.is_on_curve()      , true   )
            REQUIRE_EQUAL( p_proj.is_valid()         , false  )
            REQUIRE_EQUAL( p_proj.to_affine()        , p      )

            p_jacobi = point_jacobi_type() * 2;
            REQUIRE_EQUAL( point_jacobi_type().mul( 2 ), p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()         , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()        , p        )

            p = point_type() * 3;
            REQUIRE_EQUAL( point_type().mul( 3 ), p     )
            REQUIRE_EQUAL( p.is_identity()      , true  )
            REQUIRE_EQUAL( p.is_on_curve()      , true  )
            REQUIRE_EQUAL( p.is_valid()         , false )

            p_proj = point_proj_type() * 3;
            REQUIRE_EQUAL( point_proj_type().mul( 3 ), p_proj )
            REQUIRE_EQUAL( p_proj.is_identity()      , true   )
            REQUIRE_EQUAL( p_proj.is_on_curve()      , true   )
            REQUIRE_EQUAL( p_proj.is_valid()         , false  )
            REQUIRE_EQUAL( p_proj.to_affine()        , p      )

            p_jacobi = point_jacobi_type() * 3;
            REQUIRE_EQUAL( point_jacobi_type().mul( 3 ), p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()      , true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()         , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()        , p        )

            p = point_type() * 6555365;
            REQUIRE_EQUAL( point_type().mul( 6555365 ), p     )
            REQUIRE_EQUAL( p.is_identity()            , true  )
            REQUIRE_EQUAL( p.is_on_curve()            , true  )
            REQUIRE_EQUAL( p.is_valid()               , false )

            p_proj = point_proj_type() * 6555365;
            REQUIRE_EQUAL( point_proj_type().mul( 6555365 ), p_proj )
            REQUIRE_EQUAL( p_proj.is_identity()            , true   )
            REQUIRE_EQUAL( p_proj.is_on_curve()            , true   )
            REQUIRE_EQUAL( p_proj.is_valid()               , false  )
            REQUIRE_EQUAL( p_proj.to_affine()              , p      )

            p_jacobi = point_jacobi_type() * 6555365;
            REQUIRE_EQUAL( point_jacobi_type().mul( 6555365 ), p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity()            , true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve()            , true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()               , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()              , p        )


            if constexpr ( typename CurveT::int_type().max_byte_size() >= 16 ) {
                p = point_type() * "0E09796974C57E714C35F110DFC27CCB";
                REQUIRE_EQUAL( point_type().mul( "0E09796974C57E714C35F110DFC27CCB" ), p )
                REQUIRE_EQUAL( p.is_identity(), true  )
                REQUIRE_EQUAL( p.is_on_curve(), true  )
                REQUIRE_EQUAL( p.is_valid()   , false )

                p_proj = point_proj_type() * "0E09796974C57E714C35F110DFC27CCB";
                REQUIRE_EQUAL( point_proj_type().mul( "0E09796974C57E714C35F110DFC27CCB" ), p_proj )
                REQUIRE_EQUAL( p_proj.is_identity(), true  )
                REQUIRE_EQUAL( p_proj.is_on_curve(), true  )
                REQUIRE_EQUAL( p_proj.is_valid()   , false )
                REQUIRE_EQUAL( p_proj.to_affine()  , p     )

                p_jacobi = point_jacobi_type() * "0E09796974C57E714C35F110DFC27CCB";
                REQUIRE_EQUAL( point_jacobi_type().mul( "0E09796974C57E714C35F110DFC27CCB" ), p_jacobi )
                REQUIRE_EQUAL( p_jacobi.is_identity(), true  )
                REQUIRE_EQUAL( p_jacobi.is_on_curve(), true  )
                REQUIRE_EQUAL( p_jacobi.is_valid()   , false )
                REQUIRE_EQUAL( p_jacobi.to_affine()  , p     )
            }

            // Test multiplying generator by 0 results in identity
            REQUIRE_EQUAL( c.g.is_identity(), false );
            const auto g_proj = point_proj_type( c.g );
            const auto g_jacobi = point_jacobi_type( c.g );

            p = c.g * 0;
            REQUIRE_EQUAL( c.g.mul( 0 )   , p     )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            p_proj = g_proj * 0;
            REQUIRE_EQUAL( g_proj.mul( 0 )     , p_proj )
            REQUIRE_EQUAL( p_proj.is_identity(), true   )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true   )
            REQUIRE_EQUAL( p_proj.is_valid()   , false  )
            REQUIRE_EQUAL( p_proj.to_affine()  , p      )

            p_jacobi = g_jacobi * 0;
            REQUIRE_EQUAL( g_jacobi.mul( 0 )     , p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p        )

            // Test multiplying generator by order results in identity
            p = c.g * c.n;
            REQUIRE_EQUAL( c.g.mul( c.n  ), p     )
            REQUIRE_EQUAL( p.is_identity(), true  )
            REQUIRE_EQUAL( p.is_on_curve(), true  )
            REQUIRE_EQUAL( p.is_valid()   , false )

            p_proj = g_proj * c.n;
            REQUIRE_EQUAL( g_proj.mul( c.n )   , p_proj )
            REQUIRE_EQUAL( p_proj.is_identity(), true   )
            REQUIRE_EQUAL( p_proj.is_on_curve(), true   )
            REQUIRE_EQUAL( p_proj.is_valid()   , false  )
            REQUIRE_EQUAL( p_proj.to_affine()  , p      )

            p_jacobi = g_jacobi * c.n;
            REQUIRE_EQUAL( g_jacobi.mul( c.n )   , p_jacobi )
            REQUIRE_EQUAL( p_jacobi.is_identity(), true     )
            REQUIRE_EQUAL( p_jacobi.is_on_curve(), true     )
            REQUIRE_EQUAL( p_jacobi.is_valid()   , false    )
            REQUIRE_EQUAL( p_jacobi.to_affine()  , p        )

            // Test multiplying generator with 100 scalar values
            p        = c.g;
            p_proj   = g_proj;
            p_jacobi = g_jacobi;
            typename CurveT::int_type n_mul = 0;
            for ( uint32_t i = 1; i < 101; i++ ) {
                 if ( p.is_identity() ) {
                    if ( n_mul == 0 ) {
                       REQUIRE_EQUAL( ( c.n / i ) * i, c.n ) // order n must bi multiple of i for the p to be identity
                       n_mul = i;
                    }
                    else {
                       REQUIRE_EQUAL( (i / n_mul) * n_mul, i ) // i must be multiple of n_mul for the p to be identity
                    }
                 }

                REQUIRE_EQUAL( c.g * i                 , p                )
                REQUIRE_EQUAL( p.is_on_curve()         , true             )
                REQUIRE_EQUAL( p.is_valid()            , !p.is_identity() )
                REQUIRE_EQUAL( ( p + -p ).is_identity(), true             )

                REQUIRE_EQUAL( g_proj * i                        , p_proj           )
                REQUIRE_EQUAL( p_proj.is_identity()              , p.is_identity()  )
                REQUIRE_EQUAL( p_proj.is_on_curve()              , true             )
                REQUIRE_EQUAL( p_proj.is_valid()                 , !p.is_identity() )
                REQUIRE_EQUAL( p_proj.to_affine()                , p                )
                REQUIRE_EQUAL( ( p_proj + -p_proj ).is_identity(), true             )

                REQUIRE_EQUAL( g_jacobi * i                          , p_jacobi         )
                REQUIRE_EQUAL( p_jacobi.is_identity()                , p.is_identity()  )
                REQUIRE_EQUAL( p_jacobi.is_on_curve()                , true             )
                REQUIRE_EQUAL( p_jacobi.is_valid()                   , !p.is_identity() )
                REQUIRE_EQUAL( p_jacobi.to_affine()                  , p                )
                REQUIRE_EQUAL( ( p_jacobi + -p_jacobi ).is_identity(), true             )

                p        += c.g;
                p_proj   += g_proj;
                p_jacobi += g_jacobi;
            }

            // Test multiplying generator with 100 negative scalar values
            p        = -c.g;
            p_proj   = -g_proj;
            p_jacobi = -g_jacobi;
            for ( int32_t i = 1; i < 101; i++ ) {
                if ( p.is_identity() ) {
                    if ( n_mul == 0 ) {
                       REQUIRE_EQUAL( ( c.n / i ) * i, c.n ) // order n must bi multiple of i for the p to be identity
                       n_mul = i;
                    }
                    else {
                       REQUIRE_EQUAL( (i / n_mul) * n_mul, i ) // i must be multiple of n_mul for the p to be identity
                    }
                }

                REQUIRE_EQUAL( c.g * -i                , p                )
                REQUIRE_EQUAL( p.is_on_curve()         , true             )
                REQUIRE_EQUAL( p.is_valid()            , !p.is_identity() )
                REQUIRE_EQUAL( ( p + -p ).is_identity(), true             )

                REQUIRE_EQUAL( g_proj * -i                       , p_proj           )
                REQUIRE_EQUAL( p_proj.is_identity()              , p.is_identity()  )
                REQUIRE_EQUAL( p_proj.is_on_curve()              , true             )
                REQUIRE_EQUAL( p_proj.is_valid()                 , !p.is_identity() )
                REQUIRE_EQUAL( p_proj.to_affine()                , p                )
                REQUIRE_EQUAL( ( p_proj + -p_proj ).is_identity(), true             )

                REQUIRE_EQUAL( g_jacobi * -i                         , p_jacobi         )
                REQUIRE_EQUAL( p_jacobi.is_identity()                , p.is_identity()  )
                REQUIRE_EQUAL( p_jacobi.is_on_curve()                , true             )
                REQUIRE_EQUAL( p_jacobi.is_valid()                   , !p.is_identity() )
                REQUIRE_EQUAL( p_jacobi.to_affine()                  , p                )
                REQUIRE_EQUAL( ( p_jacobi + -p_jacobi ).is_identity(), true             )

                p        -= c.g;
                p_proj   -= g_proj;
                p_jacobi -= g_jacobi;
            }
        });
    EOSIO_TEST_END // ec_mul_test

    EOSIO_TEST_BEGIN(ec_mul_secp256k1_test)
        using namespace detail;
        using namespace std::string_view_literals;
        using bn_t              = typename secp256k1_t::int_type;
        const auto& curve       = secp256k1;
        using point_proj_type   = secp256k1_point_proj;
        using point_jacobi_type = secp256k1_point_jacobi;

        // Just making sure variables are correctly calculated and cached
        static_assert( curve.a_is_minus_3 == false );
        REQUIRE_EQUAL( curve.a_is_minus_3 == false, true )

        static_assert( curve.a_is_zero == true );
        REQUIRE_EQUAL( curve.a_is_zero == true, true )

        // Custom test generated with python
        {
            auto k  = bn_t( "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3" );
            auto p1 = curve.make_point( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", /*verify=*/ true );
            auto p2 = p1 * k;
            REQUIRE_EQUAL( p2.x , "EED4CB4E92BB0D5D85DBDB7995776135DC54208E710D585289AE129DD8EA6ACE" )
            REQUIRE_EQUAL( p2.y , "982FCA2C5901EA6E67F6EE86656F072A8AEDF243ED690A97C368664CC744C4A3" )

            auto p1_proj = ec_point_fp_proj( p1 );
            auto p2_proj = p1_proj * k;
            REQUIRE_EQUAL( p2_proj.to_affine(), p2 )

            auto p1_jacobi = ec_point_fp_jacobi( p1 );
            auto p2_jacobi = p1_jacobi * k;
            REQUIRE_EQUAL( p2_jacobi.to_affine(), p2 )

            k = bn_t( "5CBDF0646E5DB4EAA398F365" );
            p2 *= k;
            REQUIRE_EQUAL( p2.x , "EFDB9793C70B1572C4EBB3FC0F4950664E585D17CFCA213A62577F1FBAA90466" )
            REQUIRE_EQUAL( p2.y , "6F413AA07DE4725313A601EEBA0084EBD511B6E019F45E17889124B8CFFAB6AE" )

            p2_proj *= k;
            REQUIRE_EQUAL( p2_proj.to_affine(), p2 )

            p2_jacobi *= k;
            REQUIRE_EQUAL( p2_jacobi.to_affine(), p2 )

            k = -bn_t( "DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" );
            auto p3 = p2 * k;
            REQUIRE_EQUAL( p3.x , "ED03E116F92A916361DB25AC8AE2A97C6762BA5E25A5955BF8DAA3DD2CA582E1" )
            REQUIRE_EQUAL( p3.y , "BB1CC6CE54BBF2ACEF7950DF46670124CF947E60C7BB69338C624EC6B763C49C" )

            auto p3_proj = p2_proj * k;
            REQUIRE_EQUAL( p3_proj.to_affine(), p3 )

            auto p3_jacobi = p2_jacobi * k;
            REQUIRE_EQUAL( p3_jacobi.to_affine(), p3 )

            k = bn_t( "C136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F51921" );
            auto p4 = -p3 * k;
            REQUIRE_EQUAL( p4.x , "9888D3776EBCFF17FAB4B31DE9A98A45AAEC1AFC1FBA288E0B78A0030732B57C" )
            REQUIRE_EQUAL( p4.y , "8A58BDF2645D0E7B53D76AC9EB47A52ECE0EC2670D3299E3BCF20162E6128A5C" )

            auto p4_proj = -p3_proj * k;
            REQUIRE_EQUAL( p4_proj.to_affine(), p4 )

            auto p4_jacobi = -p3_jacobi * k;
            REQUIRE_EQUAL( p4_jacobi.to_affine(), p4 )

            auto p5 = -p3 * -k;
            REQUIRE_EQUAL( p5.x , "9888D3776EBCFF17FAB4B31DE9A98A45AAEC1AFC1FBA288E0B78A0030732B57C" )
            REQUIRE_EQUAL( p5.y , "75A7420D9BA2F184AC28953614B85AD131F13D98F2CD661C430DFE9C19ED71D3" )

            auto p5_proj = -p3_proj * -k;
            REQUIRE_EQUAL( p5_proj.to_affine(), p5 )

            auto p5_jacobi = -p3_jacobi * -k;
            REQUIRE_EQUAL( p5_jacobi.to_affine(), p5 )
        }

        // Test vectors from: https://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available
        {
            auto k = bn_t( "1" );
            auto r = curve.make_point( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "1" ), r )
            REQUIRE_EQUAL( curve.generate_point( "1"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1"sv ).to_affine(), r )

            k = bn_t( "2" );
            r = curve.make_point( "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "2" ), r )
            REQUIRE_EQUAL( curve.generate_point( "2"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "2" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "2"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "2" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "2"sv ).to_affine(), r )

            k = bn_t( "3" );
            r = curve.make_point( "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "3" ), r )
            REQUIRE_EQUAL( curve.generate_point( "3"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3"sv ).to_affine(), r )

            k = bn_t( "4" );
            r = curve.make_point( "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13", "51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "4" ), r )
            REQUIRE_EQUAL( curve.generate_point( "4"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4"sv ).to_affine(), r )

            k = bn_t( "5" );
            r = curve.make_point( "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4", "D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "5" ), r )
            REQUIRE_EQUAL( curve.generate_point( "5"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "5" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "5"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "5" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "5"sv ).to_affine(), r )

            k = bn_t( "6" );
            r = curve.make_point( "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556", "AE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "6" ), r )
            REQUIRE_EQUAL( curve.generate_point( "6"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6"sv ).to_affine(), r )

            k = bn_t( "7" );
            r = curve.make_point( "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC", "6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7"sv ).to_affine(), r )

            k = bn_t( "8" );
            r = curve.make_point( "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01", "5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "8" ), r )
            REQUIRE_EQUAL( curve.generate_point( "8"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "8" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "8"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "8" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "8"sv ).to_affine(), r )

            k = bn_t( "9" );
            r = curve.make_point( "ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE", "CC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "9" ), r )
            REQUIRE_EQUAL( curve.generate_point( "9"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "9"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "9"sv ).to_affine(), r )

            k = bn_t( "A" );
            r = curve.make_point( "A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7", "893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "A" ), r )
            REQUIRE_EQUAL( curve.generate_point( "A"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "A"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "A"sv ).to_affine(), r )

            k = bn_t( "B" );
            r = curve.make_point( "774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB", "D984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "B" ), r )
            REQUIRE_EQUAL( curve.generate_point( "B"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "B"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "B"sv ).to_affine(), r )

            k = bn_t( "C" );
            r = curve.make_point( "D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A", "A9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "C" ), r )
            REQUIRE_EQUAL( curve.generate_point( "C"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "C"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "C"sv ).to_affine(), r )

            k = bn_t( "D" );
            r = curve.make_point( "F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8", "AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "D"sv ).to_affine(), r )

            k = bn_t( "E" );
            r = curve.make_point( "499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4", "CAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "E"sv ).to_affine(), r )

            k = bn_t( "F" );
            r = curve.make_point( "D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E", "581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "F"sv ).to_affine(), r )

            k = bn_t( "10" );
            r = curve.make_point( "E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A", "F7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "10" ), r )
            REQUIRE_EQUAL( curve.generate_point( "10"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "10" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "10"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "10" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "10"sv ).to_affine(), r )

            k = bn_t( "11" );
            r = curve.make_point( "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "11" ), r )
            REQUIRE_EQUAL( curve.generate_point( "11"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "11" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "11"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "11" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "11"sv ).to_affine(), r )

            k = bn_t( "12" );
            r = curve.make_point( "5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC", "C136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "12" ), r )
            REQUIRE_EQUAL( curve.generate_point( "12"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "12" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "12"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "12" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "12"sv ).to_affine(), r )

            k = bn_t( "13" );
            r = curve.make_point( "2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C", "85E89BC037945D93B343083B5A1C86131A01F60C50269763B570C854E5C09B7A", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "13"sv ).to_affine(), r )

            k = bn_t( "14" );
            r = curve.make_point( "4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97", "12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "14" ), r )
            REQUIRE_EQUAL( curve.generate_point( "14"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "14" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "14"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "14" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "14"sv ).to_affine(), r )

            k = bn_t( "18EBBB95EED0E13" );
            r = curve.make_point( "A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29", "5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "18EBBB95EED0E13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "18EBBB95EED0E13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "18EBBB95EED0E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "18EBBB95EED0E13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "18EBBB95EED0E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "18EBBB95EED0E13"sv ).to_affine(), r )

            k = bn_t( "159D893D4CDD747246CDCA43590E13" );
            r = curve.make_point( "E5A2636BCFD412EBF36EC45B19BFB68A1BC5F8632E678132B885F7DF99C5E9B3", "736C1CE161AE27B405CAFD2A7520370153C2C861AC51D6C1D5985D9606B45F39", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "159D893D4CDD747246CDCA43590E13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "159D893D4CDD747246CDCA43590E13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "159D893D4CDD747246CDCA43590E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "159D893D4CDD747246CDCA43590E13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "159D893D4CDD747246CDCA43590E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "159D893D4CDD747246CDCA43590E13"sv ).to_affine(), r )

            k = bn_t( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050" );
            r = curve.make_point( "A6B594B38FB3E77C6EDF78161FADE2041F4E09FD8497DB776E546C41567FEB3C", "71444009192228730CD8237A490FEBA2AFE3D27D7CC1136BC97E439D13330D55", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050" ), r )
            REQUIRE_EQUAL( curve.generate_point( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050"sv ).to_affine(), r )

            k = bn_t( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" );
            r = curve.make_point( "3B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63", "3F3979BF72AE8202983DC989AEC7F2FF2ED91BDD69CE02FC0700CA100E59DDF3", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"sv ).to_affine(), r )

            k = bn_t( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0" );
            r = curve.make_point( "E24CE4BEEE294AA6350FAA67512B99D388693AE4E7F53D19882A6EA169FC1CE1", "8B71E83545FC2B5872589F99D948C03108D36797C4DE363EBD3FF6A9E1A95B10", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0" ), r )
            REQUIRE_EQUAL( curve.generate_point( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0C0325AD0376782CCFDDC6E99C28B0F0"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D" );
            r = curve.make_point( "4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97", "ED45D9234EF13E9DA259E05EF57BB3989E9D6B7D8E269698BAFD77106DCC1FF5", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412D"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E" );
            r = curve.make_point( "2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C", "7A17643FC86BA26C4CBCF7C4A5E379ECE5FE09F3AFD9689C4A8F37AA1A3F60B5", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412E"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F" );
            r = curve.make_point( "5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC", "3EC93E23F34146CF161D67FBCA76CAE27E271F438C951D5E0AE6D1A074F9DED7", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036412F"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130" );
            r = curve.make_point( "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "BDEE54F96B9CAE9716684F152D56C251312E0B5FB56A3F09304E660861A910B8", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364130"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131" );
            r = curve.make_point( "E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A", "81CAF8C661A6A6D624660CB0A86C8EFED6976E1BB2DC0F41E0CD330969E940E", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364131"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132" );
            r = curve.make_point( "D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E", "A7E1D78D57938D597C7BD13DD733921015BF50D427692C5A3AFB235F095D90D7", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133" );
            r = curve.make_point( "499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4", "353D093B4AB17AAE6F0FBB1B584C2B9BB9BD863D85C06A4339A0BF2AFC5EBCD4", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364133"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134" );
            r = curve.make_point( "F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8", "F54F6FD17277F5768A7DED149A3250B8C5E5F925ADE056E0D64A34AC24FC0EAE", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364134"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135" );
            r = curve.make_point( "D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A", "560CB00237EA1F285749BAC81E8427EA86DC73A2265792AD94FAE4EB0BF9D908", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364135"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136" );
            r = curve.make_point( "774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB", "267B5FCD1494A1E6FDBC22A928484C9AC8D24E1D20062957CFE28B3536AC3614", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364136"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137" );
            r = curve.make_point( "A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7", "76C545BDABE643D85C4938196C5DB3969086B3D127885EA6C3411AC3FC8C9358", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364137"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138" );
            r = curve.make_point( "ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE", "33CC76DE4F5826029BC7F68E89C49E165227775BC8A071F0FA33D9D439B05FF8", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364138"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139" );
            r = curve.make_point( "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01", "A3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364139"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A" );
            r = curve.make_point( "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC", "951435BF45DAA69F5CE8729279E5AB2457EC2F47EC02184A5AF7D9D6F78D9755", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413A"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B" );
            r = curve.make_point( "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556", "51ED8885530449DF0C4169FE80BA3A9F217F0F09AE701B5FC378F3C84F8A0998", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413B"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C" );
            r = curve.make_point( "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4", "2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D" );
            r = curve.make_point( "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13", "AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E" );
            r = curve.make_point( "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "C77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F" );
            r = curve.make_point( "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", "E51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" );
            r = curve.make_point( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"sv ).to_affine(), r )

            k = bn_t( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522" );
            r = curve.make_point( "34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6", "B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522" ), r )
            REQUIRE_EQUAL( curve.generate_point( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522"sv ).to_affine(), r )

            k = bn_t( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3" );
            r = curve.make_point( "D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575", "131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3"sv ).to_affine(), r )

            k = bn_t( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D" );
            r = curve.make_point( "E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F", "C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D"sv ).to_affine(), r )

            k = bn_t( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC" );
            r = curve.make_point( "14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1", "297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC" ), r )
            REQUIRE_EQUAL( curve.generate_point( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC"sv ).to_affine(), r )

            k = bn_t( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9" );
            r = curve.make_point( "F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3", "F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9" ), r )
            REQUIRE_EQUAL( curve.generate_point( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9"sv ).to_affine(), r )
        }
    EOSIO_TEST_END // ec_mul_secp256k1_test

    EOSIO_TEST_BEGIN(ec_mul_secp256r1_test)
        using namespace detail;
        using namespace std::string_view_literals;
        using bn_t              = typename secp256r1_t::int_type;
        constexpr auto& curve   = secp256r1;
        using point_proj_type   = secp256r1_point_proj;
        using point_jacobi_type = secp256r1_point_jacobi;

        // Just making sure variables are correctly calculated and cached
        static_assert( curve.a_is_minus_3 == true );
        REQUIRE_EQUAL( curve.a_is_minus_3 == true, true )

        static_assert( curve.a_is_zero == false );
        REQUIRE_EQUAL( curve.a_is_zero == false, true )

        // Test vectors from Botan library
        // src: https://github.com/randombit/botan/blob/321a50789e6eeda6898af114492445f0882ee70f/src/tests/data/pubkey/ecc_var_point_mul.vec
        {
            // [secp256r1]
            auto p = curve.make_point( "00", "66485C780E2F83D72433BD5D84A06BB6541C2AF31DAE871728BF856A174F93F4" );
            auto k = bn_t( "8C9F8D338CCF9A69E06E8EC420628FB4" );
            auto r = p * k;
            REQUIRE_EQUAL( r, curve.make_point( "52E0813F4C154FA39773CE64050F2080E9EDB63D2EDCB6119AEDFFC42AE03D34", "804D3E8A3BCEBA2FD1EE0429F100EAE459C90E443B96D5A98FCD97787656816D" ) )
            REQUIRE_EQUAL( r, ( ec_point_fp_proj( p ) * k ).to_affine() )
            REQUIRE_EQUAL( r, ( ec_point_fp_jacobi( p ) * k ).to_affine() )

            p = curve.make_point( "00", "99B7A386F1D07C29DBCC42A27B5F9449ABE3D50DE25178E8D7407A95E8B06C0B" );
            k = bn_t( "812F33B934572023C803A97A4144D1ED" );
            r = p * k;
            REQUIRE_EQUAL( r, curve.make_point( "3521B6A34485ECCCD6E73A2D69D3EBB837E70BFBA583962577D004520C46573E", "FB2ABBE62BE5211FBE63D65C0A32D6258792C86DC26D264456DC9DAC43CB54A8" ) )
            REQUIRE_EQUAL( r, ( ec_point_fp_proj( p ) * k ).to_affine() )
            REQUIRE_EQUAL( r, ( ec_point_fp_jacobi( p ) * k ).to_affine() )
        }

        // Test vectors from: https://web.archive.org/web/20210929025107/http://point-at-infinity.org/ecc/nisttv
        {
            auto k = bn_t( "1" );
            auto r = curve.make_point( "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "1" ), r )
            REQUIRE_EQUAL( curve.generate_point( "1"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1"sv ).to_affine(), r )

            k = bn_t( "2" );
            r = curve.make_point( "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", "7775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "2" ), r )
            REQUIRE_EQUAL( curve.generate_point( "2"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "2" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "2"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "2" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "2"sv ).to_affine(), r )

            k = bn_t( "3" );
            r = curve.make_point( "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C", "8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "3" ), r )
            REQUIRE_EQUAL( curve.generate_point( "3"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3"sv ).to_affine(), r )

            k = bn_t( "4" );
            r = curve.make_point( "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852", "E0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "4" ), r )
            REQUIRE_EQUAL( curve.generate_point( "4"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4"sv ).to_affine(), r )

            k = bn_t( "5" );
            r = curve.make_point( "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED", "E0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "5" ), r )
            REQUIRE_EQUAL( curve.generate_point( "5"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "5" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "5"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "5" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "5"sv ).to_affine(), r )

            k = bn_t( "6" );
            r = curve.make_point( "B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9", "E85C10743237DAD56FEC0E2DFBA703791C00F7701C7E16BDFD7C48538FC77FE2", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "6" ), r )
            REQUIRE_EQUAL( curve.generate_point( "6"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "6"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "6"sv ).to_affine(), r )

            k = bn_t( "7" );
            r = curve.make_point( "8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3", "73EB1DBDE03318366D069F83A6F5900053C73633CB041B21C55E1A86C1F400B4", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7"sv ).to_affine(), r )

            k = bn_t( "8" );
            r = curve.make_point( "62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393", "AD5ACCBD91E9D8244FF15D771167CEE0A2ED51F6BBE76A78DA540A6A0F09957E", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "8" ), r )
            REQUIRE_EQUAL( curve.generate_point( "8"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "8" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "8"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "8" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "8"sv ).to_affine(), r )

            k = bn_t( "9" );
            r = curve.make_point( "EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0", "2A2744C972C9FCE787014A964A8EA0C84D714FEAA4DE823FE85A224A4DD048FA", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "9" ), r )
            REQUIRE_EQUAL( curve.generate_point( "9"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "9"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "9" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "9"sv ).to_affine(), r )

            k = bn_t( "A" );
            r = curve.make_point( "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F", "878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "A" ), r )
            REQUIRE_EQUAL( curve.generate_point( "A"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "A"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "A"sv ).to_affine(), r )

            k = bn_t( "B" );
            r = curve.make_point( "3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1", "9099209ACCC4C8A224C843AFA4F4C68A090D04DA5E9889DAE2F8EEFCE82A3740", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "B" ), r )
            REQUIRE_EQUAL( curve.generate_point( "B"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "B"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "B"sv ).to_affine(), r )

            k = bn_t( "C" );
            r = curve.make_point( "741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4", "770B46A9C385FDC567383554887B1548EEB912C35BA5CA71995FF22CD4481D3", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "C" ), r )
            REQUIRE_EQUAL( curve.generate_point( "C"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "C"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "C"sv ).to_affine(), r )

            k = bn_t( "D" );
            r = curve.make_point( "177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01", "63BB58CD4EBEA558A24091ADB40F4E7226EE14C3A1FB4DF39C43BBE2EFC7BFD8", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "D"sv ).to_affine(), r )

            k = bn_t( "E" );
            r = curve.make_point( "54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B", "F599F1BB29F4317542121F8C05A2E7C37171EA77735090081BA7C82F60D0B375", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "E"sv ).to_affine(), r )

            k = bn_t( "F" );
            r = curve.make_point( "F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F", "B5B93EE3592E2D1F4E6594E51F9643E62A3B21CE75B5FA3F47E59CDE0D034F36", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "F"sv ).to_affine(), r )

            k = bn_t( "10" );
            r = curve.make_point( "76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E", "A985FE61341F260E6CB0A1B5E11E87208599A0040FC78BAA0E9DDD724B8C5110", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "10" ), r )
            REQUIRE_EQUAL( curve.generate_point( "10"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "10" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "10"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "10" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "10"sv ).to_affine(), r )

            k = bn_t( "11" );
            r = curve.make_point( "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E", "AA005EE6B5B957286231856577648E8381B2804428D5733F32F787FF71F1FCDC", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "11" ), r )
            REQUIRE_EQUAL( curve.generate_point( "11"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "11" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "11"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "11" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "11"sv ).to_affine(), r )

            k = bn_t( "12" );
            r = curve.make_point( "1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA", "F6F1645A15CBE5DC9FA9B7DFD96EE5A7DCC11B5C5EF4F1F78D83B3393C6A45A2", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "12" ), r )
            REQUIRE_EQUAL( curve.generate_point( "12"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "12" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "12"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "12" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "12"sv ).to_affine(), r )

            k = bn_t( "13" );
            r = curve.make_point( "CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83", "58D7614B24D9EF515C35E7100D6D6CE4A496716E30FA3E03E39150752BCECDAA", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "13"sv ).to_affine(), r )

            k = bn_t( "14" );
            r = curve.make_point( "83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A", "76E49B6DE2F73234AE6A5EB9D612B75C9F2202BB6923F54FF8240AAA86F640B8", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "14" ), r )
            REQUIRE_EQUAL( curve.generate_point( "14"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "14" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "14"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "14" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "14"sv ).to_affine(), r )

            k = bn_t( "18EBBB95EED0E13" );
            r = curve.make_point( "339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F", "B1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "18EBBB95EED0E13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "18EBBB95EED0E13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "18EBBB95EED0E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "18EBBB95EED0E13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "18EBBB95EED0E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "18EBBB95EED0E13"sv ).to_affine(), r )

            k = bn_t( "159D893D4CDD747246CDCA43590E13" );
            r = curve.make_point( "1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264", "BFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "159D893D4CDD747246CDCA43590E13" ), r )
            REQUIRE_EQUAL( curve.generate_point( "159D893D4CDD747246CDCA43590E13"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "159D893D4CDD747246CDCA43590E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "159D893D4CDD747246CDCA43590E13"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "159D893D4CDD747246CDCA43590E13" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "159D893D4CDD747246CDCA43590E13"sv ).to_affine(), r )

            k = bn_t( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003" );
            r = curve.make_point( "9EACE8F4B071E677C5350B02F2BB2B384AAE89D58AA72CA97A170572E0FB222F", "1BBDAEC2430B09B93F7CB08678636CE12EAAFD58390699B5FD2F6E1188FC2A78", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003" ), r )
            REQUIRE_EQUAL( curve.generate_point( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "41FFC1FFFFFE01FFFC0003FFFE0007C001FFF00003FFF07FFE0007C000000003"sv ).to_affine(), r )

            k = bn_t( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF" );
            r = curve.make_point( "878F22CC6DB6048D2B767268F22FFAD8E56AB8E2DC615F7BD89F1E350500DD8D", "714A5D7BB901C9C5853400D12341A892EF45D87FC553786756C4F0C9391D763E", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFFC03FFFC003FFFFFC007FFF00000000070000100000000E00FFFFFFF3FF"sv ).to_affine(), r )

            k = bn_t( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF" );
            r = curve.make_point( "659A379625AB122F2512B8DADA02C6348D53B54452DFF67AC7ACE4E8856295CA", "49D81AB97B648464D0B4A288BD7818FAB41A16426E943527C4FED8736C53D0F6", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFF01FFFF8FFFFC00FFFFFFFFFC000000FFFFFC007FFFFFC000FFFE3FF"sv ).to_affine(), r )

            k = bn_t( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF" );
            r = curve.make_point( "CBCEAAA8A4DD44BBCE58E8DB7740A5510EC2CB7EA8DA8D8F036B3FB04CDA4DE4", "4BD7AA301A80D7F59FD983FEDBE59BB7B2863FE46494935E3745B360E32332FA", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF" ), r )
            REQUIRE_EQUAL( curve.generate_point( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "4000008000FFFFFC000003F00000FFFFFFFF800003800F8000E0000E000000FF"sv ).to_affine(), r )

            k = bn_t( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80" );
            r = curve.make_point( "F0C4A0576154FF3A33A3460D42EAED806E854DFA37125221D37935124BA462A4", "5B392FA964434D29EEC6C9DBC261CF116796864AA2FAADB984A2DF38D1AEF7A3", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80" ), r )
            REQUIRE_EQUAL( curve.generate_point( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "3FFFFFF0001F80000003F80003FFFFC0000000000FFE0000007FF818000F80"sv ).to_affine(), r )

            k = bn_t( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000" );
            r = curve.make_point( "5E6C8524B6369530B12C62D31EC53E0288173BD662BDF680B53A41ECBCAD00CC", "447FE742C2BFEF4D0DB14B5B83A2682309B5618E0064A94804E9282179FE089F", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000" ), r )
            REQUIRE_EQUAL( curve.generate_point( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1C000000000001001F803FFFFFF80000000000007FF0000000000000000"sv ).to_affine(), r )

            k = bn_t( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF" );
            r = curve.make_point( "3792E541BC209076A3D7920A915021ECD396A6EB5C3960024BE5575F3223484", "FC774AE092403101563B712F68170312304F20C80B40C06282063DB25F268DE4", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FC0007FFFFFFC0003FFFFFFFFFFFFFE00003FFFFF07FFFFFFFFFFFFC007FFFF"sv ).to_affine(), r )

            k = bn_t( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000" );
            r = curve.make_point( "2379FF85AB693CDF901D6CE6F2473F39C04A2FE3DCD842CE7AAB0E002095BCF8", "F8B476530A634589D5129E46F322B02FBC610A703D80875EE70D7CE1877436A1", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000" ), r )
            REQUIRE_EQUAL( curve.generate_point( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "7FFFFC03FF807FFFE0001FFFFF800FFF800001FFFF0001FFFFFE001FFFC00000"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF" );
            r = curve.make_point( "C1E4072C529BF2F44DA769EFC934472848003B3AF2C0F5AA8F8DDBD53E12ED7C", "39A6EE77812BB37E8079CD01ED649D3830FCA46F718C1D3993E4A591824ABCDB", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFE03FFFC07FFFC800070000FC0007FFC00000000000FFFE1FBFF81FF"sv ).to_affine(), r )

            k = bn_t( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC" );
            r = curve.make_point( "34DFBC09404C21E250A9B40FA8772897AC63A094877DB65862B61BD1507B34F3", "CF6F8A876C6F99CEAEC87148F18C7E1E0DA6E165FFC8ED82ABB65955215F77D3", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC" ), r )
            REQUIRE_EQUAL( curve.generate_point( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "1FFF81FC000000000FF801FFFC0F81F01FFF8001FC005FFFFFF800000FFFFFC"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D" );
            r = curve.make_point( "83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A", "891B64911D08CDCC5195A14629ED48A360DDFD4596DC0AB007DBF5557909BF47", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253D"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E" );
            r = curve.make_point( "CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83", "A7289EB3DB2610AFA3CA18EFF292931B5B698E92CF05C1FC1C6EAF8AD4313255", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253E"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F" );
            r = curve.make_point( "1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA", "90E9BA4EA341A246056482026911A58233EE4A4A10B0E08727C4CC6C395BA5D", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63253F"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540" );
            r = curve.make_point( "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E", "55FFA1184A46A8D89DCE7A9A889B717C7E4D7FBCD72A8CC0CD0878008E0E0323", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632540"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541" );
            r = curve.make_point( "76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E", "567A019DCBE0D9F2934F5E4A1EE178DF7A665FFCF0387455F162228DB473AEEF", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632541"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542" );
            r = curve.make_point( "F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F", "4A46C11BA6D1D2E1B19A6B1AE069BC19D5C4DE328A4A05C0B81A6321F2FCB0C9", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632542"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543" );
            r = curve.make_point( "54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B", "A660E43D60BCE8BBDEDE073FA5D183C8E8E15898CAF6FF7E45837D09F2F4C8A", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632543"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544" );
            r = curve.make_point( "177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01", "9C44A731B1415AA85DBF6E524BF0B18DD911EB3D5E04B20C63BC441D10384027", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632544"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545" );
            r = curve.make_point( "741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4", "F88F4B9463C7A024A98C7CAAB7784EAB71146ED4CA45A358E66A00DD32BB7E2C", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632545"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546" );
            r = curve.make_point( "3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1", "6F66DF64333B375EDB37BC505B0B3975F6F2FB26A16776251D07110317D5C8BF", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632546"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547" );
            r = curve.make_point( "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F", "78799D5CD655517091EDC32262C4B3EFA6F212D7018AE11135CB4455BB50F88C", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632547"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548" );
            r = curve.make_point( "EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0", "D5D8BB358D36031978FEB569B5715F37B28EB0165B217DC017A5DDB5B22FB705", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632548"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549" );
            r = curve.make_point( "62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393", "52A533416E1627DCB00EA288EE98311F5D12AE0A4418958725ABF595F0F66A81", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632549"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A" );
            r = curve.make_point( "8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3", "8C14E2411FCCE7CA92F9607C590A6FFFAC38C9CD34FBE4DE3AA1E5793E0BFF4B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254A"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B" );
            r = curve.make_point( "B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9", "17A3EF8ACDC8252B9013F1D20458FC86E3FF0890E381E9420283B7AC7038801D", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254B"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C" );
            r = curve.make_point( "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED", "1F3E82566FB58D83751E40C9407586D9F2FED1002B27F7772E2F44BB025E925B", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254C"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D" );
            r = curve.make_point( "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852", "1F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E" );
            r = curve.make_point( "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C", "78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F" );
            r = curve.make_point( "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", "F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F"sv ).to_affine(), r )

            k = bn_t( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550" );
            r = curve.make_point( "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A", /*verify=*/ true );
            REQUIRE_EQUAL( curve.generate_point( k ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550" ), r )
            REQUIRE_EQUAL( curve.generate_point( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550"sv ), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_proj_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550"sv ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( k ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550" ).to_affine(), r )
            REQUIRE_EQUAL( curve.generate_point<point_jacobi_type>( "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550"sv ).to_affine(), r )
        }
    EOSIO_TEST_END // ec_mul_secp256r1_test

    EOSIO_TEST_BEGIN(ec_keypair_secp256r1_test)
    {
        // Generated from: '/tv/ec/fips186-4/KeyPair.rsp'
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
        // CAVS 11.0
        // "Key Pair" information
        // Curves selected: P-192 P-224 P-256 P-384 P-521 K-163 K-233 K-283 K-409 K-571 B-163 B-233 B-283 B-409 B-571
        // Generated on Wed Mar 16 16:16:42 2011

        using secp256r1_t = std::remove_cv_t<decltype( ack::ec_curve::secp256r1)>;
        using bn_t = typename secp256r1_t::int_type;
        const auto& curve = ack::ec_curve::secp256r1;
        using point_proj_type = ack::ec_point_fp_proj<secp256r1_t>;
        using point_jacobi_type = ack::ec_point_fp_jacobi<secp256r1_t>;
        // [P-256]
        {
            auto k  = bn_t( "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357" );
            auto q  = curve.make_point( "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f", "9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f" );
            auto qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            auto qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            auto qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d" );
            q  = curve.make_point( "f6836a8add91cb182d8d258dda6680690eb724a66dc3bb60d2322565c39e4ab9", "1f837aa32864870cb8e8d0ac2ff31f824e7beddc4bb7ad72c173ad974b289dc2" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "78d5d8b7b3e2c16b3e37e7e63becd8ceff61e2ce618757f514620ada8a11f6e4" );
            q  = curve.make_point( "76711126cbb2af4f6a5fe5665dad4c88d27b6cb018879e03e54f779f203a854e", "a26df39960ab5248fd3620fd018398e788bd89a3cea509b352452b69811e6856" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "2a61a0703860585fe17420c244e1de5a6ac8c25146b208ef88ad51ae34c8cb8c" );
            q  = curve.make_point( "e1aa7196ceeac088aaddeeba037abb18f67e1b55c0a5c4e71ec70ad666fcddc8", "d7d35bdce6dedc5de98a7ecb27a9cd066a08f586a733b59f5a2cdb54f971d5c8" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "01b965b45ff386f28c121c077f1d7b2710acc6b0cb58d8662d549391dcf5a883" );
            q  = curve.make_point( "1f038c5422e88eec9e88b815e8f6b3e50852333fc423134348fc7d79ef8e8a10", "43a047cb20e94b4ffb361ef68952b004c0700b2962e0c0635a70269bc789b849" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "fac92c13d374c53a085376fe4101618e1e181b5a63816a84a0648f3bdc24e519" );
            q  = curve.make_point( "7258f2ab96fc84ef6ccb33e308cd392d8b568ea635730ceb4ebd72fa870583b9", "489807ca55bdc29ca5c8fe69b94f227b0345cccdbe89975e75d385cc2f6bb1e2" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "f257a192dde44227b3568008ff73bcf599a5c45b32ab523b5b21ca582fef5a0a" );
            q  = curve.make_point( "d2e01411817b5512b79bbbe14d606040a4c90deb09e827d25b9f2fc068997872", "503f138f8bab1df2c4507ff663a1fdf7f710e7adb8e7841eaa902703e314e793" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "add67e57c42a3d28708f0235eb86885a4ea68e0d8cfd76eb46134c596522abfd" );
            q  = curve.make_point( "55bed2d9c029b7f230bde934c7124ed52b1330856f13cbac65a746f9175f85d7", "32805e311d583b4e007c40668185e85323948e21912b6b0d2cda8557389ae7b0" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "4494860fd2c805c5c0d277e58f802cff6d731f76314eb1554142a637a9bc5538" );
            q  = curve.make_point( "5190277a0c14d8a3d289292f8a544ce6ea9183200e51aec08440e0c1a463a4e4", "ecd98514821bd5aaf3419ab79b71780569470e4fed3da3c1353b28fe137f36eb" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )

            k  = bn_t( "d40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b210" );
            q  = curve.make_point( "fbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d406c73", "2393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818efa535" );
            qg = curve.generate_point( k );
            REQUIRE_EQUAL( qg, q )

            qg_proj = curve.generate_point<point_proj_type>( k );
            REQUIRE_EQUAL( qg_proj.is_valid() , true )
            REQUIRE_EQUAL( qg_proj.to_affine(), q    )

            qg_jacobi = curve.generate_point<point_jacobi_type>( k );
            REQUIRE_EQUAL( qg_jacobi.is_valid() , true )
            REQUIRE_EQUAL( qg_jacobi.to_affine(), q    )
        }
    }
    EOSIO_TEST_END // ec_keypair_secp256r1_test

    EOSIO_TEST_BEGIN( ec_mul_add_fast_test )
        using namespace detail;
        for_each_curve_do( []<typename CurveT>(const CurveT& c) {
            for ( int32_t i = 1; i < 101; i++) {
                auto p  = c.g * i;
                auto p_proj = ec_point_fp_proj( p );
                auto p_jacobi = ec_point_fp_jacobi( p );

                auto q  = c.g * (101 - i );
                auto q_proj = ec_point_fp_proj( q );
                auto q_jacobi = ec_point_fp_jacobi( q );

                auto u1 = (i * ( c.n - 1 )) % c.n;
                auto u2 = (i * ( c.n - 2 )) % c.n;

                auto r      = p * u1 + q * u2;
                auto r_proj = p_proj * u1 + q_proj * u2;
                auto r_jacobi = p_jacobi * u1 + q_jacobi * u2;
                REQUIRE_EQUAL( r, r_proj.to_affine()   );
                REQUIRE_EQUAL( r, r_jacobi.to_affine() );
                REQUIRE_EQUAL( ec_mul_add_fast(u1, p, u2, q), r );
                REQUIRE_EQUAL( ec_mul_add_fast(u1, p_proj, u2, q_proj), r_proj );
                REQUIRE_EQUAL( ec_mul_add_fast(u1, p_jacobi, u2, q_jacobi), r_jacobi );
            }
        });
    EOSIO_TEST_END // ec_mul_add_fast_test

    EOSIO_TEST_BEGIN( ec_test )
        EOSIO_TEST( ec_general_test           )
        EOSIO_TEST( ec_pkv_secp256r1_test     )
        EOSIO_TEST( ec_double_test            )
        EOSIO_TEST( ec_add_test               )
        EOSIO_TEST( ec_sub_test               )
        EOSIO_TEST( ec_mul_test               )
        EOSIO_TEST( ec_mul_secp256k1_test     )
        EOSIO_TEST( ec_mul_secp256r1_test     )
        EOSIO_TEST( ec_keypair_secp256r1_test )
        EOSIO_TEST( ec_mul_add_fast_test      )
    EOSIO_TEST_END
}
