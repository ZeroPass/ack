// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/fp.hpp>
#include <eosio/tester.hpp>

namespace ack::tests {
    EOSIO_TEST_BEGIN( fp_function_test )
        using bn_t = fixed_bigint<768>;

        // fp_is_valid tests
        REQUIRE_EQUAL( fp_is_valid(  0, bn_t( 10 ) ), true  )
        REQUIRE_EQUAL( fp_is_valid(  1, bn_t( 10 ) ), true  )
        REQUIRE_EQUAL( fp_is_valid(  9, bn_t( 10 ) ), true  )
        REQUIRE_EQUAL( fp_is_valid( 10, bn_t( 10 ) ), false )
        REQUIRE_EQUAL( fp_is_valid( 11, bn_t( 10 ) ), false )
        REQUIRE_EQUAL( fp_is_valid( -1, bn_t( 10 ) ), false )

        REQUIRE_EQUAL( fp_is_valid( 0        , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , true  )
        REQUIRE_EQUAL( fp_is_valid( bn_t( 0 ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , true  )
        REQUIRE_EQUAL( fp_is_valid(  1       , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , true  )
        REQUIRE_EQUAL( fp_is_valid( bn_t( 1 ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , true  )
        REQUIRE_EQUAL( fp_is_valid( bn_t( "55AACCFF55BBEE99010203040509F0109" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , true  )
        REQUIRE_EQUAL( fp_is_valid( bn_t( "55AACCFF55BBEE99010203040509F010A" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , false )
        REQUIRE_EQUAL( fp_is_valid( bn_t( "55AACCFF55BBEE99010203040509F010B" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , false )
        REQUIRE_EQUAL( fp_is_valid(  -1       , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , false )
        REQUIRE_EQUAL( fp_is_valid( bn_t( -1 ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ) , false )

        // fp_neg tests
        REQUIRE_EQUAL( fp_neg(  0, bn_t( 10 ) ),  0 )
        REQUIRE_EQUAL( fp_neg(  1, bn_t( 10 ) ),  9 )
        REQUIRE_EQUAL( fp_neg(  9, bn_t( 10 ) ),  1 )
        REQUIRE_EQUAL( fp_neg( 10, bn_t( 10 ) ),  0 )

        // Test that invalid input produces invalid output
        REQUIRE_EQUAL( fp_neg( 11, bn_t( 10 ) ), -1 )
        REQUIRE_EQUAL( fp_neg( -1, bn_t( 10 ) ), 11 )
        REQUIRE_EQUAL( fp_neg( bn_t( -5 ), bn_t( 10 ) ), 15 )
        REQUIRE_EQUAL( fp_neg( bn_t( 6 ), bn_t( -11 ) ), -17 )
        REQUIRE_EQUAL( fp_neg(  7, bn_t( -12 ) ), -19 )
        REQUIRE_EQUAL( fp_neg( -bn_t( 8 ), bn_t( -13 ) ), -5 )
        REQUIRE_EQUAL( fp_neg( -14, bn_t( -12 ) ), 2 )

        REQUIRE_EQUAL( fp_neg( 0        , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), 0 )
        REQUIRE_EQUAL( fp_neg( bn_t( 0 ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), 0 )
        REQUIRE_EQUAL( fp_neg(  1       , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), bn_t( "55AACCFF55BBEE99010203040509F0109" ) )
        REQUIRE_EQUAL( fp_neg( bn_t( 1 ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), bn_t( "55AACCFF55BBEE99010203040509F0109" ) )
        REQUIRE_EQUAL( fp_neg( bn_t( "55AACCFF55BBEE99010203040509F0109" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ),  1 )
        REQUIRE_EQUAL( fp_neg( bn_t( "55AACCFF55BBEE99010203040509F010A" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ),  0 )
        REQUIRE_EQUAL( fp_neg( bn_t( "55AACCFF55BBEE99010203040509F010B" ), bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), -1 ) // Test that invalid input produces invalid output
        REQUIRE_EQUAL( fp_neg(  -1      , bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), bn_t( "55AACCFF55BBEE99010203040509F010B" ) ) // Test that invalid input produces invalid output

        // fp_normalize tests
        {
            bn_t a = 0;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a,  0 )

            a = 1;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 1 )

            a = 9;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 9 )

            a = 10;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 0 )

            a = 11;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 1 )

            a = -1;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 9 )

            a = -2;
            fp_normalize( a, bn_t( 10 ) );
            REQUIRE_EQUAL( a, 8 )

            a = bn_t( "55AACCFF55BBEE99010203040509F0109" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, "55AACCFF55BBEE99010203040509F0109" )

            a = bn_t( "55AACCFF55BBEE99010203040509F010A" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, 0 )

            a = bn_t( "55AACCFF55BBEE99010203040509F010B" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, 1 )

            a = bn_t( "55AACCFF55BBEE99010203040509F010A55AACCFF55BBEE99010203040509F010A" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, 0 )

            a = bn_t( "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277142944F4EE50D91FDC56553DB06B2F5039C8AB7" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, "44F88CCFBE77ED2C358C958A79E3FCD69" )

            a = -bn_t( "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277142944F4EE50D91FDC56553DB06B2F5039C8AB7" );
            fp_normalize( a, bn_t( "55AACCFF55BBEE99010203040509F010A" ) );
            REQUIRE_EQUAL( a, "10B2402F9744016CCB756D798B25F33A1" )
        }

        // fp_add tests
        {
            REQUIRE_EQUAL( fp_add( bn_t( 0 ),  0, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_add( bn_t( 0 ),  1, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_add( bn_t( 1 ),  0, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_add( bn_t( 1 ),  1, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_add( bn_t( 9 ),  1, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_add( bn_t( 9 ),  9, bn_t( 10 ) ), 8 )

            // Test that invalid input produces invalid output (a && b >= p)
            REQUIRE_EQUAL( fp_add( bn_t( 10 ), 10, bn_t( 10 ) ), 10 )
            REQUIRE_EQUAL( fp_add( bn_t( 10 ), 11, bn_t( 10 ) ), 11 )
            REQUIRE_EQUAL( fp_add( bn_t( 11 ), 11, bn_t( 10 ) ), 12 )
            REQUIRE_EQUAL( fp_add( bn_t( 11 ), 12, bn_t( 10 ) ), 13 )
            REQUIRE_EQUAL( fp_add( bn_t( 12 ), 12, bn_t( 10 ) ), 14 )
            REQUIRE_EQUAL( fp_add( bn_t( 12 ), 13, bn_t( 10 ) ), 15 )
            REQUIRE_EQUAL( fp_add( bn_t( 13 ), 13, bn_t( 10 ) ), 16 )
            REQUIRE_EQUAL( fp_add( bn_t( 13 ), 14, bn_t( 10 ) ), 17 )

            // Test that invalid input produces invalid output (a || b || p < 0)
            REQUIRE_EQUAL( fp_add( -bn_t( 10 ), 1, bn_t( 10 ) ), -9 )
            REQUIRE_EQUAL( fp_add( bn_t( 1 ), -10, bn_t( 10 ) ), -9 )
            REQUIRE_EQUAL( fp_add( bn_t( 2 ), bn_t( -10 ), bn_t( 10 ) ), -8 )
            REQUIRE_EQUAL( fp_add( bn_t( 3 ), bn_t( 10 ), -bn_t( 10 ) ), 23 )
            REQUIRE_EQUAL( fp_add( bn_t( 9 ), 8, -bn_t( 10 ) ), 27 )

            bn_t a = "55AACCFF55BBEE99010203040509F01";
            bn_t b = "55AACCFF55BBEE99010203040509F";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "560077CC5511AA879A030507090EFA0" )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F010";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "5B0579CF4B17AD8291122334455A8F11" )

            a = "55AACCFF55BBEE99010203040509F0109";
            b = 1;
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), 0 )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F010B";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55AACCFF55BBEE99010203040509F02" )

            a = -bn_t( "55AACCFF55BBEE99010203040509F01" ); // This is also invalid input
            b = "55AACCFF55BBEE99010203040509F010B";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55552232566632AA680101010104E620A" )

            // Test that invalid input produces invalid output (a || b >= p)
            a = "55AACCFF55BBEE99010203040509F010B";
            b = "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )

            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b = "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )

            a = "55AACCFF55BBEE99010203040509F010B";
            b = -bn_t( "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277" );
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )

            // Test that invalid input produces invalid output (a || b < 0)
            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b =  "55AACCFF55BBEE99010203040509F01";
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), -bn_t( "55552232566632AA680101010104E620A" ) )

            a =  "55AACCFF55BBEE99010203040509F01";
            b = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            REQUIRE_EQUAL( fp_add( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), -bn_t( "55552232566632AA680101010104E620A" ) )
        }

        // fp_sub tests
        {
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 0, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 0, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 1, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 1, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 1, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 2, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 0, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 2, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 2, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 2, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 3, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 3, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 1, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 3, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 0, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 3, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 3, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 4, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 4, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 2, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 4, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 1, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 4, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 0, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 4, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 4, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 5, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 5, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 3, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 5, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 2, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 5, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 1, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 5, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 0, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 5, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 5, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 6, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 6, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 4, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 6, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 3, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 6, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 2, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 6, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 1, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 0 ), 6, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 0, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 6, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 1, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1 ), 9, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 2, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 2 ), 9, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 3, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 3 ), 9, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 4, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 4 ), 9, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 5, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_sub( bn_t( 5 ), 9, bn_t( 10 ) ), 6 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 6, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_sub( bn_t( 6 ), 9, bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 7, bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_sub( bn_t( 7 ), 9, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 8, bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_sub( bn_t( 8 ), 9, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_sub( bn_t( 9 ), 9, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( -1 ), -1, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( -1 ), 2, bn_t( 10 ) ), 7 )

            // Test invalid inputs produce invalid results (a && b <= -10)
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 10, bn_t( 10 ) ), -10 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 11, bn_t( 10 ) ), -11 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 12, bn_t( 10 ) ), -12 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 13, bn_t( 10 ) ), -13 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 14, bn_t( 10 ) ), -14 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 15, bn_t( 10 ) ), -15 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 16, bn_t( 10 ) ), -16 )
            REQUIRE_EQUAL( fp_sub( bn_t( -10 ), 17, bn_t( 10 ) ), -17 )

            // Test invalid inputs produce invalid results (a && b >= 10)
            REQUIRE_EQUAL( fp_sub( bn_t( 100 ), 10, bn_t( 10 ) ), 90 )
            REQUIRE_EQUAL( fp_sub( bn_t( 100 ), 11, bn_t( 10 ) ), 89 )
            REQUIRE_EQUAL( fp_sub( bn_t( 100 ), 12, bn_t( 10 ) ), 88 )
            REQUIRE_EQUAL( fp_sub( bn_t( 1000 ), 989, bn_t( 10 ) ), 11 )
            REQUIRE_EQUAL( fp_sub( bn_t( 989 ), 100, bn_t( 10 ) ), 889 )

            // Test invalid inputs produce invalid results ( p < 0 )
            REQUIRE_EQUAL( fp_sub( bn_t( 12 ), 100, -bn_t( 10 ) ), -98 )
            REQUIRE_EQUAL( fp_sub( bn_t( 15 ), bn_t( 16 ), -bn_t( 10 ) ), -11 )

            // big number tests
            bn_t a = "55AACCFF55BBEE99010203040509F01";
            bn_t b = 0;
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55AACCFF55BBEE99010203040509F01" )

            a = 0;
            b = "55AACCFF55BBEE99010203040509F";
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55AA775488BC98DD126902020205EB06B" )

            a = "55AACCFF55BBEE99010203040509F0109";
            b = 1;
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55AACCFF55BBEE99010203040509F0108" )

            a = 1;
            b = "55AACCFF55BBEE99010203040509F0109";
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), 2 )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F";
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "55552232566632AA680101010104E62" )

            a = "55AACCFF55BBEE99010203040509F";
            b = "55AACCFF55BBEE99010203040509F01";
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "555577DD23658866569A02030408EB2A8" )

            // Test invalid inputs produce invalid results (a || b < 0)
            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b =  "55AACCFF55BBEE99010203040509F01";
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), -bn_t( "55AACCFF55BBEE99010203040509F02" ) )

            a =  "55AACCFF55BBEE99010203040509F01";
            b = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            REQUIRE_EQUAL( fp_sub( a, b, bn_t( "55AACCFF55BBEE99010203040509F010A" ) ), "560077CC5511AA879A030507090EFA00C" )
        }

        // fp_mul tests
        {
            REQUIRE_EQUAL( fp_mul( bn_t( 0 ), 0, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 0 ), 1, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 0 ), 2, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 1 ), 3, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 3 ), 1, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 2 ), 4, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 4 ), 2, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 3 ), 5, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 5 ), 3, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 4 ), 6, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_mul( bn_t( 6 ), 4, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_mul( bn_t( 5 ), 7, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 7 ), 5, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 6 ), 8, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 8 ), 6, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 7 ), 9, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 9 ), 7, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 8 ), 10, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 10 ), 8, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 9 ), 11, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_mul( bn_t( 11 ), 9, bn_t( 10 ) ), 9 )
            REQUIRE_EQUAL( fp_mul( bn_t( 10 ), 12, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 12 ), 10, bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_mul( bn_t( 11 ), 13, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 13 ), 11, bn_t( 10 ) ), 3 )
            REQUIRE_EQUAL( fp_mul( bn_t( 12 ), 14, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 14 ), 12, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 13 ), 15, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 15 ), 13, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 14 ), 16, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_mul( bn_t( 16 ), 14, bn_t( 10 ) ), 4 )
            REQUIRE_EQUAL( fp_mul( bn_t( 15 ), 17, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 17 ), 15, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 65535 ), 4294967295U, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 4294967295LL ), 65535U, bn_t( 10 ) ), 5 )
            REQUIRE_EQUAL( fp_mul( bn_t( 65536 ), 18446744073709551613ULL, bn_t( 10 ) ), 8 )
            REQUIRE_EQUAL( fp_mul( bn_t( 18446744073709551613ULL ), 65536, bn_t( 10 ) ), 8 )

            REQUIRE_EQUAL( fp_mul( -bn_t( 1 ), -bn_t( 1 ), bn_t( 10 ) ), bn_t( 1 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 1 ), -bn_t( 2 ), bn_t( 10 ) ), bn_t( 2 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 2 ), -bn_t( 1 ), bn_t( 10 ) ), bn_t( 2 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 2 ), -bn_t( 4 ), bn_t( 10 ) ), bn_t( 8 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 4 ), -bn_t( 2 ), bn_t( 10 ) ), bn_t( 8 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 3 ), -bn_t( 5 ), bn_t( 10 ) ), bn_t( 5 ) )
            REQUIRE_EQUAL( fp_mul( -bn_t( 5 ), -bn_t( 3 ), bn_t( 10 ) ), bn_t( 5 ) )

            // Test invalid inputs produce invalid results (a || b || p < 0)
            REQUIRE_EQUAL( fp_mul( -bn_t( 1 ),  1,  bn_t( 10 ) ), -1 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 1 ), -1,  bn_t( 10 ) ), -1 )
            REQUIRE_EQUAL( fp_mul( -bn_t( 1 ),  2,  bn_t( 10 ) ), -2 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 2 ), -1,  bn_t( 10 ) ), -2 )
            REQUIRE_EQUAL( fp_mul( -bn_t( 2 ),  3,  bn_t( 10 ) ), -6 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 3 ), -2,  bn_t( 10 ) ), -6 )
            REQUIRE_EQUAL( fp_mul( -bn_t( 3 ),  4,  bn_t( 10 ) ), -2 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 4 ), -3,  bn_t( 10 ) ), -2 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 4 ),  3, -bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_mul(  bn_t( 4 ),  bn_t(2), -bn_t( 10 ) ), 8 )

            // Big numbers
            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31" ), bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" )   , bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            REQUIRE_EQUAL( fp_mul( -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fp_mul( -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" )   , -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            // Test invalid inputs produce invalid results (a || b < 0)
            REQUIRE_EQUAL( fp_mul( -bn_t( "6A9E8EA23CB63C228F31" ), bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31" ), -bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fp_mul( -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fp_mul( -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fp_mul( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
        }

        // fp_div tests
        {
            REQUIRE_EQUAL( fp_div( bn_t( 0 ), bn_t( 1 ), bn_t( 10 ) ), 0 )
            REQUIRE_EQUAL( fp_div( bn_t( 1 ), bn_t( 1 ), bn_t( 10 ) ), 1 )
            REQUIRE_EQUAL( fp_div( bn_t( 2 ), bn_t( 1 ), bn_t( 10 ) ), 2 )
            REQUIRE_EQUAL( fp_div( bn_t( 1 ), bn_t( 3 ), bn_t( 10 ) ), 7 )
            REQUIRE_EQUAL( fp_div( bn_t( 1 ), bn_t( 4 ), bn_t( 11 ) ), 3 )
            REQUIRE_EQUAL( fp_div( bn_t( 2 ), bn_t( 5 ), bn_t( 11 ) ), 7 )
            REQUIRE_EQUAL( fp_div( bn_t( 3 ), bn_t( 6 ), bn_t( 11 ) ), 6 )
            REQUIRE_EQUAL( fp_div( bn_t( 6 ), bn_t( 3 ), bn_t( 11 ) ), 2 )
            REQUIRE_EQUAL( fp_div( bn_t( 7 ), bn_t( 2 ), bn_t( 11 ) ), 9 )
            REQUIRE_EQUAL( fp_div( bn_t( 3 ), bn_t( 4 ), bn_t( 11 ) ), 9 )
            REQUIRE_EQUAL( fp_div( bn_t( 4 ), bn_t( 3 ), bn_t( 11 ) ), 5 )
            REQUIRE_EQUAL( fp_div( bn_t( 10 ), bn_t( 10 ), bn_t( 11 ) ), 1 )
            REQUIRE_EQUAL( fp_div( bn_t( 11 ), bn_t( 10 ), bn_t( 11 ) ), 0 )
            REQUIRE_EQUAL( fp_div( bn_t( 12 ), bn_t( 10 ), bn_t( 11 ) ), 10 )
            REQUIRE_EQUAL( fp_div( bn_t( 13 ), bn_t( 25 ), bn_t( 11 ) ), 8 )
            REQUIRE_EQUAL( fp_div( bn_t( 65535 ), bn_t( 4294967295U ), bn_t( 11 ) ), 10 )
            REQUIRE_EQUAL( fp_div( bn_t( 4294967295LL ), bn_t( 65535U ), bn_t( 11 ) ), 10 )
            REQUIRE_EQUAL( fp_div( bn_t( 65536 ), bn_t( 18446744073709551613ULL ), bn_t( 11 ) ), 10 )
            REQUIRE_EQUAL( fp_div( bn_t( 18446744073709551613ULL ), bn_t( 65536 ), bn_t( 11 ) ), 10 )

            // Test invalid inputs produce invalid outputs ( a || b || p < 0 )
            REQUIRE_ASSERT( "modular inverse failed", []() {
                auto cr = fp_div( bn_t( 3 ), -bn_t( 4 ), bn_t( 11 ) );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                auto cr = fp_div( -bn_t( 3 ), -bn_t( 4 ), bn_t( 11 ) );
            })

            REQUIRE_EQUAL( fp_div( -bn_t( 3 ), bn_t( 4 ), bn_t( 11 ) ), -9 )
            REQUIRE_EQUAL( fp_div( -bn_t( 5 ), bn_t( 8 ), bn_t( 11 ) ), -2 )
            REQUIRE_EQUAL( fp_div(  bn_t( 3 ), bn_t( 4 ), -bn_t( 11 ) ), 9 )

            // Big numbers
            REQUIRE_EQUAL( fp_div( bn_t( "6A9E8EA23CB63C228F31" ), bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "4723E220CEE84E2E184B06CB7A758F5DE656B905D") )
            REQUIRE_EQUAL( fp_div( bn_t( "6AA11DCB29F14BACCFF1" ), bn_t( "6A9E8EA23CB63C228F31" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "28B8556A73C2E4308BC9424A62336E808D232C86A") )

            REQUIRE_EQUAL( fp_div( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "903E159F5BB2E288A8216871A5156CC638754C26") )
            REQUIRE_EQUAL( fp_div( bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" )   , bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "46833B41C273C6118249EA12465D0A008396E3AFA") )

            REQUIRE_EQUAL( fp_div( bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "2F368DC795A098F09B8A3E473A3EF7805FA993BD5") )
            REQUIRE_EQUAL( fp_div( bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" ), bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11" ) ), bn_t( "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C") )
        }
    EOSIO_TEST_END // fp_function_test

    EOSIO_TEST_BEGIN( fp_element_test )
        using bn_t = fixed_bigint<768>;
        struct curve_tag {};
        using fpe_t = fp_element< bn_t, curve_tag >;

        // General tests
        {
            REQUIRE_EQUAL( fpe_t::zero().is_zero()    , true  )
            REQUIRE_EQUAL( fpe_t::zero().is_one()     , false )
            REQUIRE_EQUAL( fpe_t::zero().is_valid()   , false )
            REQUIRE_EQUAL( fpe_t::zero().value()      , 0     )
            REQUIRE_EQUAL( fpe_t::zero()              , 0     ) // operator bigint
            REQUIRE_EQUAL( fpe_t::zero().is_negative(), false )

            bn_t modulus = 0;
            REQUIRE_EQUAL( fpe_t( modulus ).is_zero()    , true  )
            REQUIRE_EQUAL( fpe_t( modulus ).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( modulus ).is_valid()   , false )
            REQUIRE_EQUAL( fpe_t( modulus ).value()      , 0     )
            REQUIRE_EQUAL( fpe_t( modulus )              , 0     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( modulus ).is_negative(), false )

            modulus = 1;
            REQUIRE_EQUAL( fpe_t( modulus ).is_zero()    , true  )
            REQUIRE_EQUAL( fpe_t( modulus ).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( modulus ).is_valid()   , true  )
            REQUIRE_EQUAL( fpe_t( modulus ).value()      , 0     )
            REQUIRE_EQUAL( fpe_t( modulus )              , 0     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( modulus ).is_negative(), false )

            modulus = 5;
            REQUIRE_EQUAL( fpe_t( modulus ).is_zero()    , true  )
            REQUIRE_EQUAL( fpe_t( modulus ).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( modulus ).is_valid()   , true  )
            REQUIRE_EQUAL( fpe_t( modulus ).value()      , 0     )
            REQUIRE_EQUAL( fpe_t( modulus )              , 0     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( modulus ).is_negative(), false )

            REQUIRE_EQUAL( fpe_t( 0, modulus ).is_zero()    , true  )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).value()      , 0     )
            REQUIRE_EQUAL( fpe_t( 0, modulus )              , 0     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 0, modulus ).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 0, modulus, /*check*/true ).is_valid(), true  )

            REQUIRE_EQUAL( fpe_t::one().is_zero()    , false )
            REQUIRE_EQUAL( fpe_t::one().is_one()     , true  )
            REQUIRE_EQUAL( fpe_t::one().is_valid()   , false )
            REQUIRE_EQUAL( fpe_t::one().value()      , 1     )
            REQUIRE_EQUAL( fpe_t::one()              , 1     ) // operator bigint
            REQUIRE_EQUAL( fpe_t::one().is_negative(), false )

            modulus = 6;
            REQUIRE_EQUAL( fpe_t( 1, modulus).is_zero()    , false )
            REQUIRE_EQUAL( fpe_t( 1, modulus).is_one()     , true  )
            REQUIRE_EQUAL( fpe_t( 1, modulus).value()      , 1     )
            REQUIRE_EQUAL( fpe_t( 1, modulus)              , 1     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 1, modulus).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 1, modulus, /*check*/true).is_valid(), true )

            modulus = 6;
            REQUIRE_EQUAL( fpe_t( 2, modulus).is_zero()    , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus).value()      , 2     )
            REQUIRE_EQUAL( fpe_t( 2, modulus)              , 2     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 2, modulus).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 2, modulus, /*check*/true).is_valid(), true )

            modulus = 6;
            REQUIRE_EQUAL( fpe_t( 3, modulus).is_zero()    , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus).value()      , 3     )
            REQUIRE_EQUAL( fpe_t( 3, modulus)              , 3     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 3, modulus).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 3, modulus, /*check*/true).is_valid(), true )

            modulus = 6;
            REQUIRE_EQUAL( fpe_t( 4, modulus).is_zero()    , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus).value()      , 4     )
            REQUIRE_EQUAL( fpe_t( 4, modulus)              , 4     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 4, modulus).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 4, modulus, /*check*/true).is_valid(), true )

            modulus = 6;
            REQUIRE_EQUAL( fpe_t( 5, modulus).is_zero()    , false )
            REQUIRE_EQUAL( fpe_t( 5, modulus).is_one()     , false )
            REQUIRE_EQUAL( fpe_t( 5, modulus).value()      , 5     )
            REQUIRE_EQUAL( fpe_t( 5, modulus)              , 5     ) // operator bigint
            REQUIRE_EQUAL( fpe_t( 5, modulus).is_negative(), false )
            REQUIRE_EQUAL( fpe_t( 5, modulus, /*check*/true).is_valid(), true )

            // Assigning negative value should passed when not checked
            modulus = 6;
            auto fe = fpe_t( -3, modulus, /*check*/false );
            REQUIRE_EQUAL( fe.is_zero()    , false )
            REQUIRE_EQUAL( fe.is_one()     , false )
            REQUIRE_EQUAL( fe.value()      , -3    )
            REQUIRE_EQUAL( fe              , -3    ) // operator bigint
            REQUIRE_EQUAL( fe.is_negative(), true  )
            REQUIRE_EQUAL( fe.is_valid()   , false )

            fe.assign( 3, /*check*/true );
            REQUIRE_EQUAL( fe.is_zero()    , false )
            REQUIRE_EQUAL( fe.is_one()     , false )
            REQUIRE_EQUAL( fe.value()      , 3     )
            REQUIRE_EQUAL( fe              , 3     ) // operator bigint
            REQUIRE_EQUAL( fe.is_negative(), false )
            REQUIRE_EQUAL( fe.is_valid()   , true  )

            fe.assign( -4, /*check*/false );
            REQUIRE_EQUAL( fe.is_zero()    , false )
            REQUIRE_EQUAL( fe.is_one()     , false )
            REQUIRE_EQUAL( fe.value()      , -4    )
            REQUIRE_EQUAL( fe              , -4    ) // operator bigint
            REQUIRE_EQUAL( fe.is_negative(), true  )
            REQUIRE_EQUAL( fe.is_valid()   , false )

            fe = 5;
            REQUIRE_EQUAL( fe.is_zero()    , false )
            REQUIRE_EQUAL( fe.is_one()     , false )
            REQUIRE_EQUAL( fe.value()      , 5     )
            REQUIRE_EQUAL( fe              , 5     ) // operator bigint
            REQUIRE_EQUAL( fe.is_negative(), false )
            REQUIRE_EQUAL( fe.is_valid()   , true  )

            fe = -1;
            REQUIRE_EQUAL( fe.is_zero()    , false )
            REQUIRE_EQUAL( fe.is_one()     , false )
            REQUIRE_EQUAL( fe.value()      , -1    )
            REQUIRE_EQUAL( fe              , -1    ) // operator bigint
            REQUIRE_EQUAL( fe.is_negative(), true  )
            REQUIRE_EQUAL( fe.is_valid()   , false )

            // Test fail cases
            REQUIRE_ASSERT( "modulus is null", []() {
                fpe_t::zero().modulus();
            })

            REQUIRE_ASSERT( "modulus is null", []() {
                fpe_t::one().modulus();
            })

            REQUIRE_ASSERT( "invalid value for given modulus", []() {
                bn_t modulus = 6;
                fpe_t( 6, modulus, /*check*/true );
            })

            REQUIRE_ASSERT( "invalid value for given modulus", []() {
                bn_t modulus = 6;
                fpe_t( 7, modulus, /*check*/true );
            })

            REQUIRE_ASSERT( "invalid value for given modulus", []() {
                bn_t modulus = 6;
                fpe_t( -1, modulus, /*check*/true );
            })

            REQUIRE_ASSERT( "invalid value", []() {
                bn_t modulus = 6;
                auto fe = fpe_t( 3, modulus, /*check*/true);
                fe.assign( -1, /*check*/true );
            })

            REQUIRE_ASSERT( "invalid value", []() {
                bn_t modulus = 6;
                auto fe = fpe_t( 3, modulus, /*check*/true);
                fe.assign( 7, /*check*/true );
            })
        }

        // Comparison tests
        {
            bn_t modulus = 10;
            bn_t modulus2 = 11;

            // EQ tests
            REQUIRE_EQUAL( fpe_t( -1, modulus ) == fpe_t( -1, modulus ) , true  )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) == fpe_t( -1, modulus2 ), true  )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) == bn_t( -1 )           , true  )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) == -1                   , true  )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( -1, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( -1, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == bn_t( -1 )           , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == -1                   , false )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 0, modulus ) , true  )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 0, modulus2 ), true  )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == bn_t( 0 )           , true  )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == 0                   , true  )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 1, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 1, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == bn_t( 1 )           , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == 1                   , false )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 2, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == fpe_t( 2, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == bn_t( 2 )           , false )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) == 2                   , false )

            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 0, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 0, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == bn_t( 0 )           , false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == 0                   , false )

            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 1, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 1, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == bn_t( 1 )           , true )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == 1                   , true )

            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 2, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == fpe_t( 2, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == bn_t( 2 )           , false )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) == 2                   , false )

            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 0, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 0, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == bn_t( 0 )           , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == 0                   , false )

            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 1, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 1, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == bn_t( 1 )           , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == 1                   , false )

            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 2, modulus ) , true  )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 2, modulus2 ), true  )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == bn_t( 2 )           , true  )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == 2                   , true  )

            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 3, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == fpe_t( 3, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == bn_t( 3 )           , false )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) == 3                   , false )

            // NE tests
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != fpe_t( -1, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != fpe_t( -1, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != bn_t( -1 )           , false )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != -1                   , false )

            REQUIRE_EQUAL( fpe_t( -1, modulus ) != fpe_t( 0, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != fpe_t( 0, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != bn_t( 0 )           , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) != 0                   , true )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 2, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 2, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != bn_t( 2 )           , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != 2                   , true )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 3, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 3, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != bn_t( 3 )           , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != 3                   , false )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != 4                   , true )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 9, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != fpe_t( 9, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != bn_t( 9 )           , true )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) != 9                   , true )

            // LT tests
            REQUIRE_EQUAL( fpe_t( -1, modulus ) < fpe_t( 0, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) < fpe_t( 0, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) < bn_t( 0 )           , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) < 0                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 5, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 5, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < bn_t( 5 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < 5                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 4, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 4, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < bn_t( 4 )           , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < 4                   , false )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 3, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 3, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < bn_t( 3 )           , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < 3                   , false )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 9, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < fpe_t( 9, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < bn_t( 9 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) < 9                   , true )

            // LE tests
            REQUIRE_EQUAL( fpe_t( -1, modulus ) <= fpe_t( 0, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) <= fpe_t( 0, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) <= bn_t( 0 )           , true )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) <= 0                   , true )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) <= fpe_t( 0, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) <= fpe_t( 0, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) <= bn_t( 0 )           , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) <= 0                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 5, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 5, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= bn_t( 5 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= 5                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= 4                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 3, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 3, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= bn_t( 3 )           , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= 3                   , false )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 9, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= fpe_t( 9, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= bn_t( 9 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) <= 9                   , true )

            // GT tests
            REQUIRE_EQUAL( fpe_t( 0, modulus ) > fpe_t( -1, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) > fpe_t( -1, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) > bn_t( -1 )           , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) > -1                   , true )

            REQUIRE_EQUAL( fpe_t( 5, modulus ) > fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) > fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) > bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) > 4                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) > fpe_t( 4, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) > fpe_t( 4, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) > bn_t( 4 )           , false )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) > 4                   , false )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) > fpe_t( 4, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) > fpe_t( 4, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) > bn_t( 4 )           , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) > 4                   , false )

            REQUIRE_EQUAL( fpe_t( 9, modulus ) > fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) > fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) > bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) > 4                   , true )

            // GE tests
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= fpe_t( -1, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= fpe_t( -1, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= bn_t( -1 )           , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= -1                   , true )

            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= fpe_t( 0, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= fpe_t( 0, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= bn_t( 0 )           , true )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) >= 0                   , true )

            REQUIRE_EQUAL( fpe_t( 5, modulus ) >= fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) >= fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) >= bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) >= 4                   , true )

            REQUIRE_EQUAL( fpe_t( 4, modulus ) >= fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) >= fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) >= bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) >= 4                   , true )

            REQUIRE_EQUAL( fpe_t( 3, modulus ) >= fpe_t( 4, modulus ) , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) >= fpe_t( 4, modulus2 ), false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) >= bn_t( 4 )           , false )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) >= 4                   , false )

            REQUIRE_EQUAL( fpe_t( 9, modulus ) >= fpe_t( 4, modulus ) , true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) >= fpe_t( 4, modulus2 ), true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) >= bn_t( 4 )           , true )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) >= 4                   , true )
        }

        /* Arithmetic tests */

        // Test inversion
        {
            bn_t modulus = 1;
            REQUIRE_EQUAL( fpe_t( 0, modulus ).inv(),  0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).inv(),  0 )

            modulus = 17;
            REQUIRE_EQUAL( fpe_t( 1, modulus ).inv(), 1 )

            modulus = 11;
            REQUIRE_EQUAL( fpe_t( 1, modulus ).inv(), 1 )

            modulus = 10000000001LL;
            REQUIRE_EQUAL( fpe_t( 1, modulus ).inv(),  1 )

            // Test vectors generated with python
            modulus = "1234567890ABCDEF7890ABCDF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "1234567890ABCDEF7890ABCDE" )

            modulus = "1234567890ABCDEF7890ABCEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "E06746CD311CF77BF80647D9" )

            modulus = "1234567890ABCDEF7890ACDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "5A8DDC811FD157C6C6988D1" )

            modulus = "1234567890ABCDEF7890BCDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "A3A488FC79674663C321C5B4" )

            modulus = "1234567890ABCDEF7890DCDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "91523409246FB409CDA6E5FE" )

            modulus = "1234567890ABCDEF7890ECDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "549E5E3252D1C50553BDDC23" )

            modulus = "1234567890ABCDEF7891FCDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "10452825C5CECAF60F54E8CC2" )

            modulus = "1234567890ABCDEF7892FCDEF";
            REQUIRE_EQUAL( fpe_t( "1234567890ABCDEF7890ABCDEF", modulus ).inv(),  "891267A816DE4F23C7799B2D" )

            modulus = "1F01A01B01C01E01D01010101010101001";
            REQUIRE_EQUAL( fpe_t( "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", modulus ).inv(),  "1545D9535378BE5B27D1096E3F179B336" )

            modulus = "E8CCF2A301AB5C4470D1745D5A5A5D127F9A4BB3C4E31F45F37DCE98606233C5";
            REQUIRE_EQUAL( fpe_t( "AE7FD295C6DF1F6F882D9A0D65D621A58AA1E0A44C0EE24A504F1C192A8E07E0", modulus ).inv(),
                           "24AC2DD72DA1EB9A32E0AEDE37A3E4504AE6C5D56D54D87951F8778BE5C403C2" )

            modulus = "C9CE7DBA10B68EF84A96DE3B2663D7C8A61E9032FBD4F9C4E383FFC0B1EF2FB5C5FE5C5AC8E5F5D5B0C12968FDFD7F1";
            REQUIRE_EQUAL( fpe_t("11D531E8249C1F7CFF52082098B84BCD4413B3B3A3F54FE8F2F1B9B46B1EE9822EDDF8E47555AF05C32A6C051CD42A57", modulus ).inv(),
                           "9C747D073689632FE68DBE0D02DA963AED83A9C23EE3391945EE5DCA2801B95469B037165468584965990F65ECC2499" )

            modulus = "BA9F9B61D6112C732F0E95EB00D266C82EE29D6706E5B6BFC57D49C02FBDE5B16111F616D62E051EF7B43C2190638E29FCD98447FCBA75B9A1F3168F0BB08D85";
            REQUIRE_EQUAL( fpe_t("4D08382065A3FAF00EB65E7F1290A21C43CA3B3F0C301AC9D0D85B8222F2C427D19CAB657B46204AFD6A5F6F082A6F9A6A5F5E78B262A282ECD7A634872D0BDA", modulus ).inv(),
                           "379C326CA0547AB26812734CA8C73532E1F20CE77EDED7B74475832D3DB8E84D8996CA0D24C0D9C7DF8CF9340634E8823C01C5CAF32627F8E9CCB6747BD48299" )

            // Test failures
            REQUIRE_ASSERT( "division by zero", [&]() {
                modulus = 0;
                auto fe = fpe_t( 0, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 2;
                auto fe = fpe_t( 0, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 3;
                auto fe = fpe_t( 0, modulus ).inv();
            })

            // Bell's prime
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = "359334085968622831041960188598043661065388726959079837";
                auto fe = fpe_t( 0, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 2, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 4, modulus ).inv();
            })

            REQUIRE_ASSERT( "division by zero", [&]() {
                modulus = 0;
                auto fe = fpe_t( 5, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 5, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 6, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 10, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 12, modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 10;
                auto fe = fpe_t( 20, modulus ).inv();
            })

            // Mersenne prime 2^107-1
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = 654;
                auto fe = fpe_t( "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", modulus ).inv();
            })

            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                modulus = "1F01A01B01C01E01D010101010101010";
                auto fe = fpe_t( "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", modulus ).inv();
            })
        }

        // Addition test
        {
            bn_t modulus = 10;
            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( fpe_t( 0, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( bn_t( 0 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( 0 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + fpe_t( 0, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + bn_t( 0 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + 0                       , 0 )

            auto fe = fpe_t( 0, modulus );
            fe += fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe += bn_t( modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe += 0;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( fpe_t( 1, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( bn_t( 1 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).add( 1 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + fpe_t( 1, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + bn_t( 1 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) + 1                       , 1 )

            fe  = fpe_t( 0, modulus );
            fe += fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 0, modulus );
            fe += bn_t( 1 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 0, modulus );
            fe += 1;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( fpe_t( 0, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( bn_t( 0 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( 0 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + fpe_t( 0, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + bn_t( 0 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + 0                       , 1 )

            fe  = fpe_t( 1, modulus );
            fe += fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 1, modulus );
            fe += bn_t( 0 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 1, modulus );
            fe += 0;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( fpe_t( 1, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( bn_t( 1 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( 1 )                  , 2 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + fpe_t( 1, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + bn_t( 1 )               , 2 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + 1                       , 2 )

            fe  = fpe_t( 1, modulus );
            fe += fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 1, modulus );
            fe += bn_t( 1 );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 1, modulus );
            fe += 1;
            REQUIRE_EQUAL( fe, 2 )

            REQUIRE_EQUAL( fpe_t( 9, modulus ).add( fpe_t( 1, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).add( bn_t( 1 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).add( 1 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) + fpe_t( 1, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) + bn_t( 1 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) + 1                       , 0 )

            fe  = fpe_t( 9, modulus );
            fe += fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 9, modulus );
            fe += bn_t( 1 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 9, modulus );
            fe += 1;
            REQUIRE_EQUAL( fe, 0 )

            // Test fe2 having different modulus does not affect result
            bn_t modulus2 = 3;
            REQUIRE_EQUAL( fpe_t( 3, modulus ).add( fpe_t( 2, modulus2 ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) + fpe_t( 2, modulus2 )     , 5 )

            fe  = fpe_t( 3, modulus );
            fe += fpe_t( 2, modulus2 );
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 9, modulus ).add( fpe_t( 2, modulus2 ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) + fpe_t( 2, modulus2 )     , 1 )

            fe  = fpe_t( 9, modulus );
            fe += fpe_t( 2, modulus2 );
            REQUIRE_EQUAL( fe, 1 )

            // Test that invalid input produces invalid output (a && b >= p)
            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( fpe_t( 10, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( bn_t( 10 ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( 10 )                  , 10 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + fpe_t( 10, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + bn_t( 10 )               , 10 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + 10                       , 10 )

            fe  = fpe_t( 10, modulus );
            fe += fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 10, modulus );
            fe += bn_t( 10 );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 10, modulus );
            fe += 10;
            REQUIRE_EQUAL( fe, 10 )

            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( fpe_t( 11, modulus ) ), 11 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( bn_t( 11 ) )          , 11 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).add( 11 )                  , 11 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + fpe_t( 11, modulus )     , 11 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + bn_t( 11 )               , 11 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) + 11                       , 11 )

            fe  = fpe_t( 10, modulus );
            fe += fpe_t( 11, modulus );
            REQUIRE_EQUAL( fe, 11 )

            fe  = fpe_t( 10, modulus );
            fe += bn_t( 11 );
            REQUIRE_EQUAL( fe, 11 )

            fe  = fpe_t( 10, modulus );
            fe += 11;
            REQUIRE_EQUAL( fe, 11 )

            REQUIRE_EQUAL( fpe_t( 12, modulus ).add( fpe_t( 19, modulus ) ), 21 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).add( bn_t( 19 ) )          , 21 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).add( 19 )                  , 21 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) + fpe_t( 19, modulus )     , 21 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) + bn_t( 19 )               , 21 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) + 19                       , 21 )

            fe  = fpe_t( 12, modulus );
            fe += fpe_t( 19, modulus );
            REQUIRE_EQUAL( fe, 21 )

            fe  = fpe_t( 12, modulus );
            fe += bn_t( 19 );
            REQUIRE_EQUAL( fe, 21 )

            fe  = fpe_t( 12, modulus );
            fe += 19;
            REQUIRE_EQUAL( fe, 21 )

            // Test that invalid input produces invalid output (a || b || p < 0)
            REQUIRE_EQUAL( fpe_t( -10, modulus ).add( fpe_t( 1, modulus ) ), -9 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).add( bn_t( 1 ) )          , -9 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).add( 1 )                  , -9 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) + fpe_t( 1, modulus )     , -9 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) + bn_t( 1 )               , -9 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) + 1                       , -9 )

            fe  = fpe_t( -10, modulus );
            fe += fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, -9 )

            fe  = fpe_t( -10, modulus );
            fe += bn_t( 1 );
            REQUIRE_EQUAL( fe, -9 )

            fe  = fpe_t( -10, modulus );
            fe += 1;
            REQUIRE_EQUAL( fe, -9 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( fpe_t( -10, modulus ) ), -9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( bn_t( -10 ) )          , -9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).add( -10 )                  , -9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + fpe_t( -10, modulus )     , -9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + bn_t( -10 )               , -9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) + -10                       , -9 )

            fe  = fpe_t( 1, modulus );
            fe += fpe_t( -10, modulus );
            REQUIRE_EQUAL( fe, -9 )

            fe  = fpe_t( 1, modulus );
            fe += bn_t( -10 );
            REQUIRE_EQUAL( fe, -9 )

            fe  = fpe_t( 1, modulus );
            fe += -10;
            REQUIRE_EQUAL( fe, -9 )

            modulus = -10;
            REQUIRE_EQUAL( fpe_t( 3, modulus ).add( fpe_t( 10, modulus ) ), 23 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).add( bn_t( 10 ) )          , 23 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).add( 10 )                  , 23 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) + fpe_t( 10, modulus )     , 23 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) + bn_t( 10 )               , 23 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) + 10                       , 23 )

            fe  = fpe_t( 3, modulus );
            fe += fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 23 )

            fe  = fpe_t( 3, modulus );
            fe += bn_t( 10 );
            REQUIRE_EQUAL( fe, 23 )

            fe  = fpe_t( 3, modulus );
            fe += 10;
            REQUIRE_EQUAL( fe, 23 )

            // Big numbers
            bn_t a = "55AACCFF55BBEE99010203040509F01";
            bn_t b = "55AACCFF55BBEE99010203040509F";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "560077CC5511AA879A030507090EFA0" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "560077CC5511AA879A030507090EFA0" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "560077CC5511AA879A030507090EFA0" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "560077CC5511AA879A030507090EFA0" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "560077CC5511AA879A030507090EFA0" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "560077CC5511AA879A030507090EFA0" )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F010";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "5B0579CF4B17AD8291122334455A8F11" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "5B0579CF4B17AD8291122334455A8F11" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "5B0579CF4B17AD8291122334455A8F11" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "5B0579CF4B17AD8291122334455A8F11" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "5B0579CF4B17AD8291122334455A8F11" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "5B0579CF4B17AD8291122334455A8F11" )

            a = "55AACCFF55BBEE99010203040509F0109";
            b = 1;
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , 0 )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , 0 )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, 0 )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F010B";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "55AACCFF55BBEE99010203040509F02" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "55AACCFF55BBEE99010203040509F02" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "55AACCFF55BBEE99010203040509F02" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "55AACCFF55BBEE99010203040509F02" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F02" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F02" )

            a = -bn_t( "55AACCFF55BBEE99010203040509F01" ); // This is also invalid input
            b = "55AACCFF55BBEE99010203040509F010B";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "55552232566632AA680101010104E620A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "55552232566632AA680101010104E620A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "55552232566632AA680101010104E620A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "55552232566632AA680101010104E620A" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55552232566632AA680101010104E620A" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "55552232566632AA680101010104E620A" )

            // Test that invalid input produces invalid output (a || b >= p)
            a = "55AACCFF55BBEE99010203040509F010B";
            b = "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69278" )

            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b = "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, "7541384852E10FF10D5FB6A675E4B06D6A54EB3B89BD0082B63B89062" )

            a = "55AACCFF55BBEE99010203040509F010B";
            b = -bn_t( "7541384852E10FF10D5FB6A7213A4A6C15CCC86D8BC1068AC04F69277" );
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ), -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  , -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     , -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       , -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, -bn_t( "7541384852E10FF10D5FB6A6CB8F7D6CC010D9D48ABF0386BB457916C" ) )

            // Test that invalid input produces invalid output (a || b < 0)
            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b =  "55AACCFF55BBEE99010203040509F01";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ),  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  ,  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     ,  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       ,  -bn_t( "55552232566632AA680101010104E620A" ) )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "55552232566632AA680101010104E620A" ) )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, -bn_t( "55552232566632AA680101010104E620A" ) )

            a =  "55AACCFF55BBEE99010203040509F01";
            b = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( fpe_t( b, modulus ) ),  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ).add( b )                  ,  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + fpe_t( b, modulus )     ,  -bn_t( "55552232566632AA680101010104E620A" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) + b                       ,  -bn_t( "55552232566632AA680101010104E620A" ) )

            fe  = fpe_t( a, modulus );
            fe += fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "55552232566632AA680101010104E620A" ) )

            fe  = fpe_t( a, modulus );
            fe += b;
            REQUIRE_EQUAL( fe, -bn_t( "55552232566632AA680101010104E620A" ) )
        }

        // Subtraction tests
        {
            bn_t modulus = 10;
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( fpe_t( 0, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( bn_t( 0 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( 0 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - fpe_t( 0, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - bn_t( 0 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - 0                       , 0 )

            auto fe = fpe_t( 0, modulus );
            fe -= fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe -= bn_t( modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe -= 0;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( fpe_t( 0, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( bn_t( 0 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( 0 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - fpe_t( 0, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - bn_t( 0 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - 0                       , 1 )

            fe  = fpe_t( 1, modulus );
            fe -= fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 1, modulus );
            fe -= bn_t( 0 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 1, modulus );
            fe -= 0;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( fpe_t( 1, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( bn_t( 1 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( 1 )                  , 9 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - fpe_t( 1, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - bn_t( 1 )               , 9 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - 1                       , 9 )

            fe  = fpe_t( 0, modulus );
            fe -= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 0, modulus );
            fe -= bn_t( 1 );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 0, modulus );
            fe -= 1;
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( fpe_t( 1, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( bn_t( 1 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( 1 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - fpe_t( 1, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - bn_t( 1 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - 1                       , 0 )

            fe  = fpe_t( 1, modulus );
            fe -= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 1, modulus );
            fe -= bn_t( 1 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 1, modulus );
            fe -= 1;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( fpe_t( 1, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( bn_t( 1 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( 1 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - fpe_t( 1, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - bn_t( 1 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - 1                       , 1 )

            fe  = fpe_t( 2, modulus );
            fe -= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 2, modulus );
            fe -= bn_t( 1 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 2, modulus );
            fe -= 1;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( fpe_t( 2, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( bn_t( 2 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).sub( 2 )                  , 9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - fpe_t( 2, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - bn_t( 2 )               , 9 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) - 2                       , 9 )

            fe  = fpe_t( 1, modulus );
            fe -= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 1, modulus );
            fe -= bn_t( 2 );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 1, modulus );
            fe -= 2;
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( fpe_t( 0, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( bn_t( 0 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( 0 )                  , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - fpe_t( 0, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - bn_t( 0 )               , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - 0                       , 2 )

            fe  = fpe_t( 2, modulus );
            fe -= fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 2, modulus );
            fe -= bn_t( 0 );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 2, modulus );
            fe -= 0;
            REQUIRE_EQUAL( fe, 2 )

            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( fpe_t( 2, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( bn_t( 2 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).sub( 2 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - fpe_t( 2, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - bn_t( 2 )               , 8 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) - 2                       , 8 )

            fe  = fpe_t( 0, modulus );
            fe -= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 0, modulus );
            fe -= bn_t( 2 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 0, modulus );
            fe -= 2;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).sub( fpe_t( 2, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).sub( bn_t( 2 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).sub( 2 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) - fpe_t( 2, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) - bn_t( 2 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) - 2                       , 1 )

            fe  = fpe_t( 3, modulus );
            fe -= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 3, modulus );
            fe -= bn_t( 2 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 3, modulus );
            fe -= 2;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( fpe_t( 3, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( bn_t( 3 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).sub( 3 )                  , 9 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - fpe_t( 3, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) - bn_t( 3 )               , 9 )

            fe  = fpe_t( 2, modulus );
            fe -= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 2, modulus );
            fe -= bn_t( 3 );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 2, modulus );
            fe -= 3;
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( fpe_t( 8, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( bn_t( 8 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( 8 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) - fpe_t( 8, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) - bn_t( 8 )               , 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) - 8                       , 1 )

            fe  = fpe_t( 9, modulus );
            fe -= fpe_t( 8, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 9, modulus );
            fe -= bn_t( 8 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 9, modulus );
            fe -= 8;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 8, modulus ).sub( fpe_t( 9, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ).sub( bn_t( 9 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ).sub( 9 )                  , 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) - fpe_t( 9, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) - bn_t( 9 )               , 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) - 9                       , 9 )

            fe  = fpe_t( 8, modulus );
            fe -= fpe_t( 9, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 8, modulus );
            fe -= bn_t( 9 );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 8, modulus );
            fe -= 9;
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( fpe_t( 9, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( bn_t( 9 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( 9 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) - fpe_t( 9, modulus )     , 0 )

            fe  = fpe_t( 9, modulus );
            fe -= fpe_t( 9, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 9, modulus );
            fe -= bn_t( 9 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 9, modulus );
            fe -= 9;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( fpe_t( -1, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( bn_t( -1 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( -1 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - fpe_t( -1, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - bn_t( -1 )               , 0 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - -1                       , 0 )

            fe  = fpe_t( -1, modulus );
            fe -= fpe_t( -1, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( -1, modulus );
            fe -= bn_t( -1 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( -1, modulus );
            fe -= -1;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( fpe_t( 2, modulus ) ), 7 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( bn_t( 2 ) )          , 7 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).sub( 2 )                  , 7 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - fpe_t( 2, modulus )     , 7 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - bn_t( 2 )               , 7 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) - 2                       , 7 )

            fe  = fpe_t( -1, modulus );
            fe -= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 7 )

            fe  = fpe_t( -1, modulus );
            fe -= bn_t( 2 );
            REQUIRE_EQUAL( fe, 7 )

            fe  = fpe_t( -1, modulus );
            fe -= 2;
            REQUIRE_EQUAL( fe, 7 )

            // Test fe2 having different modulus does not affect result
            auto modulus2 = bn_t( 9 );
            REQUIRE_EQUAL( fpe_t( 9, modulus ).sub( fpe_t( 8, modulus2 ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) - fpe_t( 8, modulus2 )     , 1 )
            fe  = fpe_t( 9, modulus );
            fe -= fpe_t( 8, modulus2 );
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 8, modulus ).sub( fpe_t( 9, modulus2 ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) - fpe_t( 9, modulus2 )     , 9 )
            fe  = fpe_t( 8, modulus );
            fe -= fpe_t( 9, modulus2 );
            REQUIRE_EQUAL( fe, 9 )

            // Test invalid inputs produce invalid results (a <= -10)
            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( fpe_t( 10, modulus ) ), -10 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( bn_t( 10 ) )          , -10 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( 10 )                  , -10 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - fpe_t( 10, modulus )     , -10 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - bn_t( 10 )               , -10 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - 10                       , -10 )

            fe  = fpe_t( -10, modulus );
            fe -= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, -10 )

            fe  = fpe_t( -10, modulus );
            fe -= bn_t( 10 );
            REQUIRE_EQUAL( fe, -10 )

            fe  = fpe_t( -10, modulus );
            fe -= 10;
            REQUIRE_EQUAL( fe, -10 )

            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( fpe_t( 17, modulus ) ), -17 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( bn_t( 17 ) )          , -17 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ).sub( 17 )                  , -17 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - fpe_t( 17, modulus )     , -17 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - bn_t( 17 )               , -17 )
            REQUIRE_EQUAL( fpe_t( -10, modulus ) - 17                       , -17 )

            fe  = fpe_t( -10, modulus );
            fe -= fpe_t( 17, modulus );
            REQUIRE_EQUAL( fe, -17 )

            fe  = fpe_t( -10, modulus );
            fe -= bn_t( 17 );
            REQUIRE_EQUAL( fe, -17 )

            fe  = fpe_t( -10, modulus );
            fe -= 17;
            REQUIRE_EQUAL( fe, -17 )

            // Test invalid inputs produce invalid results (a && b >= 10)
            REQUIRE_EQUAL( fpe_t( 100, modulus ).sub( fpe_t( 10, modulus ) ), 90 )
            REQUIRE_EQUAL( fpe_t( 100, modulus ).sub( bn_t( 10 ) )          , 90 )
            REQUIRE_EQUAL( fpe_t( 100, modulus ).sub( 10 )                  , 90 )
            REQUIRE_EQUAL( fpe_t( 100, modulus ) - fpe_t( 10, modulus )     , 90 )
            REQUIRE_EQUAL( fpe_t( 100, modulus ) - bn_t( 10 )               , 90 )
            REQUIRE_EQUAL( fpe_t( 100, modulus ) - 10                       , 90 )

            fe  = fpe_t( 100, modulus );
            fe -= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 90 )

            fe  = fpe_t( 100, modulus );
            fe -= bn_t( 10 );
            REQUIRE_EQUAL( fe, 90 )

            fe  = fpe_t( 100, modulus );
            fe -= 10;
            REQUIRE_EQUAL( fe, 90 )

            REQUIRE_EQUAL( fpe_t( 1000, modulus ).sub( fpe_t( 989, modulus ) ), 11 )
            REQUIRE_EQUAL( fpe_t( 1000, modulus ).sub( bn_t( 989 ) )          , 11 )
            REQUIRE_EQUAL( fpe_t( 1000, modulus ).sub( 989 )                  , 11 )
            REQUIRE_EQUAL( fpe_t( 1000, modulus ) - fpe_t( 989, modulus )     , 11 )
            REQUIRE_EQUAL( fpe_t( 1000, modulus ) - bn_t( 989 )               , 11 )
            REQUIRE_EQUAL( fpe_t( 1000, modulus ) - 989                       , 11 )

            fe  = fpe_t( 1000, modulus );
            fe -= fpe_t( 989, modulus );
            REQUIRE_EQUAL( fe, 11 )

            fe  = fpe_t( 1000, modulus );
            fe -= bn_t( 989 );
            REQUIRE_EQUAL( fe, 11 )

            fe  = fpe_t( 1000, modulus );
            fe -= 989;
            REQUIRE_EQUAL( fe, 11 )

            // Test invalid inputs produce invalid results ( p < 0 )
            modulus = -10;
            REQUIRE_EQUAL( fpe_t( 12, modulus ).sub( fpe_t( 100, modulus ) ), -98 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).sub( bn_t( 100 ) )          , -98 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).sub( 100 )                  , -98 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) - fpe_t( 100, modulus )     , -98 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) - bn_t( 100 )               , -98 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) - 100                       , -98 )

            fe  = fpe_t( 12, modulus );
            fe -= fpe_t( 100, modulus );
            REQUIRE_EQUAL( fe, -98 )

            fe  = fpe_t( 12, modulus );
            fe -= bn_t( 100 );
            REQUIRE_EQUAL( fe, -98 )

            fe  = fpe_t( 12, modulus );
            fe -= 100;
            REQUIRE_EQUAL( fe, -98 )

            REQUIRE_EQUAL( fpe_t( 15, modulus ).sub( fpe_t( 16, modulus ) ), -11 )
            REQUIRE_EQUAL( fpe_t( 15, modulus ).sub( bn_t( 16 ) )          , -11 )
            REQUIRE_EQUAL( fpe_t( 15, modulus ).sub( 16 )                  , -11 )
            REQUIRE_EQUAL( fpe_t( 15, modulus ) - fpe_t( 16, modulus )     , -11 )
            REQUIRE_EQUAL( fpe_t( 15, modulus ) - bn_t( 16 )               , -11 )
            REQUIRE_EQUAL( fpe_t( 15, modulus ) - 16                       , -11 )

            fe  = fpe_t( 15, modulus );
            fe -= fpe_t( 16, modulus );
            REQUIRE_EQUAL( fe, -11 )

            fe  = fpe_t( 15, modulus );
            fe -= bn_t( 16 );
            REQUIRE_EQUAL( fe, -11 )

            fe  = fpe_t( 15, modulus );
            fe -= 16;
            REQUIRE_EQUAL( fe, -11 )

            // big number tests
            bn_t a = "55AACCFF55BBEE99010203040509F01";
            bn_t b = 0;
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), "55AACCFF55BBEE99010203040509F01" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , "55AACCFF55BBEE99010203040509F01" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , "55AACCFF55BBEE99010203040509F01" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , "55AACCFF55BBEE99010203040509F01" )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F01" )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F01" )

            a = 0;
            b = "55AACCFF55BBEE99010203040509F";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), "55AA775488BC98DD126902020205EB06B" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , "55AA775488BC98DD126902020205EB06B" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , "55AA775488BC98DD126902020205EB06B" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , "55AA775488BC98DD126902020205EB06B" )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55AA775488BC98DD126902020205EB06B" )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, "55AA775488BC98DD126902020205EB06B" )

            a = "55AACCFF55BBEE99010203040509F0109";
            b = 1;
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), "55AACCFF55BBEE99010203040509F0108" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , "55AACCFF55BBEE99010203040509F0108" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , "55AACCFF55BBEE99010203040509F0108" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , "55AACCFF55BBEE99010203040509F0108" )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F0108" )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, "55AACCFF55BBEE99010203040509F0108" )

            a = 1;
            b = "55AACCFF55BBEE99010203040509F0109";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , 2 )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , 2 )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, 2 )

            a = "55AACCFF55BBEE99010203040509F01";
            b = "55AACCFF55BBEE99010203040509F";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), "55552232566632AA680101010104E62" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , "55552232566632AA680101010104E62" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , "55552232566632AA680101010104E62" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , "55552232566632AA680101010104E62" )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55552232566632AA680101010104E62" )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, "55552232566632AA680101010104E62" )

            a = "55AACCFF55BBEE99010203040509F";
            b = "55AACCFF55BBEE99010203040509F01";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), "555577DD23658866569A02030408EB2A8" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , "555577DD23658866569A02030408EB2A8" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , "555577DD23658866569A02030408EB2A8" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , "555577DD23658866569A02030408EB2A8" )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "555577DD23658866569A02030408EB2A8" )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, "555577DD23658866569A02030408EB2A8" )

            // Test invalid inputs produce invalid results (a || b < 0)
            a = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            b =  "55AACCFF55BBEE99010203040509F01";
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), -bn_t( "55AACCFF55BBEE99010203040509F02" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , -bn_t( "55AACCFF55BBEE99010203040509F02" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , -bn_t( "55AACCFF55BBEE99010203040509F02" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , -bn_t( "55AACCFF55BBEE99010203040509F02" ) )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "55AACCFF55BBEE99010203040509F02" ) )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, -bn_t( "55AACCFF55BBEE99010203040509F02" ) )

            a =  "55AACCFF55BBEE99010203040509F01";
            b = -bn_t( "55AACCFF55BBEE99010203040509F010B" );
            modulus = "55AACCFF55BBEE99010203040509F010A";
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( fpe_t( b, modulus ) ), bn_t( "560077CC5511AA879A030507090EFA00C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ).sub( b )                  , bn_t( "560077CC5511AA879A030507090EFA00C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - fpe_t( b, modulus )     , bn_t( "560077CC5511AA879A030507090EFA00C" ) )
            REQUIRE_EQUAL( fpe_t( a, modulus ) - b                       , bn_t( "560077CC5511AA879A030507090EFA00C" ) )

            fe  = fpe_t( a, modulus );
            fe -= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, bn_t( "560077CC5511AA879A030507090EFA00C" ) )

            fe  = fpe_t( a, modulus );
            fe -= b;
            REQUIRE_EQUAL( fe, bn_t( "560077CC5511AA879A030507090EFA00C" ) )
        }

        // Multiplication tests
        {
            bn_t modulus = 10;
            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( fpe_t( 0, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( bn_t( 0 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( 0 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * fpe_t( 0, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * bn_t( 0 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * 0                       , 0 )

            auto fe = fpe_t( 0, modulus );
            fe *= fpe_t( 0, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe *= bn_t( 0 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe *= 0;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( fpe_t( 1, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( bn_t( 1 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).mul( 1 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * fpe_t( 1, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * bn_t( 1 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) * 1                       , 0 )

            fe  = fpe_t( 0, modulus );
            fe *= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe *= bn_t( 1 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe *= 1;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( fpe_t( 3, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( bn_t( 3 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( 3 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * fpe_t( 3, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * bn_t( 3 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * 3                       , 3 )

            fe  = fpe_t( 1, modulus );
            fe *= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 1, modulus );
            fe *= bn_t( 3 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 1, modulus );
            fe *= 3;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( fpe_t( 1, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( bn_t( 1 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( 1 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * fpe_t( 1, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * bn_t( 1 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * 1                       , 3 )

            fe  = fpe_t( 3, modulus );
            fe *= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 3, modulus );
            fe *= bn_t( 1 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 3, modulus );
            fe *= 1;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( fpe_t( 4, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( bn_t( 4 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( 4 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * fpe_t( 4, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * bn_t( 4 )               , 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * 4                       , 8 )

            fe  = fpe_t( 2, modulus );
            fe *= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 2, modulus );
            fe *= bn_t( 4 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 2, modulus );
            fe *= 4;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( fpe_t( 2, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( bn_t( 2 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( 2 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * fpe_t( 2, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * bn_t( 2 )               , 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * 2                       , 8 )

            fe  = fpe_t( 4, modulus );
            fe *= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 4, modulus );
            fe *= bn_t( 2 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 4, modulus );
            fe *= 2;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( fpe_t( 5, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( bn_t( 5 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( 5 )                  , 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * fpe_t( 5, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * bn_t( 5 )               , 5 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * 5                       , 5 )

            fe  = fpe_t( 3, modulus );
            fe *= fpe_t( 5, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 3, modulus );
            fe *= bn_t( 5 );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 3, modulus );
            fe *= 5;
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 5, modulus ).mul( fpe_t( 3, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 5, modulus ).mul( bn_t( 3 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( 5, modulus ).mul( 3 )                  , 5 )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) * fpe_t( 3, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) * bn_t( 3 )               , 5 )
            REQUIRE_EQUAL( fpe_t( 5, modulus ) * 3                       , 5 )

            fe  = fpe_t( 5, modulus );
            fe *= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 5, modulus );
            fe *= bn_t( 3 );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 5, modulus );
            fe *= 3;
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 7, modulus ).mul( fpe_t( 9, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ).mul( bn_t( 9 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ).mul( 9 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) * fpe_t( 9, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) * bn_t( 9 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) * 9                       , 3 )

            fe  = fpe_t( 7, modulus );
            fe *= fpe_t( 9, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 7, modulus );
            fe *= bn_t( 9 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 7, modulus );
            fe *= 9;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 9, modulus ).mul( fpe_t( 7, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).mul( bn_t( 7 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ).mul( 7 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) * fpe_t( 7, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) * bn_t( 7 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 9, modulus ) * 7                       , 3 )

            fe  = fpe_t( 9, modulus );
            fe *= fpe_t( 7, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 9, modulus );
            fe *= bn_t( 7 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 9, modulus );
            fe *= 7;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 8, modulus ).mul( fpe_t( 10, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ).mul( bn_t( 10 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ).mul( 10 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) * fpe_t( 10, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) * bn_t( 10 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 8, modulus ) * 10                       , 0 )

            fe  = fpe_t( 8, modulus );
            fe *= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 8, modulus );
            fe *= bn_t( 10 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 8, modulus );
            fe *= 10;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( fpe_t( 8, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( bn_t( 8 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( 8 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * fpe_t( 8, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * bn_t( 8 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * 8                       , 0 )

            fe  = fpe_t( 10, modulus );
            fe *= fpe_t( 8, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 10, modulus );
            fe *= bn_t( 8 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 10, modulus );
            fe *= 8;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( fpe_t( 12, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( bn_t( 12 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).mul( 12 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * fpe_t( 12, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * bn_t( 12 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) * 12                       , 0 )

            fe  = fpe_t( 10, modulus );
            fe *= fpe_t( 12, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 10, modulus );
            fe *= bn_t( 12 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 10, modulus );
            fe *= 12;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 12, modulus ).mul( fpe_t( 10, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).mul( bn_t( 10 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).mul( 10 )                  , 0 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) * fpe_t( 10, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) * bn_t( 10 )               , 0 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) * 10                       , 0 )

            fe  = fpe_t( 12, modulus );
            fe *= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 12, modulus );
            fe *= bn_t( 10 );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 12, modulus );
            fe *= 10;
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 11, modulus ).mul( fpe_t( 13, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ).mul( bn_t( 13 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ).mul( 13 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) * fpe_t( 13, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) * bn_t( 13 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) * 13                       , 3 )

            fe  = fpe_t( 11, modulus );
            fe *= fpe_t( 13, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 11, modulus );
            fe *= bn_t( 13 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 11, modulus );
            fe *= 13;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 13, modulus ).mul( fpe_t( 11, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ).mul( bn_t( 11 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ).mul( 11 )                  , 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) * fpe_t( 11, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) * bn_t( 11 )               , 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) * 11                       , 3 )

            fe  = fpe_t( 13, modulus );
            fe *= fpe_t( 11, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 13, modulus );
            fe *= bn_t( 11 );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 13, modulus );
            fe *= 11;
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 65535, modulus ).mul( fpe_t( 4294967295U, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ).mul( bn_t( 4294967295U ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ).mul( 4294967295U )                  , 5 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ) * fpe_t( 4294967295U, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ) * bn_t( 4294967295U )               , 5 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ) * 4294967295U                       , 5 )

            fe  = fpe_t( 65535, modulus );
            fe *= fpe_t( 4294967295U, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 65535, modulus );
            fe *= bn_t( 4294967295U );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 65535, modulus );
            fe *= 4294967295U;
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ).mul( fpe_t( 65535, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ).mul( bn_t( 65535 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ).mul( 65535 )                  , 5 )
            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ) * fpe_t( 65535, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ) * bn_t( 65535 )               , 5 )
            REQUIRE_EQUAL( fpe_t( 4294967295U, modulus ) * 65535                       , 5 )

            fe  = fpe_t( 4294967295U, modulus );
            fe *= fpe_t( 65535, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 4294967295U, modulus );
            fe *= bn_t( 65535 );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 4294967295U, modulus );
            fe *= 65535;
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 65536, modulus ).mul( fpe_t( 18446744073709551613ULL, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ).mul( bn_t( 18446744073709551613ULL ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ).mul( 18446744073709551613ULL )                  , 8 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ) * fpe_t( 18446744073709551613ULL, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ) * bn_t( 18446744073709551613ULL )               , 8 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ) * 18446744073709551613ULL                       , 8 )

            fe  = fpe_t( 65536, modulus );
            fe *= fpe_t( 18446744073709551613ULL, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 65536, modulus );
            fe *= bn_t( 18446744073709551613ULL );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 65536, modulus );
            fe *= 18446744073709551613ULL;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ).mul( fpe_t( 65536, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ).mul( bn_t( 65536 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ).mul( 65536 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ) * fpe_t( 65536, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ) * bn_t( 65536 )               , 8 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ) * 65536                       , 8 )

            fe  = fpe_t( 18446744073709551613ULL, modulus );
            fe *= fpe_t( 65536, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 18446744073709551613ULL, modulus );
            fe *= bn_t( 65536 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 18446744073709551613ULL, modulus );
            fe *= 65536;
            REQUIRE_EQUAL( fe, 8 )


            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( fpe_t( -1, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( bn_t( -1 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( -1 )                  , 1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * fpe_t( -1, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * bn_t( -1 )               , 1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * -1                       , 1 )

            fe  = fpe_t( -1, modulus );
            fe *= fpe_t( -1, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( -1, modulus );
            fe *= bn_t( -1 );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( -1, modulus );
            fe *= -1;
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( -2, modulus ).mul( fpe_t( -4, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( -2, modulus ).mul( bn_t( -4 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( -2, modulus ).mul( -4 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( -2, modulus ) * fpe_t( -4, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( -2, modulus ) * bn_t( -4 )               , 8 )
            REQUIRE_EQUAL( fpe_t( -2, modulus ) * -4                       , 8 )

            fe  = fpe_t( -2, modulus );
            fe *= fpe_t( -4, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( -2, modulus );
            fe *= bn_t( -4 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( -2, modulus );
            fe *= -4;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( -4, modulus ).mul( fpe_t( -2, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( -4, modulus ).mul( bn_t( -2 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( -4, modulus ).mul( -2 )                  , 8 )
            REQUIRE_EQUAL( fpe_t( -4, modulus ) * fpe_t( -2, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( -4, modulus ) * bn_t( -2 )               , 8 )
            REQUIRE_EQUAL( fpe_t( -4, modulus ) * -2                       , 8 )

            fe  = fpe_t( -4, modulus );
            fe *= fpe_t( -2, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( -4, modulus );
            fe *= bn_t( -2 );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( -4, modulus );
            fe *= -2;
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( fpe_t( -5, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( bn_t( -5 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( -5 )                  , 5 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * fpe_t( -5, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * bn_t( -5 )               , 5 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * -5                       , 5 )

            fe  = fpe_t( -3, modulus );
            fe *= fpe_t( -5, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( -3, modulus );
            fe *= bn_t( -5 );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( -3, modulus );
            fe *= -5;
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( -5, modulus ).mul( fpe_t( -3, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ).mul( bn_t( -3 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ).mul( -3 )                  , 5 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ) * fpe_t( -3, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ) * bn_t( -3 )               , 5 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ) * -3                       , 5 )

            fe  = fpe_t( -5, modulus );
            fe *= fpe_t( -3, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( -5, modulus );
            fe *= bn_t( -3 );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( -5, modulus );
            fe *= -3;
            REQUIRE_EQUAL( fe, 5 )

            // Test fe2 having different modulus does not affect result
            bn_t modulus2 = 5;
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( fpe_t( 2, modulus2 ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * fpe_t( 2, modulus2 )     , 8 )
            fe  = fpe_t( 4, modulus );
            fe *= fpe_t( 2, modulus2 );
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( fpe_t( 4, modulus2 ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * fpe_t( 4, modulus2 )     , 8 )
            fe  = fpe_t( 2, modulus );
            fe *= fpe_t( 4, modulus2 );
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 13, modulus ).mul( fpe_t( 11, modulus2 ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) * fpe_t( 11, modulus2 )     , 3 )
            fe  = fpe_t( 13, modulus );
            fe *= fpe_t( 11, modulus2 );
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 11, modulus ).mul( fpe_t( 13, modulus2 ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) * fpe_t( 13, modulus2 )     , 3 )
            fe  = fpe_t( 11, modulus );
            fe *= fpe_t( 13, modulus2 );
            REQUIRE_EQUAL( fe, 3 )

            // Test invalid inputs produce invalid results (a || b || p < 0)
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( fpe_t( 1, modulus ) ), -1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( bn_t( 1 ) )          , -1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( 1 )                  , -1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * fpe_t( 1, modulus )     , -1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * bn_t( 1 )               , -1 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * 1                       , -1 )

            fe  = fpe_t( -1, modulus );
            fe *= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, -1 )

            fe  = fpe_t( -1, modulus );
            fe *= bn_t( 1 );
            REQUIRE_EQUAL( fe, -1 )

            fe  = fpe_t( -1, modulus );
            fe *= 1;
            REQUIRE_EQUAL( fe, -1 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( fpe_t( -1, modulus ) ), -1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( bn_t( -1 ) )          , -1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).mul( -1 )                  , -1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * fpe_t( -1, modulus )     , -1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * bn_t( -1 )               , -1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) * -1                       , -1 )

            fe  = fpe_t( 1, modulus );
            fe *= fpe_t( -1, modulus );
            REQUIRE_EQUAL( fe, -1 )

            fe  = fpe_t( 1, modulus );
            fe *= bn_t( -1 );
            REQUIRE_EQUAL( fe, -1 )

            fe  = fpe_t( 1, modulus );
            fe *= -1;
            REQUIRE_EQUAL( fe, -1 )

            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( fpe_t( 2, modulus ) ), -2 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( bn_t( 2 ) )          , -2 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ).mul( 2 )                  , -2 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * fpe_t( 2, modulus )     , -2 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * bn_t( 2 )               , -2 )
            REQUIRE_EQUAL( fpe_t( -1, modulus ) * 2                       , -2 )

            fe  = fpe_t( -1, modulus );
            fe *= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( -1, modulus );
            fe *= bn_t( 2 );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( -1, modulus );
            fe *= 2;
            REQUIRE_EQUAL( fe, -2 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( fpe_t( -1, modulus ) ), -2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( bn_t( -1 ) )          , -2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).mul( -1 )                  , -2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * fpe_t( -1, modulus )     , -2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * bn_t( -1 )               , -2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) * -1                       , -2 )

            fe  = fpe_t( 2, modulus );
            fe *= fpe_t( -1, modulus );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( 2, modulus );
            fe *= bn_t( -1 );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( 2, modulus );
            fe *= -1;
            REQUIRE_EQUAL( fe, -2 )

            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( fpe_t( 4, modulus ) ), -2 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( bn_t( 4 ) )          , -2 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ).mul( 4 )                  , -2 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * fpe_t( 4, modulus )     , -2 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * bn_t( 4 )               , -2 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) * 4                       , -2 )

            fe  = fpe_t( -3, modulus );
            fe *= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( -3, modulus );
            fe *= bn_t( 4 );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( -3, modulus );
            fe *= 4;
            REQUIRE_EQUAL( fe, -2 )

            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( fpe_t( -3, modulus ) ), -2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( bn_t( -3 ) )          , -2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( -3 )                  , -2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * fpe_t( -3, modulus )     , -2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * bn_t( -3 )               , -2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * -3                       , -2 )

            fe  = fpe_t( 4, modulus );
            fe *= fpe_t( -3, modulus );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( 4, modulus );
            fe *= bn_t( -3 );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( 4, modulus );
            fe *= -3;
            REQUIRE_EQUAL( fe, -2 )

            modulus = -10;
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( fpe_t( 3, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( bn_t( 3 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).mul( 3 )                  , 2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * fpe_t( 3, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * bn_t( 3 )               , 2 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) * 3                       , 2 )

            fe  = fpe_t( 4, modulus );
            fe *= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 4, modulus );
            fe *= bn_t( 3 );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 4, modulus );
            fe *= 3;
            REQUIRE_EQUAL( fe, 2 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( fpe_t( 4, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( bn_t( 4 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).mul( 4 )                  , 2 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * fpe_t( 4, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * bn_t( 4 )               , 2 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) * 4                       , 2 )

            fe  = fpe_t( 3, modulus );
            fe *= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 3, modulus );
            fe *= bn_t( 4 );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 3, modulus );
            fe *= 4;
            REQUIRE_EQUAL( fe, 2 )

            // Big numbers
            bn_t a = "6A9E8EA23CB63C228F31";
            bn_t b = "6AA11DCB29F14BACCFF1";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            a = "6AA11DCB29F14BACCFF1";
            b = "6A9E8EA23CB63C228F31";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "2C68C12F748702A999B83A04E233AF7B1E3D6C21" )

            a = "6A9E8EA23CB63C228F31AD9268B4097F1";
            b = "6AA11DCB29F14BACCFF196CE3F0AD2";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            a = "6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6A9E8EA23CB63C228F31AD9268B4097F1";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            a = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6AA11DCB29F14BACCFF196CE3F0AD2";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            a = "6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "1A945B1E1A80601352171738E860E7922A6EBAAA6" )

            a = -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" );
            b = -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            a = -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            b = -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" );
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC" )

            // Test invalid inputs produce invalid results (a || b < 0)
            a = -bn_t( "6A9E8EA23CB63C228F31" );
            b =  bn_t( "6AA11DCB29F14BACCFF1" );
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            a =  bn_t( "6A9E8EA23CB63C228F31" );
            b = -bn_t( "6AA11DCB29F14BACCFF1" );
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "2C68C12F748702A999B83A04E233AF7B1E3D6C21") )

            a = -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" );
            b =  bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            a =  bn_t( "6A9E8EA23CB63C228F31AD9268B4097F1" );
            b = -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "55E5D84D4E68A9F8EF1E3E56B73B64A732B9A66BC") )

            a = -bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" );
            b =  bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            a =  bn_t( "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2" );
            b = -bn_t( "6AA11DCB29F14BACCFF196CE3F0AD2" );
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( fpe_t( b, modulus ) ), -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ).mul( b )                  , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) * fpe_t( b, modulus )     , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
            REQUIRE_EQUAL( fpe_t( a, modulus ) *  b                      , -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            fe  = fpe_t( a, modulus );
            fe *= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )

            fe  = fpe_t( a, modulus );
            fe *= b;
            REQUIRE_EQUAL( fe, -bn_t( "1A945B1E1A80601352171738E860E7922A6EBAAA6") )
        }

        // Division tests
        {
            bn_t modulus = 10;
            REQUIRE_EQUAL( fpe_t( 0, modulus ).div( fpe_t( 1, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ).div( bn_t( 1 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) / fpe_t( 1, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 0, modulus ) / bn_t( 1 )               , 0 )

            auto fe = fpe_t( 0, modulus );
            fe /= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 0, modulus );
            fe /= bn_t( 1 );
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( fpe_t( 1, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( bn_t( 1 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / fpe_t( 1, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / bn_t( 1 )               , 1 )

            fe  = fpe_t( 1, modulus );
            fe /= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 1, modulus );
            fe /= bn_t( 1 );
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).div( fpe_t( 1, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).div( bn_t( 1 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) / fpe_t( 1, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) / bn_t( 1 )               , 2 )

            fe  = fpe_t( 2, modulus );
            fe /= fpe_t( 1, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 2, modulus );
            fe /= bn_t( 1 );
            REQUIRE_EQUAL( fe, 2 )

            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( fpe_t( 3, modulus ) ), 7 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( bn_t( 3 ) )          , 7 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / fpe_t( 3, modulus )     , 7 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / bn_t( 3 )               , 7 )

            fe  = fpe_t( 1, modulus );
            fe /= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 7 )

            fe  = fpe_t( 1, modulus );
            fe /= bn_t( 3 );
            REQUIRE_EQUAL( fe, 7 )

            modulus = 11;
            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( fpe_t( 4, modulus ) ), 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ).div( bn_t( 4 ) )          , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / fpe_t( 4, modulus )     , 3 )
            REQUIRE_EQUAL( fpe_t( 1, modulus ) / bn_t( 4 )               , 3 )

            fe  = fpe_t( 1, modulus );
            fe /= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, 3 )

            fe  = fpe_t( 1, modulus );
            fe /= bn_t( 4 );
            REQUIRE_EQUAL( fe, 3 )

            REQUIRE_EQUAL( fpe_t( 2, modulus ).div( fpe_t( 5, modulus ) ), 7 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ).div( bn_t( 5 ) )          , 7 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) / fpe_t( 5, modulus )     , 7 )
            REQUIRE_EQUAL( fpe_t( 2, modulus ) / bn_t( 5 )               , 7 )

            fe  = fpe_t( 2, modulus );
            fe /= fpe_t( 5, modulus );
            REQUIRE_EQUAL( fe, 7 )

            fe  = fpe_t( 2, modulus );
            fe /= bn_t( 5 );
            REQUIRE_EQUAL( fe, 7 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( fpe_t( 6, modulus ) ), 6 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( bn_t( 6 ) )          , 6 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / fpe_t( 6, modulus )     , 6 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / bn_t( 6 )               , 6 )

            fe  = fpe_t( 3, modulus );
            fe /= fpe_t( 6, modulus );
            REQUIRE_EQUAL( fe, 6 )

            fe  = fpe_t( 3, modulus );
            fe /= bn_t( 6 );
            REQUIRE_EQUAL( fe, 6 )

            REQUIRE_EQUAL( fpe_t( 6, modulus ).div( fpe_t( 3, modulus ) ), 2 )
            REQUIRE_EQUAL( fpe_t( 6, modulus ).div( bn_t( 3 ) )          , 2 )
            REQUIRE_EQUAL( fpe_t( 6, modulus ) / fpe_t( 3, modulus )     , 2 )
            REQUIRE_EQUAL( fpe_t( 6, modulus ) / bn_t( 3 )               , 2 )

            fe  = fpe_t( 6, modulus );
            fe /= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 2 )

            fe  = fpe_t( 6, modulus );
            fe /= bn_t( 3 );
            REQUIRE_EQUAL( fe, 2 )

            REQUIRE_EQUAL( fpe_t( 7, modulus ).div( fpe_t( 2, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ).div( bn_t( 2 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) / fpe_t( 2, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) / bn_t( 2 )               , 9 )

            fe  = fpe_t( 7, modulus );
            fe /= fpe_t( 2, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 7, modulus );
            fe /= bn_t( 2 );
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( fpe_t( 4, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( bn_t( 4 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / fpe_t( 4, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / bn_t( 4 )               , 9 )

            fe  = fpe_t( 3, modulus );
            fe /= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 3, modulus );
            fe /= bn_t( 4 );
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 4, modulus ).div( fpe_t( 3, modulus ) ), 5 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ).div( bn_t( 3 ) )          , 5 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) / fpe_t( 3, modulus )     , 5 )
            REQUIRE_EQUAL( fpe_t( 4, modulus ) / bn_t( 3 )               , 5 )

            fe  = fpe_t( 4, modulus );
            fe /= fpe_t( 3, modulus );
            REQUIRE_EQUAL( fe, 5 )

            fe  = fpe_t( 4, modulus );
            fe /= bn_t( 3 );
            REQUIRE_EQUAL( fe, 5 )

            REQUIRE_EQUAL( fpe_t( 10, modulus ).div( fpe_t( 10, modulus ) ), 1 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ).div( bn_t( 10 ) )          , 1 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) / fpe_t( 10, modulus )     , 1 )
            REQUIRE_EQUAL( fpe_t( 10, modulus ) / bn_t( 10 )               , 1 )

            fe  = fpe_t( 10, modulus );
            fe /= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 1 )

            fe  = fpe_t( 10, modulus );
            fe /= bn_t( 10 );
            REQUIRE_EQUAL( fe, 1 )

            REQUIRE_EQUAL( fpe_t( 11, modulus ).div( fpe_t( 10, modulus ) ), 0 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ).div( bn_t( 10 ) )          , 0 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) / fpe_t( 10, modulus )     , 0 )
            REQUIRE_EQUAL( fpe_t( 11, modulus ) / bn_t( 10 )               , 0 )

            fe  = fpe_t( 11, modulus );
            fe /= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 0 )

            fe  = fpe_t( 11, modulus );
            fe /= bn_t( 10 );
            REQUIRE_EQUAL( fe, 0 )

            REQUIRE_EQUAL( fpe_t( 12, modulus ).div( fpe_t( 10, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ).div( bn_t( 10 ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) / fpe_t( 10, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 12, modulus ) / bn_t( 10 )               , 10 )

            fe  = fpe_t( 12, modulus );
            fe /= fpe_t( 10, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 12, modulus );
            fe /= bn_t( 10 );
            REQUIRE_EQUAL( fe, 10 )

            REQUIRE_EQUAL( fpe_t( 13, modulus ).div( fpe_t( 25, modulus ) ), 8 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ).div( bn_t( 25 ) )          , 8 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) / fpe_t( 25, modulus )     , 8 )
            REQUIRE_EQUAL( fpe_t( 13, modulus ) / bn_t( 25 )               , 8 )

            fe  = fpe_t( 13, modulus );
            fe /= fpe_t( 25, modulus );
            REQUIRE_EQUAL( fe, 8 )

            fe  = fpe_t( 13, modulus );
            fe /= bn_t( 25 );
            REQUIRE_EQUAL( fe, 8 )

            REQUIRE_EQUAL( fpe_t( 65535, modulus ).div( fpe_t( 4294967295U, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ).div( bn_t( 4294967295U ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ) / fpe_t( 4294967295U, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 65535, modulus ) / bn_t( 4294967295U )               , 10 )

            fe  = fpe_t( 65535, modulus );
            fe /= fpe_t( 4294967295U, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 65535, modulus );
            fe /= bn_t( 4294967295U );
            REQUIRE_EQUAL( fe, 10 )

            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ).div( fpe_t( 65535U, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ).div( bn_t( 65535U ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ) / fpe_t( 65535U, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ) / bn_t( 65535U )               , 10 )

            fe  = fpe_t( 4294967295LL, modulus );
            fe /= fpe_t( 65535U, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 4294967295LL, modulus );
            fe /= bn_t( 65535U );
            REQUIRE_EQUAL( fe, 10 )

            REQUIRE_EQUAL( fpe_t( 65536, modulus ).div( fpe_t( 18446744073709551613ULL, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ).div( bn_t( 18446744073709551613ULL ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ) / fpe_t( 18446744073709551613ULL, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 65536, modulus ) / bn_t( 18446744073709551613ULL )               , 10 )

            fe  = fpe_t( 65536, modulus );
            fe /= fpe_t( 18446744073709551613ULL, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 65536, modulus );
            fe /= bn_t( 18446744073709551613ULL );
            REQUIRE_EQUAL( fe, 10 )

            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ).div( fpe_t( 65536, modulus ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ).div( bn_t( 65536 ) )          , 10 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ) / fpe_t( 65536, modulus )     , 10 )
            REQUIRE_EQUAL( fpe_t( 18446744073709551613ULL, modulus ) / bn_t( 65536 )               , 10 )

            fe  = fpe_t( 18446744073709551613ULL, modulus );
            fe /= fpe_t( 65536, modulus );
            REQUIRE_EQUAL( fe, 10 )

            fe  = fpe_t( 18446744073709551613ULL, modulus );
            fe /= bn_t( 65536 );
            REQUIRE_EQUAL( fe, 10 )

            // Test fe2 having different modulus does not affect result
            bn_t modulus2 = 3;
            REQUIRE_EQUAL( fpe_t( 7, modulus ).div( fpe_t( 2, modulus2 ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 7, modulus ) / fpe_t( 2, modulus2 )     , 9 )
            fe  = fpe_t( 7, modulus );
            fe /= fpe_t( 2, modulus2 );
            REQUIRE_EQUAL( fe, 9 )

            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ).div( fpe_t( 65535U, modulus2 ) ), 10 )
            REQUIRE_EQUAL( fpe_t( 4294967295LL, modulus ) / fpe_t( 65535U, modulus2 )     , 10 )
            fe  = fpe_t( 4294967295LL, modulus );
            fe /= fpe_t( 65535U, modulus2 );
            REQUIRE_EQUAL( fe, 10 )

            // Test invalid inputs produce invalid outputs ( a || b || p < 0 )
            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( 3, modulus ).div( fpe_t( -4, modulus ) );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( 3, modulus ).div( bn_t( -4 ) );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( 3, modulus ) / fpe_t( -4, modulus );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( 3, modulus ) / bn_t( -4 ) ;
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( -3, modulus ).div( fpe_t( -4, modulus ) );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( -3, modulus ).div( bn_t( -4 ) );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( -3, modulus ) / fpe_t( -4, modulus );
            })

            REQUIRE_ASSERT( "modular inverse failed", []() {
                bn_t modulus = 11;
                auto fr = fpe_t( -3, modulus ) / bn_t( -4 ) ;
            })

            modulus = 11;
            REQUIRE_EQUAL( fpe_t( -3, modulus ).div( fpe_t( 4, modulus ) ), -9 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ).div( bn_t( 4 ) )          , -9 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) / fpe_t( 4, modulus )     , -9 )
            REQUIRE_EQUAL( fpe_t( -3, modulus ) / bn_t( 4 )               , -9 )

            fe  = fpe_t( -3, modulus );
            fe /= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, -9 )

            fe  = fpe_t( -3, modulus );
            fe /= bn_t( 4 );
            REQUIRE_EQUAL( fe, -9 )

            modulus = 11;
            REQUIRE_EQUAL( fpe_t( -5, modulus ).div( fpe_t( 8, modulus ) ), -2 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ).div( bn_t( 8 ) )          , -2 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ) / fpe_t( 8, modulus )     , -2 )
            REQUIRE_EQUAL( fpe_t( -5, modulus ) / bn_t( 8 )               , -2 )

            fe  = fpe_t( -5, modulus );
            fe /= fpe_t( 8, modulus );
            REQUIRE_EQUAL( fe, -2 )

            fe  = fpe_t( -5, modulus );
            fe /= bn_t( 8 );
            REQUIRE_EQUAL( fe, -2 )

            modulus = -11;
            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( fpe_t( 4, modulus ) ), 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ).div( bn_t( 4 ) )          , 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / fpe_t( 4, modulus )     , 9 )
            REQUIRE_EQUAL( fpe_t( 3, modulus ) / bn_t( 4 )               , 9 )

            fe  = fpe_t( 3, modulus );
            fe /= fpe_t( 4, modulus );
            REQUIRE_EQUAL( fe, 9 )

            fe  = fpe_t( 3, modulus );
            fe /= bn_t( 4 );
            REQUIRE_EQUAL( fe, 9 )

            // Big numbers
            bn_t a = "6A9E8EA23CB63C228F31";
            bn_t b = "6AA11DCB29F14BACCFF1";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "4723E220CEE84E2E184B06CB7A758F5DE656B905D" )

            a = "6AA11DCB29F14BACCFF1";
            b = "6A9E8EA23CB63C228F31";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "28B8556A73C2E4308BC9424A62336E808D232C86A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "28B8556A73C2E4308BC9424A62336E808D232C86A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "28B8556A73C2E4308BC9424A62336E808D232C86A" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "28B8556A73C2E4308BC9424A62336E808D232C86A" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "28B8556A73C2E4308BC9424A62336E808D232C86A" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "28B8556A73C2E4308BC9424A62336E808D232C86A" )

            a = "6A9E8EA23CB63C228F31AD9268B4097F1";
            b = "6AA11DCB29F14BACCFF196CE3F0AD2";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "903E159F5BB2E288A8216871A5156CC638754C26" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "903E159F5BB2E288A8216871A5156CC638754C26" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "903E159F5BB2E288A8216871A5156CC638754C26" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "903E159F5BB2E288A8216871A5156CC638754C26" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "903E159F5BB2E288A8216871A5156CC638754C26" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "903E159F5BB2E288A8216871A5156CC638754C26" )

            a = "6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6A9E8EA23CB63C228F31AD9268B4097F1";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "46833B41C273C6118249EA12465D0A008396E3AFA" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "46833B41C273C6118249EA12465D0A008396E3AFA" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "46833B41C273C6118249EA12465D0A008396E3AFA" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "46833B41C273C6118249EA12465D0A008396E3AFA" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "46833B41C273C6118249EA12465D0A008396E3AFA" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "46833B41C273C6118249EA12465D0A008396E3AFA" )

            a = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6AA11DCB29F14BACCFF196CE3F0AD2";
            modulus = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "2F368DC795A098F09B8A3E473A3EF7805FA993BD5" )

            a = "6AA11DCB29F14BACCFF196CE3F0AD2";
            b = "6A9E8EA23CB63C228F31AD9268B4097F156D6AA11DCB29F14BACCFF196CE3F0AD2";
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( fpe_t( b, modulus ) ), "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )
            REQUIRE_EQUAL( fpe_t( a, modulus ).div( b )                  , "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / fpe_t( b, modulus )     , "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )
            REQUIRE_EQUAL( fpe_t( a, modulus ) / b                       , "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )

            fe  = fpe_t( a, modulus );
            fe /= fpe_t( b, modulus );
            REQUIRE_EQUAL( fe, "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )

            fe  = fpe_t( a, modulus );
            fe /= b;
            REQUIRE_EQUAL( fe, "2F1F1FE098ED612AC09FE67F0DF9AE18AC979376C" )
        }
    EOSIO_TEST_END // fp_element_test

    EOSIO_TEST_BEGIN(fp_test)
        EOSIO_TEST( fp_function_test )
        EOSIO_TEST( fp_element_test  )
    EOSIO_TEST_END
}
