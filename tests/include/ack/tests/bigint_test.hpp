// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/bigint.hpp>
#include <ack/types.hpp>
#include <ack/utils.hpp>
#include <ack/tests/utils.hpp>

#include <array>
#include <bit>
#include <limits>
#include <type_traits>
#include <eosio/tester.hpp>

namespace ack::tests {
    namespace detail {
        template<std::size_t N>
        using fixed_word_array = std::array<word_t, N>;

        template<std::size_t N>
        inline constexpr fixed_word_array<N> word_array( const word_t (&warray)[N] ) {
            fixed_word_array<N> r{};
            for ( std::size_t i = 0; i < N; i++ ) {
                r[i] = warray[i];
            }
            return r;
        }

        inline constexpr void swap_bytes(byte_t* x, size_t n)
        {
            for (size_t i = 0; i < n / 2; i++) {
                std::swap(x[i], x[n - 1 - i]);
            }
        }

        template<typename T, typename = std::enable_if_t< std::is_integral_v<T> >>
        inline constexpr size_t bit_width( const T& x ) {
            using ut = std::make_unsigned_t<T>;
            return std::numeric_limits<ut>::digits - std::countl_zero<ut>(abs(x));
        }

        template<typename TVData>
        struct bigint_ser_test
        {
            using bigint_t = typename TVData::bigint_t;
            void do_tests() const {
                const auto test = []( const auto& s, const auto& tv, const auto& tvis ) {
                    std::remove_cvref_t<decltype(tv)> r {};

                    REQUIRE_EQUAL( std::span( s.data(), s.size() ), tvis );

                    REQUIRE_EQUAL( s.get_bytes( r ), true );
                    REQUIRE_EQUAL( r, tv )

                    REQUIRE_EQUAL( std::span( s.to_bytes() ), tv );
                };

                // Test constexpr set_array from big endian
                {
                    constexpr bigint_t b = [&](){
                        bigint_t tmp;
                        tmp.set_array( TVData::tv.data(), TVData::tv.size(), /*big_endian*/true );
                        return tmp;
                    }();

                    test( b, TVData::tv, TVData::tvis );
                }

                // Test runtime set_array from big endian
                {
                    bigint_t b;
                    REQUIRE_EQUAL(
                        b.set_array( TVData::tv.data(), TVData::tv.size(), /*big_endian*/true ),
                        true
                    );
                    test( b, TVData::tv, TVData::tvis );
                }

                // Test constexpr set_array from little endian
                {
                    constexpr bigint_t b = [&](){
                        auto tvle = TVData::tv;
                        swap_bytes( const_cast<byte_t*>( tvle.data() ), tvle.size() );
                        bigint_t tmp;
                        tmp.set_array( tvle.data(), tvle.size(), /*big_endian*/false );
                        return tmp;
                    }();

                    test( b, TVData::tv, TVData::tvis );
                }

                // Test runtime set_array from little endian
                {
                    bigint_t b;
                    auto tvle = TVData::tv;
                    swap_bytes( tvle.data(), tvle.size() );
                    b.set_array( tvle.data(), tvle.size(), /*big_endian*/false );
                    test( b, TVData::tv, TVData::tvis );
                }

                // Test constexpr get_array from
                {
                    constexpr bigint_t b = [&](){
                        bigint_t tmp;
                        tmp.set_array( TVData::tv.data(), TVData::tv.size(), /*big_endian*/true );
                        return tmp;
                    }();

                    constexpr auto rarr = [&](){
                        std::remove_cvref_t<decltype(TVData::tvis)> r {};
                        b.get_array( r.data(), r.size() );
                        return r;
                    }();

                    REQUIRE_EQUAL( rarr, TVData::tvis );
                }

                // Test runtime get_array from
                {
                    bigint_t b;
                    b.set_array( TVData::tv.data(), TVData::tv.size(), /*big_endian*/true );

                    std::remove_cvref_t<decltype(TVData::tvis)> r {};
                    b.get_array( r.data(), r.size() );

                    REQUIRE_EQUAL( r, TVData::tvis );
                }

                // Test constexpr set_bytes
                {
                    constexpr bigint_t b = [&](){
                        bigint_t tmp;
                        tmp.set_bytes( TVData::tv );
                        return tmp;
                    }();
                    test( b, TVData::tv, TVData::tvis );
                }

                // Test runtime set_bytes
                {
                    bigint_t b;
                    b.set_bytes( TVData::tv );
                    test( b, TVData::tv, TVData::tvis );
                }

                // Test constexpr constructor
                {
                    constexpr bigint_t b( TVData::tv );
                    test( b, TVData::tv, TVData::tvis );

                    constexpr bigint_t b1( TVData::tvhex );
                    test( b1, TVData::tv, TVData::tvis );

                    constexpr bigint_t b2( b );
                    test( b2, TVData::tv, TVData::tvis );
                }

                // Test runtime constructor
                {
                    bigint_t b( TVData::tv );
                    test( b, TVData::tv, TVData::tvis );

                    bigint_t b1( TVData::tvhex );
                    test( b1, TVData::tv, TVData::tvis );

                    bigint_t b2( b );
                    test( b2, TVData::tv, TVData::tvis );
                }

                // Test constexpr copy constructor
                {
                    constexpr bigint_t b = TVData::tv;
                    test( b, TVData::tv, TVData::tvis );

                    constexpr bigint_t b1 = b ;
                    test( b1, TVData::tv, TVData::tvis );
                }

                // Test runtime copy constructor
                {
                    bigint_t b = TVData::tv;
                    test( b, TVData::tv, TVData::tvis );

                    bigint_t b1 = b ;
                    test( b1, TVData::tv, TVData::tvis );
                }
            }
        };

        namespace bigint_ser_test_data
        {
            struct tv1 {
                using bigint_t = fixed_bigint<1>;
                static constexpr char tvhex[] = "00";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0
                });
            };

            struct tv2 {
                using bigint_t = fixed_bigint<1>;
                static constexpr char tvhex[] = "01";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1
                });
            };

            struct tv3 {
                using bigint_t = fixed_bigint<2>;
                static constexpr char tvhex[] = "02";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2
                });
            };

            struct tv4 {
                using bigint_t = fixed_bigint<2>;
                static constexpr char tvhex[] = "03";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    3
                });
            };

            struct tv5 {
                using bigint_t = fixed_bigint<3>;
                static constexpr char tvhex[] = "04";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4
                });
            };

            struct tv6 {
                using bigint_t = fixed_bigint<4>;
                static constexpr char tvhex[] = "08";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    8
                });
            };

            struct tv7 {
                using bigint_t = fixed_bigint<5>;
                static constexpr char tvhex[] = "10";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    16
                });
            };

            struct tv8 {
                using bigint_t = fixed_bigint<6>;
                static constexpr char tvhex[] = "20";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    32
                });
            };

            struct tv9 {
                using bigint_t = fixed_bigint<6>;
                static constexpr char tvhex[] = "28";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    40
                });
            };

            struct tv10 {
                using bigint_t = fixed_bigint<6>;
                static constexpr char tvhex[] = "3f";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    63
                });
            };

            struct tv11 {
                using bigint_t = fixed_bigint<7>;
                static constexpr char tvhex[] = "7f";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    127
                });
            };

            struct tv12 {
                using bigint_t = fixed_bigint<7>;
                static constexpr char tvhex[] = "40";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    64
                });
            };

            struct tv13 {
                using bigint_t = fixed_bigint<8>;
                static constexpr char tvhex[] = "80";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    128
                });
            };

            struct tv14 {
                using bigint_t = fixed_bigint<8>;
                static constexpr char tvhex[] = "ff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    255
                });
            };

            struct tv15 {
                using bigint_t = fixed_bigint<9>;
                static constexpr char tvhex[] = "0100";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    256
                });
            };

            struct tv16 {
                using bigint_t = fixed_bigint<9>;
                static constexpr char tvhex[] = "01ff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    511
                });
            };

            struct tv17 {
                using bigint_t = fixed_bigint<10>;
                static constexpr char tvhex[] = "0200";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    512
                });
            };

            struct tv18 {
                using bigint_t = fixed_bigint<16>;
                static constexpr char tvhex[] = "ffff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    65535
                });
            };

            struct tv19 {
                using bigint_t = fixed_bigint<17>;
                static constexpr char tvhex[] = "010000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    65536
                });
            };

            struct tv20 {
                using bigint_t = fixed_bigint<20>;
                static constexpr char tvhex[] = "0fffff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1048575
                });
            };

            struct tv21 {
                using bigint_t = fixed_bigint<21>;
                static constexpr char tvhex[] = "100000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1048576
                });
            };

            struct tv22 {
                using bigint_t = fixed_bigint<31>;
                static constexpr char tvhex[] = "7fffffff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2147483647
                });
            };

            struct tv23 {
                using bigint_t = fixed_bigint<32>;
                static constexpr char tvhex[] = "80000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2147483648
                });
            };

            struct tv24 {
                using bigint_t = fixed_bigint<32>;
                static constexpr char tvhex[] = "ffffffff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967295
                });
            };

            struct tv25 {
                using bigint_t = fixed_bigint<33>;
                static constexpr char tvhex[] = "0100000003";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    3, 1
                });
            };

            struct tv26 {
                using bigint_t = fixed_bigint<40>;
                static constexpr char tvhex[] = "ffffffffff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967295, 255
                });
            };

            struct tv27 {
                using bigint_t = fixed_bigint<41>;
                static constexpr char tvhex[] = "010000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 256
                });
            };

            struct tv28 {
                using bigint_t = fixed_bigint<41>;
                static constexpr char tvhex[] = "010000000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 256
                });
            };

            struct tv29 {
                using bigint_t = fixed_bigint<41>;
                static constexpr char tvhex[] = "0100000000ff";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    255, 256
                });
            };

            struct tv30 {
                using bigint_t = fixed_bigint<41>;
                static constexpr char tvhex[] = "010000000100";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    256, 256
                });
            };

            struct tv31 {
                using bigint_t = fixed_bigint<48>;
                static constexpr char tvhex[] = "fffffffffffe";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967294, 65535
                });
            };

            struct tv32 {
                using bigint_t = fixed_bigint<49>;
                static constexpr char tvhex[] = "01000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 65536
                });
            };

            struct tv33 {
                using bigint_t = fixed_bigint<49>;
                static constexpr char tvhex[] = "01000000000002";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2, 65536
                });
            };

            struct tv34 {
                using bigint_t = fixed_bigint<56>;
                static constexpr char tvhex[] = "fffffffffffffe";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967294, 16777215
                });
            };

            struct tv35 {
                using bigint_t = fixed_bigint<57>;
                static constexpr char tvhex[] = "0100000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 16777216
                });
            };

            struct tv36 {
                using bigint_t = fixed_bigint<57>;
                static constexpr char tvhex[] = "0100000000000002";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2, 16777216
                });
            };

            struct tv37 {
                using bigint_t = fixed_bigint<64>;
                static constexpr char tvhex[] = "fffffffffffffffd";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967293, 4294967295
                });
            };

            struct tv38 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "010000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 1
                });
            };

            struct tv39 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "010000000000000010";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    16, 0, 1
                });
            };

            struct tv40 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "01000000000000013c";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    316, 0, 1
                });
            };

            struct tv41 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "0100000000f9be5390";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4190000016, 0, 1
                });
            };

            struct tv42 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "0100000000fffffb00";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294966016, 0, 1
                });
            };

            struct tv43 {
                using bigint_t = fixed_bigint<65>;
                static constexpr char tvhex[] = "010000000100000058";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    88, 1, 1
                });
            };

            struct tv44 {
                using bigint_t = fixed_bigint<73>;
                static constexpr char tvhex[] = "01000000000000000002";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2, 0, 256
                });
            };

            struct tv45 {
                using bigint_t = fixed_bigint<80>;
                static constexpr char tvhex[] = "fffffffffffffffffffa";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967290, 4294967295, 65535
                });
            };

            struct tv46 {
                using bigint_t = fixed_bigint<81>;
                static constexpr char tvhex[] = "0100000000000000000018";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    24, 0, 65536
                });
            };

            struct tv47 {
                using bigint_t = fixed_bigint<88>;
                static constexpr char tvhex[] = "fffffffffffffffffffffb";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967291, 4294967295, 16777215
                });
            };

            struct tv48 {
                using bigint_t = fixed_bigint<96>;
                static constexpr char tvhex[] = "fffffffffffffffffffffff9";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967289, 4294967295, 4294967295
                });
            };

            struct tv49 {
                using bigint_t = fixed_bigint<97>;
                static constexpr char tvhex[] = "01000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 1
                });
            };

            struct tv50 {
                using bigint_t = fixed_bigint<97>;
                static constexpr char tvhex[] = "0100000000000000000000001d";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    29, 0, 0, 1
                });
            };

            struct tv51 {
                using bigint_t = fixed_bigint<99>;
                static constexpr char tvhex[] = "07fffffffffffffffffffffff8";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4294967288, 4294967295, 4294967295, 7
                });
            };

            struct tv52 {
                using bigint_t = fixed_bigint<100>;
                static constexpr char tvhex[] = "08000000000000000000000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 0, 0, 8
                });
            };

            struct tv53 {
                using bigint_t = fixed_bigint<101>;
                static constexpr char tvhex[] = "10000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 16
                });
            };

            struct tv54 {
                using bigint_t = fixed_bigint<105>;
                static constexpr char tvhex[] = "0100000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 256
                });
            };

            struct tv55 {
                using bigint_t = fixed_bigint<109>;
                static constexpr char tvhex[] = "1000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 4096
                });
            };

            struct tv56 {
                using bigint_t = fixed_bigint<113>;
                static constexpr char tvhex[] = "010000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 65536
                });
            };

            struct tv57 {
                using bigint_t = fixed_bigint<117>;
                static constexpr char tvhex[] = "100000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 1048576
                });
            };

            struct tv58 {
                using bigint_t = fixed_bigint<121>;
                static constexpr char tvhex[] = "01000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 16777216
                });
            };

            struct tv59 {
                using bigint_t = fixed_bigint<121>;
                static constexpr char tvhex[] = "013cf34b33b593baedd6f0414d6ec8ab";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1299105963, 3990286401, 867537850, 20771659
                });
            };

            struct tv60 {
                using bigint_t = fixed_bigint<125>;
                static constexpr char tvhex[] = "10000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 268435456
                });
            };

            struct tv61 {
                using bigint_t = fixed_bigint<127>;
                static constexpr char tvhex[] = "4de1ea21d193ee84fe7cc49fbec288da";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    3200420058, 4269589663, 3516132996, 1306651169
                });
            };

            struct tv62 {
                using bigint_t = fixed_bigint<128>;
                static constexpr char tvhex[] = "997aa01804b446815f16294d9e09181d";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2651396125, 1595287885, 78923393, 2574950424
                });
            };

            struct tv63 {
                using bigint_t = fixed_bigint<128>;
                static constexpr char tvhex[] = "d5f5990fd834e4a3d689515d4e1fc613";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1310705171, 3599323485, 3627345059, 3589642511
                });
            };

            struct tv64 {
                using bigint_t = fixed_bigint<128>;
                static constexpr char tvhex[] = "f3baf08ddfd3a32c18c05790815053b0";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2169525168, 415258512, 3755189036, 4089114765
                });
            };

            struct tv65 {
                using bigint_t = fixed_bigint<129>;
                static constexpr char tvhex[] = "0100000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 1
                });
            };

            struct tv66 {
                using bigint_t = fixed_bigint<133>;
                static constexpr char tvhex[] = "1000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 16
                });
            };

            struct tv67 {
                using bigint_t = fixed_bigint<137>;
                static constexpr char tvhex[] = "010000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 256
                });
            };

            struct tv68 {
                using bigint_t = fixed_bigint<141>;
                static constexpr char tvhex[] = "100000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 4096
                });
            };

            struct tv69 {
                using bigint_t = fixed_bigint<145>;
                static constexpr char tvhex[] = "01000000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 65536
                });
            };

            struct tv70 {
                using bigint_t = fixed_bigint<149>;
                static constexpr char tvhex[] = "10000000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 1048576
                });
            };

            struct tv71 {
                using bigint_t = fixed_bigint<153>;
                static constexpr char tvhex[] = "0100000000000000000000000000000000000000";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    0, 0, 0, 0, 16777216
                });
            };

            struct tv72 {
                using bigint_t = fixed_bigint<157>;
                static constexpr char tvhex[] = "1000000000000000000000000000000000000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 0, 0, 0, 268435456
                });
            };

            struct tv73 {
                using bigint_t = fixed_bigint<161>;
                static constexpr char tvhex[] = "010000000000000010000000000000000000000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 0, 0, 16, 0, 1
                });
            };

            struct tv74 {
                using bigint_t = fixed_bigint<161>;
                static constexpr char tvhex[] = "010000000100000001000000010000000100000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 1, 1, 1, 1, 1
                });
            };

            struct tv75 {
                using bigint_t = fixed_bigint<193>;
                static constexpr char tvhex[] = "01000000010000000100000001000000010000000100000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 1, 1, 1, 1, 1, 1
                });
            };

            struct tv76 {
                using bigint_t = fixed_bigint<193>;
                static constexpr char tvhex[] = "01000000010000000400000001000000010000000100000002";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2, 1, 1, 1, 4, 1, 1
                });
            };

            struct tv77 {
                using bigint_t = fixed_bigint<228>;
                static constexpr char tvhex[] = "0800000007000000060000000500000004000000030000000200000001";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1, 2, 3, 4, 5, 6, 7, 8
                });
            };

            struct tv78 {
                using bigint_t = fixed_bigint<256>;
                static constexpr char tvhex[] = "80a2a40ae4b869899b4a4213084efea97c2a80b8bfd61599cea2cd02eeaf1570";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    4004451696, 3466775810, 3218478489, 2083160248, 139394729, 2605335059, 3837290889, 2158142474
                });
            };

            struct tv79 {
                using bigint_t = fixed_bigint<256>;
                static constexpr char tvhex[] = "c7ca6fdedf04b5270afbbd876e652d5b5c89105eb631f1bf2c6d04e4c6c2e3db";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    3334661083, 745342180, 3056726463, 1552486494, 1852124507, 184270215, 3741627687, 3351932894
                });
            };

            struct tv80 {
                using bigint_t = fixed_bigint<256>;
                static constexpr char tvhex[] = "eb6ccc27df39f9bc14e1b00651950061fdb7b41cc50bca2aee6d72fa58b84201";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1488470529, 4000150266, 3305884202, 4256674844, 1368719457, 350334982, 3745118652, 3949775911
                });
            };

            struct tv81 {
                using bigint_t = fixed_bigint<256>;
                static constexpr char tvhex[] = "ef9f18a4f74c142af267950669c3f27d0238f0031acc271746a87a49dd8c9f8e";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    3716980622, 1185446473, 449586967, 37285891, 1774449277, 4066874630, 4148958250, 4020181156
                });
            };

            struct tv82 {
                using bigint_t = fixed_bigint<379>;
                static constexpr char tvhex[] = "07951eff810c7f37124df60e07f50ea4ef5dd6db734fce56570c2efd676aa1478c361c054be641c62e3a84a3310c00e6";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    822870246, 775586979, 1273381318, 2352356357, 1735041351, 1460416253, 1934610006, 4015904475, 133500580, 307099150, 2165079863, 127213311
                });
            };

            struct tv83 {
                using bigint_t = fixed_bigint<384>;
                static constexpr char tvhex[] = "94e72427505302eb550a58f552a1dc4d30ab7826e8a2dbab315d6e11c0bb1eb7f719a319c41f4706b65578a648c55dc7";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1220894151, 3059054758, 3290384134, 4145652505, 3233488567, 828206609, 3902987179, 816543782, 1386339405, 1426741493, 1347617515, 2498176039
                });
            };

            struct tv84 {
                using bigint_t = fixed_bigint<384>;
                static constexpr char tvhex[] = "a399441c6d7511f6bdb1bcab4ec6f30dc899635ea71574432d9cac703cd1621cda95aeafb00093a504caf1336ca4945b";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    1822725211, 80408883, 2952827813, 3667242671, 1020355100, 765242480, 2803201091, 3365495646, 1321661197, 3182541995, 1836388854, 2744730652
                });
            };

            struct tv85 {
                using bigint_t = fixed_bigint<509>;
                static constexpr char tvhex[] = "1f5368ae735dd6ba8de6ea2c5e84a65b399e5fb8a89e9e9f71827b27d31c21fd7153645d39ef24c237eeaa06062891ee3f358b420e0fe503d1c9c67f388391e8";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    948146664, 3519661695, 235922691, 1060473666, 103322094, 938387974, 971973826, 1901290589, 3541836285, 1904376615, 2828967583, 966680504, 1585751643, 2380720684, 1935529658, 525559982
                });
            };

            struct tv86 {
                using bigint_t = fixed_bigint<511>;
                static constexpr char tvhex[] = "4060af3d1f75303467e7ed5e4a359c4242a534379f4efff25fe6975347bda02e3aefa4390c2d141b8e0b6321f682c489799384521aa1d1b01b381bb4369c8b0f";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    916228879, 456661940, 446812592, 2039710802, 4135765129, 2383110945, 204280859, 988783673, 1203609646, 1608947539, 2672754674, 1118123063, 1245027394, 1743252830, 527773748, 1080078141
                });
            };

            struct tv87 {
                using bigint_t = fixed_bigint<512>;
                static constexpr char tvhex[] = "b09d14791f79ec3693b6d5745a399e31ff51b5bb7f705db556cd3a0776dfb765a368d83ec765b8614a67dc3d93b9416f1ebd74469ba3abb0641ada5d7fc718b9";
                static constexpr auto tv    = from_hex( tvhex );
                static constexpr auto tvis  = word_array({ // internal state
                    2143754425, 1679481437, 2611194800, 515732550, 2478391663, 1248320573, 3345332321, 2741557310, 1994372965, 1456290311, 2138070453, 4283545019, 1513725489, 2478232948, 528084022, 2963084409
                });
            };
        }
    }

    EOSIO_TEST_BEGIN( bigint_miscellaneous_test )
        using namespace detail;
        using namespace bigint_ser_test_data;

        // First test word_t is 4 bytes since the implementation assumes this
        static_assert( sizeof(word_t) == 4, "word_t must be 4 bytes" );

        // Second that fixed_bigint is the same as bigint<fixed_word_buffer<N>>
        // and that the word buffer is the same size as the number of words.
        static_assert( std::is_same_v< bigint<fixed_word_buffer<1>>, fixed_bigint<1> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<1>>, fixed_bigint<32> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<2>>, fixed_bigint<33> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<2>>, fixed_bigint<64> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<3>>, fixed_bigint<65> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<3>>, fixed_bigint<96> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<4>>, fixed_bigint<97> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<4>>, fixed_bigint<128> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<5>>, fixed_bigint<129> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<5>>, fixed_bigint<160> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<6>>, fixed_bigint<161> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<6>>, fixed_bigint<192> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<7>>, fixed_bigint<193> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<7>>, fixed_bigint<224> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<8>>, fixed_bigint<225> > );
        static_assert( std::is_same_v< bigint<fixed_word_buffer<8>>, fixed_bigint<256> > );

        // Test construction from 32 bit ints
        // Note, the correctness of conversion from hex is tested lower down in this test scope
        {
            using bigint_t = fixed_bigint<32>;
            static_assert( bigint_t() == 0 );
            static_assert( bigint_t() == bigint_t(0) );
            static_assert( bigint_t() == bigint_t()  );
            static_assert( bigint_t().is_zero()     == true  );
            static_assert( bigint_t().is_negative() == false );
            static_assert( bigint_t().is_one()      == false );
            static_assert( bigint_t().size()        == 1     );

            REQUIRE_EQUAL( bigint_t() == 0          , true  )
            REQUIRE_EQUAL( bigint_t() == bigint_t(0), true  )
            REQUIRE_EQUAL( bigint_t() == bigint_t() , true  )
            REQUIRE_EQUAL( bigint_t().is_zero()     , true  )
            REQUIRE_EQUAL( bigint_t().is_negative() , false )
            REQUIRE_EQUAL( bigint_t().is_one()      , false )
            REQUIRE_EQUAL( bigint_t().size()        , 1     )

            static_assert( bigint_t(0) ==  0 );
            static_assert( bigint_t(0) ==  bigint_t(0) );
            static_assert( bigint_t(0).is_zero()     == true  );
            static_assert( bigint_t(0).is_negative() == false );
            static_assert( bigint_t(0).is_one()      == false );

            REQUIRE_EQUAL( bigint_t(0)              , 0           )
            REQUIRE_EQUAL( bigint_t(0)              , bigint_t(0) )
            REQUIRE_EQUAL( bigint_t(0).is_zero()    , true        )
            REQUIRE_EQUAL( bigint_t(0).is_negative(), false       )
            REQUIRE_EQUAL( bigint_t(0).is_one()     , false       )

            static_assert( bigint_t(1) ==  1 );
            static_assert( bigint_t(1) ==  bigint_t(1) );
            static_assert( bigint_t(1).is_zero()     == false );
            static_assert( bigint_t(1).is_negative() == false );
            static_assert( bigint_t(1).is_one()      == true  );

            REQUIRE_EQUAL( bigint_t(1)              , 1           )
            REQUIRE_EQUAL( bigint_t(1)              , bigint_t(1) )
            REQUIRE_EQUAL( bigint_t(1).is_zero()    , false       )
            REQUIRE_EQUAL( bigint_t(1).is_negative(), false       )
            REQUIRE_EQUAL( bigint_t(1).is_one()     , true        )

            static_assert( bigint_t("00000001") == 1 );
            static_assert( bigint_t("00000001") == bigint_t(1) );
            static_assert( bigint_t("00000001").is_zero()     == false );
            static_assert( bigint_t("00000001").is_negative() == false );
            static_assert( bigint_t("00000001").is_one()      == true  );

            REQUIRE_EQUAL( bigint_t("00000001")              , 1           )
            REQUIRE_EQUAL( bigint_t("00000001")              , bigint_t(1) )
            REQUIRE_EQUAL( bigint_t("00000001").is_zero()    , false       )
            REQUIRE_EQUAL( bigint_t("00000001").is_negative(), false       )
            REQUIRE_EQUAL( bigint_t("00000001").is_one()     , true        )

            static_assert( bigint_t(-1)               ==  -1           );
            static_assert( bigint_t(-1)               ==  bigint_t(-1) );
            static_assert( bigint_t(-1).is_zero()     ==  false        );
            static_assert( bigint_t(-1).is_negative() ==  true         );
            static_assert( bigint_t(-1).is_one()      ==  false        );

            REQUIRE_EQUAL( bigint_t(-1)              , -1           )
            REQUIRE_EQUAL( bigint_t(-1)              , bigint_t(-1) )
            REQUIRE_EQUAL( bigint_t(-1).is_zero()    , false        )
            REQUIRE_EQUAL( bigint_t(-1).is_negative(), true         )
            REQUIRE_EQUAL( bigint_t(-1).is_one()     , false        )

            static_assert( -bigint_t(1)                   ==  -1           );
            static_assert( ( -bigint_t(1) )               ==  bigint_t(-1) );
            static_assert( ( -bigint_t(1) ).is_zero()     ==  false        );
            static_assert( ( -bigint_t(1) ).is_negative() ==  true         );
            static_assert( ( -bigint_t(1) ).is_one()      ==  false        );

            REQUIRE_EQUAL( -bigint_t(1)                  , -1           )
            REQUIRE_EQUAL( ( -bigint_t(1) )              , bigint_t(-1) )
            REQUIRE_EQUAL( ( -bigint_t(1) ).is_zero()    , false        )
            REQUIRE_EQUAL( ( -bigint_t(1) ).is_negative(), true         )
            REQUIRE_EQUAL( ( -bigint_t(1) ).is_one()     , false        )

            static_assert( -bigint_t(uint32_t(1UL))                   ==  -1           );
            static_assert( ( -bigint_t(uint32_t(1UL)) )               ==  bigint_t(-1) );
            static_assert( ( -bigint_t(uint32_t(1UL)) ).is_zero()     ==  false        );
            static_assert( ( -bigint_t(uint32_t(1UL)) ).is_negative() ==  true         );
            static_assert( ( -bigint_t(uint32_t(1UL)) ).is_one()      ==  false        );

            REQUIRE_EQUAL( -bigint_t(uint32_t(1UL))                  , -1           )
            REQUIRE_EQUAL( ( -bigint_t(uint32_t(1UL)) )              , bigint_t(-1) )
            REQUIRE_EQUAL( ( -bigint_t(uint32_t(1UL)) ).is_zero()    , false        )
            REQUIRE_EQUAL( ( -bigint_t(uint32_t(1UL)) ).is_negative(), true         )
            REQUIRE_EQUAL( ( -bigint_t(uint32_t(1UL)) ).is_one()     , false        )

            static_assert( -bigint_t(-1)                    ==  1           );
            static_assert( ( -bigint_t(-1 ) )               ==  bigint_t(1) );
            static_assert( ( -bigint_t(-1 ) ).is_zero()     ==  false       );
            static_assert( ( -bigint_t(-1 ) ).is_negative() ==  false       );
            static_assert( ( -bigint_t(-1 ) ).is_one()      ==  true        );

            REQUIRE_EQUAL( -bigint_t(-1)                   , 1           )
            REQUIRE_EQUAL( ( -bigint_t(-1 ) )              , bigint_t(1) )
            REQUIRE_EQUAL( ( -bigint_t(-1 ) ).is_zero()    , false       )
            REQUIRE_EQUAL( ( -bigint_t(-1 ) ).is_negative(), false       )
            REQUIRE_EQUAL( ( -bigint_t(-1 ) ).is_one()     , true        )

            static_assert( bigint_t(-1)               ==  -1           );
            static_assert( bigint_t(-1)               ==  bigint_t(-1) );
            static_assert( bigint_t(-1).is_zero()     ==  false        );
            static_assert( bigint_t(-1).is_negative() ==  true         );

            REQUIRE_EQUAL( bigint_t(-1)              , -1           )
            REQUIRE_EQUAL( bigint_t(-1)              , bigint_t(-1) )
            REQUIRE_EQUAL( bigint_t(-1).is_zero()    , false        )
            REQUIRE_EQUAL( bigint_t(-1).is_negative(), true         )

            static_assert( bigint_t(-1U)                  ==  -1U   );
            static_assert( bigint_t(-1U) != -bigint_t(1U) ==  true  );
            static_assert( bigint_t(-1U).is_zero()        ==  false );
            static_assert( bigint_t(-1U).is_negative()    ==  false );
            static_assert( bigint_t(-1U).is_one()         ==  false );

            REQUIRE_EQUAL( bigint_t(-1U)                 , -1U   )
            REQUIRE_EQUAL( bigint_t(-1U) != -bigint_t(1U), true  )
            REQUIRE_EQUAL( bigint_t(-1U).is_zero()       , false )
            REQUIRE_EQUAL( bigint_t(-1U).is_negative()   , false )
            REQUIRE_EQUAL( bigint_t(-1U).is_one()        , false )

            static_assert( -bigint_t("00000001")                   ==  -1           );
            static_assert( -bigint_t("00000001")                   ==  bigint_t(-1) );
            static_assert( ( -bigint_t("00000001") ).is_zero()     ==  false        );
            static_assert( ( -bigint_t("00000001") ).is_negative() ==  true         );
            static_assert( ( -bigint_t("00000001") ).is_one()      ==  false        );

            REQUIRE_EQUAL( -bigint_t("00000001")                  , -1           )
            REQUIRE_EQUAL( -bigint_t("00000001")                  , bigint_t(-1) )
            REQUIRE_EQUAL( ( -bigint_t("00000001") ).is_zero()    , false        )
            REQUIRE_EQUAL( ( -bigint_t("00000001") ).is_negative(), true         )
            REQUIRE_EQUAL( ( -bigint_t("00000001") ).is_one()     , false        )

            static_assert( bigint_t(0x101010)               ==  0x101010           );
            static_assert( bigint_t(0x101010)               ==  bigint_t(0x101010) );
            static_assert( bigint_t(0x101010).is_zero()     ==  false              );
            static_assert( bigint_t(0x101010).is_negative() ==  false              );
            static_assert( bigint_t(0x101010).is_one()      ==  false              );

            REQUIRE_EQUAL( bigint_t(0x101010)              , 0x101010           )
            REQUIRE_EQUAL( bigint_t(0x101010)              , bigint_t(0x101010) )
            REQUIRE_EQUAL( bigint_t(0x101010).is_zero()    , false              )
            REQUIRE_EQUAL( bigint_t(0x101010).is_negative(), false              )
            REQUIRE_EQUAL( bigint_t(0x101010).is_one()     , false              )

            static_assert( bigint_t(-0x101010)               ==  -0x101010           );
            static_assert( bigint_t(-0x101010)               ==  bigint_t(-0x101010) );
            static_assert( bigint_t(-0x101010).is_zero()     ==  false               );
            static_assert( bigint_t(-0x101010).is_negative() ==  true                );
            static_assert( bigint_t(-0x101010).is_one()      ==  false               );

            // The largest possible value in 32-bit signed integer (2147483647)
            static_assert( bigint_t(2147483647)               ==  2147483647           );
            static_assert( bigint_t(2147483647)               ==  bigint_t(2147483647) );
            static_assert( bigint_t(2147483647).is_zero()     ==  false                );
            static_assert( bigint_t(2147483647).is_negative() ==  false                );
            static_assert( bigint_t(2147483647).is_one()      ==  false                );

            REQUIRE_EQUAL( bigint_t(2147483647)              , 2147483647           )
            REQUIRE_EQUAL( bigint_t(2147483647)              , bigint_t(2147483647) )
            REQUIRE_EQUAL( bigint_t(2147483647).is_zero()    , false                )
            REQUIRE_EQUAL( bigint_t(2147483647).is_negative(), false                )
            REQUIRE_EQUAL( bigint_t(2147483647).is_one()     , false                )

            // The 1 + smallest possible value in 32-bit signed integer (-2147483648 + 1)
            static_assert( bigint_t::invalid_var == -2147483648L, "Expected invalid_var to be -2147483648L" );
            static_assert( bigint_t(int(-2147483647L))               ==  int(-2147483647L)           );
            static_assert( bigint_t(int(-2147483647L))               ==  bigint_t(int(-2147483647L)) );
            static_assert( bigint_t(int(-2147483647L)).is_zero()     ==  false                       );
            static_assert( bigint_t(int(-2147483647L)).is_negative() ==  true                        );
            static_assert( bigint_t(int(-2147483647L)).is_one()      ==  false                       );

            REQUIRE_EQUAL( bigint_t(int(-2147483647L))              , int(-2147483647L)           )
            REQUIRE_EQUAL( bigint_t(int(-2147483647L))              , bigint_t(int(-2147483647L)) )
            REQUIRE_EQUAL( bigint_t(int(-2147483647L)).is_zero()    , false                       )
            REQUIRE_EQUAL( bigint_t(int(-2147483647L)).is_negative(), true                        )
            REQUIRE_EQUAL( bigint_t(int(-2147483647L)).is_one()     , false                       )

            // The largest possible value in 32-bit unsigned integer (4294967295)
            static_assert( bigint_t(4294967295U)               == 4294967295U           );
            static_assert( bigint_t(4294967295U)               == bigint_t(4294967295U) );
            static_assert( bigint_t(4294967295U).is_zero()     == false                 );
            static_assert( bigint_t(4294967295U).is_negative() == false                 );
            static_assert( bigint_t(4294967295U).is_one()      == false                 );

            REQUIRE_EQUAL( bigint_t(4294967295U)              , 4294967295U           )
            REQUIRE_EQUAL( bigint_t(4294967295U)              , bigint_t(4294967295U) )
            REQUIRE_EQUAL( bigint_t(4294967295U).is_zero()    , false                 )
            REQUIRE_EQUAL( bigint_t(4294967295U).is_negative(), false                 )
            REQUIRE_EQUAL( bigint_t(4294967295U).is_one()     , false                 )
        }

        // Test construction from 64 bit ints
        {
            using bigint_t = fixed_bigint<64>;
            // Test internal representation
            // Note, the correctness of conversion from hex is tested lower down in this test scope
            static_assert( bigint_t(0x000000100000FF00LL)  == bigint_t("000000100000FF00") );
            static_assert( bigint_t(0x000000100000FF00ULL) == bigint_t("000000100000FF00") );
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL) , bigint_t("000000100000FF00") )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL), bigint_t("000000100000FF00") )

            static_assert( bigint_t(0) ==  0 );
            static_assert( bigint_t(0) ==  bigint_t(0) );
            static_assert( bigint_t(0).is_zero() ==  true );
            static_assert( bigint_t(0).is_negative() ==  false );
            static_assert( bigint_t(0).is_one() ==  false );

            REQUIRE_EQUAL( bigint_t(0), 0 )
            REQUIRE_EQUAL( bigint_t(0), bigint_t(0) )
            REQUIRE_EQUAL( bigint_t(0).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(0).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0).is_one(), false )

            static_assert( bigint_t(0LL) == 0LL );
            static_assert( bigint_t(0LL) == bigint_t(0LL) );
            static_assert( bigint_t(0LL).is_zero() == true );
            static_assert( bigint_t(0LL).is_negative() == false );
            static_assert( bigint_t(0LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0LL), 0LL )
            REQUIRE_EQUAL( bigint_t(0LL), bigint_t(0LL) )
            REQUIRE_EQUAL( bigint_t(0LL).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(0LL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0LL).is_one(), false )

            static_assert( bigint_t(0U) == 0U );
            static_assert( bigint_t(0U) == bigint_t(0U) );
            static_assert( bigint_t(0U).is_zero() == true );
            static_assert( bigint_t(0U).is_negative() == false );
            static_assert( bigint_t(0U).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0U), 0U )
            REQUIRE_EQUAL( bigint_t(0U), bigint_t(0U) )
            REQUIRE_EQUAL( bigint_t(0U).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(0U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0U).is_one(), false )

            static_assert( bigint_t(0ULL) == 0ULL );
            static_assert( bigint_t(0ULL) == bigint_t(0ULL) );
            static_assert( bigint_t(0ULL).is_zero() == true );
            static_assert( bigint_t(0ULL).is_negative() == false );
            static_assert( bigint_t(0ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0ULL), 0ULL )
            REQUIRE_EQUAL( bigint_t(0ULL), bigint_t(0ULL) )
            REQUIRE_EQUAL( bigint_t(0ULL).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(0ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0ULL).is_one(), false )

            static_assert( bigint_t(1) == 1 );
            static_assert( bigint_t(1) == bigint_t(1) );
            static_assert( bigint_t(1).is_zero() == false );
            static_assert( bigint_t(1).is_negative() == false );
            static_assert( bigint_t(1).is_one() == true );

            REQUIRE_EQUAL( bigint_t(1), 1 )
            REQUIRE_EQUAL( bigint_t(1), bigint_t(1) )
            REQUIRE_EQUAL( bigint_t(1).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(1).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(1).is_one(), true )

            static_assert( bigint_t("0000000000000001") == 1 );
            static_assert( bigint_t("0000000000000001") == bigint_t(1) );
            static_assert( bigint_t("0000000000000001").is_zero() == false );
            static_assert( bigint_t("0000000000000001").is_negative() == false );
            static_assert( bigint_t("0000000000000001").is_one() == true );

            REQUIRE_EQUAL( bigint_t("0000000000000001"), 1 )
            REQUIRE_EQUAL( bigint_t("0000000000000001"), bigint_t(1) )
            REQUIRE_EQUAL( bigint_t("0000000000000001").is_zero(), false )
            REQUIRE_EQUAL( bigint_t("0000000000000001").is_negative(), false )
            REQUIRE_EQUAL( bigint_t("0000000000000001").is_one(), true )

            static_assert( bigint_t(1LL) == 1LL );
            static_assert( bigint_t(1LL) == bigint_t(1LL) );
            static_assert( bigint_t(1LL).is_zero() == false );
            static_assert( bigint_t(1LL).is_negative() == false );
            static_assert( bigint_t(1LL).is_one() == true );

            REQUIRE_EQUAL( bigint_t(1LL), 1LL )
            REQUIRE_EQUAL( bigint_t(1LL), bigint_t(1LL) )
            REQUIRE_EQUAL( bigint_t(1LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(1LL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(1LL).is_one(), true )

            static_assert( bigint_t(1U) == 1U );
            static_assert( bigint_t(1U) == bigint_t(1U) );
            static_assert( bigint_t(1U).is_zero() == false );
            static_assert( bigint_t(1U).is_negative() == false );
            static_assert( bigint_t(1U).is_one() == true );

            REQUIRE_EQUAL( bigint_t(1U), 1U )
            REQUIRE_EQUAL( bigint_t(1U), bigint_t(1U) )
            REQUIRE_EQUAL( bigint_t(1U).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(1U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(1U).is_one(), true )

            static_assert( bigint_t(1ULL) == 1ULL );
            static_assert( bigint_t(1ULL) == bigint_t(1ULL) );
            static_assert( bigint_t(1ULL).is_zero() == false );
            static_assert( bigint_t(1ULL).is_negative() == false );
            static_assert( bigint_t(1ULL).is_one() == true );

            REQUIRE_EQUAL( bigint_t(1ULL), 1ULL )
            REQUIRE_EQUAL( bigint_t(1ULL), bigint_t(1ULL) )
            REQUIRE_EQUAL( bigint_t(1ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(1ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(1ULL).is_one(), true )

            static_assert( bigint_t(2) == 2 );
            static_assert( bigint_t(2) == bigint_t(2) );
            static_assert( bigint_t(2).is_zero() == false );
            static_assert( bigint_t(2).is_negative() == false );
            static_assert( bigint_t(2).is_one() == false );

            REQUIRE_EQUAL( bigint_t(2), 2 )
            REQUIRE_EQUAL( bigint_t(2), bigint_t(2) )
            REQUIRE_EQUAL( bigint_t(2).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(2).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(2).is_one(), false )

            static_assert( bigint_t(2LL) == 2LL );
            static_assert( bigint_t(2LL) == bigint_t(2LL) );
            static_assert( bigint_t(2LL).is_zero() == false );
            static_assert( bigint_t(2LL).is_negative() == false );
            static_assert( bigint_t(2LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(2LL), 2LL )
            REQUIRE_EQUAL( bigint_t(2LL), bigint_t(2LL) )
            REQUIRE_EQUAL( bigint_t(2LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(2LL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(2LL).is_one(), false )

            static_assert( bigint_t(2U) == 2U );
            static_assert( bigint_t(2U) == bigint_t(2U) );
            static_assert( bigint_t(2U).is_zero() == false );
            static_assert( bigint_t(2U).is_negative() == false );
            static_assert( bigint_t(2U).is_one() == false );

            REQUIRE_EQUAL( bigint_t(2U), 2U )
            REQUIRE_EQUAL( bigint_t(2U), bigint_t(2U) )
            REQUIRE_EQUAL( bigint_t(2U).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(2U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(2U).is_one(), false )

            static_assert( bigint_t(2ULL) == 2ULL );
            static_assert( bigint_t(2ULL) == bigint_t(2ULL) );
            static_assert( bigint_t(2ULL).is_zero() == false );
            static_assert( bigint_t(2ULL).is_negative() == false );
            static_assert( bigint_t(2ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(2ULL), 2ULL )
            REQUIRE_EQUAL( bigint_t(2ULL), bigint_t(2ULL) )
            REQUIRE_EQUAL( bigint_t(2ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(2ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(2ULL).is_one(), false )

            static_assert( bigint_t(-0) == -0 );
            static_assert( bigint_t(-0) == bigint_t(-0) );
            static_assert( bigint_t(-0).is_zero() == true );
            static_assert( bigint_t(-0).is_negative() == false );
            static_assert( bigint_t(-0).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0), -0 )
            REQUIRE_EQUAL( bigint_t(-0), bigint_t(-0) )
            REQUIRE_EQUAL( bigint_t(-0).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(-0).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-0).is_one(), false )

            static_assert( bigint_t(-0LL) == -0LL );
            static_assert( bigint_t(-0LL) == bigint_t(-0LL) );
            static_assert( bigint_t(-0LL).is_zero() == true );
            static_assert( bigint_t(-0LL).is_negative() == false );
            static_assert( bigint_t(-0LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0LL), -0LL )
            REQUIRE_EQUAL( bigint_t(-0LL), bigint_t(-0LL) )
            REQUIRE_EQUAL( bigint_t(-0LL).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(-0LL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-0LL).is_one(), false )

            static_assert( bigint_t(-0U) == -0U );
            static_assert( bigint_t(-0U) == bigint_t(-0U) );
            static_assert( bigint_t(-0U).is_zero() == true );
            static_assert( bigint_t(-0U).is_negative() == false );
            static_assert( bigint_t(-0U).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0U), -0U )
            REQUIRE_EQUAL( bigint_t(-0U), bigint_t(-0U) )
            REQUIRE_EQUAL( bigint_t(-0U).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(-0U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-0U).is_one(), false )

            static_assert( bigint_t(-0ULL) == -0ULL );
            static_assert( bigint_t(-0ULL) == bigint_t(-0ULL) );
            static_assert( bigint_t(-0ULL).is_zero() == true );
            static_assert( bigint_t(-0ULL).is_negative() == false );
            static_assert( bigint_t(-0ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0ULL), -0ULL )
            REQUIRE_EQUAL( bigint_t(-0ULL), bigint_t(-0ULL) )
            REQUIRE_EQUAL( bigint_t(-0ULL).is_zero(), true )
            REQUIRE_EQUAL( bigint_t(-0ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-0ULL).is_one(), false )

            static_assert( bigint_t(-1) == -1 );
            static_assert( bigint_t(-1) == bigint_t(-1) );
            static_assert( bigint_t(-1).is_zero() == false );
            static_assert( bigint_t(-1).is_negative() == true );
            static_assert( bigint_t(-1).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-1), -1 )
            REQUIRE_EQUAL( bigint_t(-1), bigint_t(-1) )
            REQUIRE_EQUAL( bigint_t(-1).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-1).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(-1).is_one(), false )

            static_assert( -bigint_t("0000000000000001") == -1 );
            static_assert( -bigint_t("0000000000000001") == bigint_t(-1) );
            static_assert( ( -bigint_t("0000000000000001") ).is_zero() == false );
            static_assert( ( -bigint_t("0000000000000001") ).is_negative() == true );
            static_assert( ( -bigint_t("0000000000000001") ).is_one() == false );

            REQUIRE_EQUAL( -bigint_t("0000000000000001"), -1 )
            REQUIRE_EQUAL( -bigint_t("0000000000000001"), bigint_t(-1) )
            REQUIRE_EQUAL( ( -bigint_t("0000000000000001") ).is_zero(), false )
            REQUIRE_EQUAL( ( -bigint_t("0000000000000001") ).is_negative(), true )
            REQUIRE_EQUAL( ( -bigint_t("0000000000000001") ).is_one(), false )

            static_assert( bigint_t(-1LL) == -1LL );
            static_assert( bigint_t(-1LL) == bigint_t(-1LL) );
            static_assert( bigint_t(-1LL).is_zero() == false );
            static_assert( bigint_t(-1LL).is_negative() == true );
            static_assert( bigint_t(-1LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-1LL), -1LL )
            REQUIRE_EQUAL( bigint_t(-1LL), bigint_t(-1LL) )
            REQUIRE_EQUAL( bigint_t(-1LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-1LL).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(-1LL).is_one(), false )

            static_assert( bigint_t(-1U) == -1U );
            static_assert( bigint_t(-1U) == bigint_t(-1U) );
            static_assert( bigint_t(-1U).is_zero() == false );
            static_assert( bigint_t(-1U).is_negative() == false );
            static_assert( bigint_t(-1U).is_one() == false ); // max uint32_t

            REQUIRE_EQUAL( bigint_t(-1U), -1U )
            REQUIRE_EQUAL( bigint_t(-1U), bigint_t(-1U) )
            REQUIRE_EQUAL( bigint_t(-1U).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-1U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-1U).is_one(), false ) // max uint32_t

            static_assert( bigint_t(-1ULL) == -1ULL );
            static_assert( bigint_t(-1ULL) == bigint_t(-1ULL) );
            static_assert( bigint_t(-1ULL).is_zero() == false );
            static_assert( bigint_t(-1ULL).is_negative() == false );
            static_assert( bigint_t(-1ULL).is_one() == false ); // max uint64_t

            REQUIRE_EQUAL( bigint_t(-1ULL), -1ULL )
            REQUIRE_EQUAL( bigint_t(-1ULL), bigint_t(-1ULL) )
            REQUIRE_EQUAL( bigint_t(-1ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-1ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-1ULL).is_one(), false ) // max uint64_t

            static_assert( bigint_t(-2) == -2 );
            static_assert( bigint_t(-2) == bigint_t(-2) );
            static_assert( bigint_t(-2).is_zero() == false );
            static_assert( bigint_t(-2).is_negative() == true );
            static_assert( bigint_t(-2).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-2), -2 )
            REQUIRE_EQUAL( bigint_t(-2), bigint_t(-2) )
            REQUIRE_EQUAL( bigint_t(-2).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-2).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(-2).is_one(), false )

            static_assert( bigint_t(-2LL) == -2LL );
            static_assert( bigint_t(-2LL) == bigint_t(-2LL) );
            static_assert( bigint_t(-2LL).is_zero() == false );
            static_assert( bigint_t(-2LL).is_negative() == true );
            static_assert( bigint_t(-2LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-2LL), -2LL );
            REQUIRE_EQUAL( bigint_t(-2LL), bigint_t(-2LL) )
            REQUIRE_EQUAL( bigint_t(-2LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-2LL).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(-2LL).is_one(), false )

            static_assert( bigint_t(-2U) == -2U );
            static_assert( bigint_t(-2U) == bigint_t(-2U) );
            static_assert( bigint_t(-2U).is_zero() == false );
            static_assert( bigint_t(-2U).is_negative() == false );
            static_assert( bigint_t(-2U).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-2U), -2U );
            REQUIRE_EQUAL( bigint_t(-2U), bigint_t(-2U) )
            REQUIRE_EQUAL( bigint_t(-2U).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-2U).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-2U).is_one(), false )

            static_assert( bigint_t(-2ULL) == -2ULL );
            static_assert( bigint_t(-2ULL) == bigint_t(-2ULL) );
            static_assert( bigint_t(-2ULL).is_zero() == false );
            static_assert( bigint_t(-2ULL).is_negative() == false );
            static_assert( bigint_t(-2ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-2ULL), -2ULL )
            REQUIRE_EQUAL( bigint_t(-2ULL), bigint_t(-2ULL) )
            REQUIRE_EQUAL( bigint_t(-2ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-2ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-2ULL).is_one(), false )

            static_assert( bigint_t(0x000000100000FF00LL) == 0x000000100000FF00LL );
            static_assert( bigint_t(0x000000100000FF00LL) == bigint_t(0x000000100000FF00LL) );
            static_assert( bigint_t(0x000000100000FF00LL).is_zero() == false );
            static_assert( bigint_t(0x000000100000FF00LL).is_negative() == false );
            static_assert( bigint_t(0x000000100000FF00LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL), 0x000000100000FF00LL )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL), bigint_t(0x000000100000FF00LL) )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00LL).is_one(), false )

            static_assert( bigint_t(-0x000000100000FF00LL) == -0x000000100000FF00LL );
            static_assert( bigint_t(-0x000000100000FF00LL) == bigint_t(-0x000000100000FF00LL) );
            static_assert( bigint_t(-0x000000100000FF00LL).is_zero() == false );
            static_assert( bigint_t(-0x000000100000FF00LL).is_negative() == true );
            static_assert( bigint_t(-0x000000100000FF00LL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00LL), -0x000000100000FF00LL )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00LL), bigint_t(-0x000000100000FF00LL) )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00LL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00LL).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00LL).is_one(), false )

            static_assert( bigint_t(0x000000100000FF00ULL) == 0x000000100000FF00ULL );
            static_assert( bigint_t(0x000000100000FF00ULL) == bigint_t(0x000000100000FF00ULL) );
            static_assert( bigint_t(0x000000100000FF00ULL).is_zero() == false );
            static_assert( bigint_t(0x000000100000FF00ULL).is_negative() == false );
            static_assert( bigint_t(0x000000100000FF00ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL), 0x000000100000FF00ULL )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL), bigint_t(0x000000100000FF00ULL) )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0x000000100000FF00ULL).is_one(), false )

            static_assert( bigint_t(-0x000000100000FF00ULL) == -0x000000100000FF00ULL );
            static_assert( bigint_t(-0x000000100000FF00ULL) == bigint_t(-0x000000100000FF00ULL) );
            static_assert( bigint_t(-0x000000100000FF00ULL).is_zero() == false );
            static_assert( bigint_t(-0x000000100000FF00ULL).is_negative() == false );
            static_assert( bigint_t(-0x000000100000FF00ULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00ULL), -0x000000100000FF00ULL )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00ULL), bigint_t(-0x000000100000FF00ULL) )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00ULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00ULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(-0x000000100000FF00ULL).is_one(), false )

            // The largest possible value in 64-bit signed integer (9223372036854775807)
            static_assert( bigint_t(0x7FFFFFFFFFFFFFFFLL) == 0x7FFFFFFFFFFFFFFFLL );
            static_assert( bigint_t(0x7FFFFFFFFFFFFFFFLL) == bigint_t(0x7FFFFFFFFFFFFFFFLL) );
            static_assert( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_zero() == false );
            static_assert( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_negative() == false );
            static_assert( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0x7FFFFFFFFFFFFFFFLL), 0x7FFFFFFFFFFFFFFFLL )
            REQUIRE_EQUAL( bigint_t(0x7FFFFFFFFFFFFFFFLL), bigint_t(0x7FFFFFFFFFFFFFFFLL) )
            REQUIRE_EQUAL( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0x7FFFFFFFFFFFFFFFLL).is_one(), false )

            // The smallest possible value in 64-bit signed integer (-9223372036854775808)
            static_assert( bigint_t(int64_t(0x8000000000000000LL)) == int64_t(0x8000000000000000LL) );
            static_assert( bigint_t(int64_t(0x8000000000000000LL)) == bigint_t(int64_t(0x8000000000000000LL)) );
            static_assert( bigint_t(int64_t(0x8000000000000000LL)).is_zero() == false );
            static_assert( bigint_t(int64_t(0x8000000000000000LL)).is_negative() == true );
            static_assert( bigint_t(int64_t(0x8000000000000000LL)).is_one() == false );

            REQUIRE_EQUAL( bigint_t(int64_t(0x8000000000000000LL)), int64_t(0x8000000000000000LL) )
            REQUIRE_EQUAL( bigint_t(int64_t(0x8000000000000000LL)), bigint_t(int64_t(0x8000000000000000LL)) )
            REQUIRE_EQUAL( bigint_t(int64_t(0x8000000000000000LL)).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(int64_t(0x8000000000000000LL)).is_negative(), true )
            REQUIRE_EQUAL( bigint_t(int64_t(0x8000000000000000LL)).is_one(), false )

            // The largest possible value in 64-bit unsigned integer (18446744073709551615)
            static_assert( bigint_t(0xFFFFFFFFFFFFFFFFULL) == 0xFFFFFFFFFFFFFFFFULL );
            static_assert( bigint_t(0xFFFFFFFFFFFFFFFFULL) == bigint_t(0xFFFFFFFFFFFFFFFFULL) );
            static_assert( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_zero() == false );
            static_assert( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_negative() == false );
            static_assert( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_one() == false );

            REQUIRE_EQUAL( bigint_t(0xFFFFFFFFFFFFFFFFULL), 0xFFFFFFFFFFFFFFFFULL )
            REQUIRE_EQUAL( bigint_t(0xFFFFFFFFFFFFFFFFULL), bigint_t(0xFFFFFFFFFFFFFFFFULL) )
            REQUIRE_EQUAL( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_zero(), false )
            REQUIRE_EQUAL( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_negative(), false )
            REQUIRE_EQUAL( bigint_t(0xFFFFFFFFFFFFFFFFULL).is_one(), false )
        }

        // Comparison tests
        {
            static_assert( ( fixed_bigint<32>(10) == 10 ) == true );
            static_assert( ( fixed_bigint<32>(10) == fixed_bigint<32>(10) ) == true );
            static_assert( ( 10 == fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) == 11 ) == false );
            static_assert( ( 11 == fixed_bigint<32>(10) ) == false );
            static_assert( ( fixed_bigint<32>(10) == fixed_bigint<32>(11) ) == false );
            static_assert( ( fixed_bigint<32>(10) == -10 ) == false );
            static_assert( ( -10 == fixed_bigint<32>(10) ) == false );
            static_assert( ( fixed_bigint<32>(10) == fixed_bigint<32>(-10) ) == false );

            REQUIRE_EQUAL( fixed_bigint<32>(10) == 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) == fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( 10 == fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) == 11, false )
            REQUIRE_EQUAL( 11 == fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) == fixed_bigint<32>(11), false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) == -10, false )
            REQUIRE_EQUAL( -10 == fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) == fixed_bigint<32>(-10), false )

            static_assert( ( fixed_bigint<32>(10U) == 10U ) == true );
            static_assert( ( fixed_bigint<32>(10U) == fixed_bigint<32>(10U) ) == true );
            static_assert( ( 10U == fixed_bigint<32>(10U) ) == true  );  // unsigned overload
            static_assert( ( fixed_bigint<32>(10U) == 11U ) == false );
            static_assert( ( 11U == fixed_bigint<32>(10U) ) == false ); // unsigned overload
            static_assert( ( fixed_bigint<32>(10U) == fixed_bigint<32>(11U) ) == false );

            REQUIRE_EQUAL( fixed_bigint<32>(10U) == 10U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) == fixed_bigint<32>(10U), true )
            REQUIRE_EQUAL( 10U == fixed_bigint<32>(10U), true ) // unsigned overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) == 11U, false )
            REQUIRE_EQUAL( 11U == fixed_bigint<32>(10U), false ) // unsigned overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) == fixed_bigint<32>(11U), false )

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL == fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == 0x0000FFFF00010000LL ) == false );
            static_assert( ( 0x0000FFFF00010000LL == fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(0x0000FFFF00010000LL) ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == -0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( -0x0000FFFF0000FFFFLL == fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false );

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL == fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == 0x0000FFFF00010000LL, false )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL == fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(0x0000FFFF00010000LL), false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == -0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL == fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) == fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false )

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == 0x0000FFFF0000FFFFULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL == fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == 0x0000FFFF00010000ULL ) == false );
            static_assert( ( 0x0000FFFF00010000ULL == fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == fixed_bigint<64>(0x0000FFFF00010000ULL) ) == false );

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == 0x0000FFFF0000FFFFULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == fixed_bigint<64>(0x0000FFFF0000FFFFULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL == fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == 0x0000FFFF00010000ULL, false )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL == fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) == fixed_bigint<64>(0x0000FFFF00010000ULL), false )

            static_assert( ( fixed_bigint<32>(10) != 11 ) == true );
            static_assert( ( fixed_bigint<32>(10) != fixed_bigint<32>(11) ) == true );
            static_assert( ( 11 != fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(11) != 10 ) == true );
            static_assert( ( 10 != fixed_bigint<32>(11) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) != fixed_bigint<32>(10) ) == false );
            static_assert( ( fixed_bigint<32>(10) != 10 ) == false );
            static_assert( ( 10 != fixed_bigint<32>(10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(10) != -10 ) == true );
            static_assert( ( -10 != fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) != fixed_bigint<32>(-10) ) == true );

            REQUIRE_EQUAL( fixed_bigint<32>(10) != 11, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) != fixed_bigint<32>(11), true )
            REQUIRE_EQUAL( 11 != fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11) != 10, true )
            REQUIRE_EQUAL( 10 != fixed_bigint<32>(11), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) != 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) != fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( 10 != fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) != -10, true )
            REQUIRE_EQUAL( -10 != fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) != fixed_bigint<32>(-10), true )

            static_assert( ( fixed_bigint<32>(10U) != 11U ) == true );
            static_assert( ( fixed_bigint<32>(10U) != fixed_bigint<32>(11U) ) == true );
            static_assert( ( 11U != fixed_bigint<32>(10U) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(11U) != 10U ) == true );
            static_assert( ( 10U != fixed_bigint<32>(11U) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10U) != fixed_bigint<32>(10U) ) == false );
            static_assert( ( fixed_bigint<32>(10U) != 10U ) == false );
            static_assert( ( 10U != fixed_bigint<32>(10U) ) == false ); // int overload

            REQUIRE_EQUAL( fixed_bigint<32>(10U) != 11U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) != fixed_bigint<32>(11U), true )
            REQUIRE_EQUAL( 11U != fixed_bigint<32>(10U), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11U) != 10U, true )
            REQUIRE_EQUAL( 10U != fixed_bigint<32>(11U), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) != 10U, false )
            REQUIRE_EQUAL( 10U != fixed_bigint<32>(10U), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) != fixed_bigint<32>(10U), false )

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != 0x0000FFFF00010000LL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(0x0000FFFF00010000LL) ) == true );
            static_assert( ( 0x0000FFFF00010000LL != fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != -0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( -0x0000FFFF0000FFFFLL != fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFLL != fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL != fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != 0x0000FFFF00010000LL, true )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL != fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(0x0000FFFF00010000LL), true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != -0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) != fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL != fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != 0x0000FFFF00010000ULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != fixed_bigint<64>(0x0000FFFF00010000ULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL != fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != 0x0000FFFF0000FFFFULL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFULL != fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // unsigned long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != 0x0000FFFF0000FFFFULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != fixed_bigint<64>(0x0000FFFF0000FFFFULL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL != fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != 0x0000FFFF00010000ULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) != fixed_bigint<64>(0x0000FFFF00010000ULL), true )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL != fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // unsigned long long overload

            static_assert( ( fixed_bigint<32>(10) < 11 ) == true );
            static_assert( ( fixed_bigint<32>(10) < fixed_bigint<32>(11) ) == true );
            static_assert( ( 10 < fixed_bigint<32>(11) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(-10) < 10 ) == true );
            static_assert( ( fixed_bigint<32>(-10) < fixed_bigint<32>(10) ) == true );
            static_assert( ( -10 < fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) < 10 ) == false );
            static_assert( ( fixed_bigint<32>(10) < fixed_bigint<32>(10) ) == false );
            static_assert( ( 10 < fixed_bigint<32>(10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(10) < -10 ) == false );
            static_assert( ( fixed_bigint<32>(10) < fixed_bigint<32>(-10) ) == false );
            static_assert( ( 10 < fixed_bigint<32>(-10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-10) < -10 ) == false );
            static_assert( ( fixed_bigint<32>(-10) < fixed_bigint<32>(-10) ) == false );
            static_assert( ( -10 < fixed_bigint<32>(-10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-10) < -11 ) == false );
            static_assert( ( fixed_bigint<32>(-10) < fixed_bigint<32>(-11) ) == false );
            static_assert( ( -10 < fixed_bigint<32>(-11) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-11) < -10 ) == true );
            static_assert( ( fixed_bigint<32>(-11) < fixed_bigint<32>(-10) ) == true );
            static_assert( ( -11 < fixed_bigint<32>(-10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(11) < 10 ) == false );
            static_assert( ( fixed_bigint<32>(11) < fixed_bigint<32>(10) ) == false );
            static_assert( ( 11 < fixed_bigint<32>(10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-11) < 10 ) == true );
            static_assert( ( fixed_bigint<32>(-11) < fixed_bigint<32>(10) ) == true );
            static_assert( ( -11 < fixed_bigint<32>(10) ) == true ); // int overload

            REQUIRE_EQUAL( fixed_bigint<32>(10) < 11, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) < fixed_bigint<32>(11), true );
            REQUIRE_EQUAL( 10 < fixed_bigint<32>(11), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < fixed_bigint<32>(10), true );
            REQUIRE_EQUAL( -10 < fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) < 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) < fixed_bigint<32>(10), false );
            REQUIRE_EQUAL( 10 < fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) < -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) < fixed_bigint<32>(-10), false );
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < fixed_bigint<32>(-10), false );
            REQUIRE_EQUAL( -10 < fixed_bigint<32>(-10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11) < 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(11) < fixed_bigint<32>(10), false );
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < -11, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) < fixed_bigint<32>(-11), false );
            REQUIRE_EQUAL( -10 < fixed_bigint<32>(-11), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) < -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) < fixed_bigint<32>(-10), true );
            REQUIRE_EQUAL( -11 < fixed_bigint<32>(-10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) < 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) < fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( -11 < fixed_bigint<32>(10), true ) // int overload

            static_assert( ( fixed_bigint<32>(10U) < 11U ) == true );
            static_assert( ( fixed_bigint<32>(10U) < fixed_bigint<32>(11U) ) == true );
            static_assert( ( 10U < fixed_bigint<32>(11U) ) == true ); // unsigned int overload
            static_assert( ( fixed_bigint<32>(10U) < 10U ) == false );
            static_assert( ( fixed_bigint<32>(10U) < fixed_bigint<32>(10U) ) == false );
            static_assert( ( 10U < fixed_bigint<32>(10U) ) == false ); // unsigned int overload
            static_assert( ( fixed_bigint<32>(11U) < 10U ) == false );
            static_assert( ( fixed_bigint<32>(11U) < fixed_bigint<32>(10U) ) == false );
            static_assert( ( 11U < fixed_bigint<32>(10U) ) == false ); // unsigned int overload

            REQUIRE_EQUAL( fixed_bigint<32>(10U) < 11U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) < fixed_bigint<32>(11U), true );
            REQUIRE_EQUAL( 10U < fixed_bigint<32>(11U), true ) // unsigned int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) < 10U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) < fixed_bigint<32>(10U), false );
            REQUIRE_EQUAL( 10U < fixed_bigint<32>(10U), false ) // unsigned int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11U) < 10U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(11U) < fixed_bigint<32>(10U), false );
            REQUIRE_EQUAL( 11U < fixed_bigint<32>(10U), false ) // unsigned int overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < 0x0000FFFF00010000LL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF00010000LL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF00010000LL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < -0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < -0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( -0x0000FFFF0000FFFFLL < fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( -0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) < 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF00010000LL < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF00010000LL) < 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF00010000LL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( -0x0000FFFF00010000LL < fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < 0x0000FFFF00010000LL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF00010000LL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF00010000LL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < -0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) < fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL < fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < -0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL < fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL < fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) < 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL < fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF00010000LL) < 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF00010000LL) < fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( -0x0000FFFF00010000LL < fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < 0x0000FFFF00010000ULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < fixed_bigint<64>(0x0000FFFF00010000ULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL < fixed_bigint<64>(0x0000FFFF00010000ULL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < 0x0000FFFF0000FFFFULL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFULL < fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) < 0x0000FFFF0000FFFFULL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) < fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false );
            static_assert( ( 0x0000FFFF00010000ULL < fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < 0x0000FFFF00010000ULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < fixed_bigint<64>(0x0000FFFF00010000ULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL < fixed_bigint<64>(0x0000FFFF00010000ULL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < 0x0000FFFF0000FFFFULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) < fixed_bigint<64>(0x0000FFFF0000FFFFULL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL < fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) < 0x0000FFFF0000FFFFULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) < fixed_bigint<64>(0x0000FFFF0000FFFFULL), false )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL < fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // long long overload

            static_assert( ( fixed_bigint<32>(10) <= 10 ) == true );
            static_assert( ( fixed_bigint<32>(10) <= fixed_bigint<32>(10) ) == true );
            static_assert( ( 10 <= fixed_bigint<32>(10) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(10) <= 11 ) == true );
            static_assert( ( fixed_bigint<32>(10) <= fixed_bigint<32>(11) ) == true );
            static_assert( ( 10 <= fixed_bigint<32>(11) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(11) <= 10 ) == false );
            static_assert( ( fixed_bigint<32>(11) <= fixed_bigint<32>(10) ) == false );
            static_assert( ( 11 <= fixed_bigint<32>(10) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(10) <= -10 ) == false );
            static_assert( ( fixed_bigint<32>(10) <= fixed_bigint<32>(-10) ) == false );
            static_assert( ( 10 <= fixed_bigint<32>(-10) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(-10) <= 10 ) == true );
            static_assert( ( fixed_bigint<32>(-10) <= fixed_bigint<32>(10) ) == true );
            static_assert( ( -10 <= fixed_bigint<32>(10) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(-10) <= -11 ) == false );
            static_assert( ( fixed_bigint<32>(-10) <= fixed_bigint<32>(-11) ) == false );
            static_assert( ( -10 <= fixed_bigint<32>(-11) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(-10) <= -10 ) == true );
            static_assert( ( fixed_bigint<32>(-10) <= fixed_bigint<32>(-10) ) == true );
            static_assert( ( -10 <= fixed_bigint<32>(-10) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(-11) <= -10 ) == true );
            static_assert( ( fixed_bigint<32>(-11) <= fixed_bigint<32>(-10) ) == true );
            static_assert( ( -11 <= fixed_bigint<32>(-10) ) == true ); // long overload

            REQUIRE_EQUAL( fixed_bigint<32>(10) <= 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) <= fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( 10 <= fixed_bigint<32>(10), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) <= 11, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) <= fixed_bigint<32>(11), true )
            REQUIRE_EQUAL( 10 <= fixed_bigint<32>(11), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(11) <= 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(11) <= fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( 11 <= fixed_bigint<32>(10), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) <= -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) <= fixed_bigint<32>(-10), false )
            REQUIRE_EQUAL( 10 <= fixed_bigint<32>(-10), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( -10 <= fixed_bigint<32>(10), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= -11, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= fixed_bigint<32>(-11), false )
            REQUIRE_EQUAL( -10 <= fixed_bigint<32>(-11), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) <= fixed_bigint<32>(-10), true )
            REQUIRE_EQUAL( -10 <= fixed_bigint<32>(-10), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) <= -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) <= fixed_bigint<32>(-10), true )
            REQUIRE_EQUAL( -11 <= fixed_bigint<32>(-10), true ) // long overload

            static_assert( ( fixed_bigint<32>(10U) <= 10U ) == true );
            static_assert( ( fixed_bigint<32>(10U) <= fixed_bigint<32>(10U) ) == true );
            static_assert( ( 10U <= fixed_bigint<32>(10U) ) == true ); // unsigned long overload
            static_assert( ( fixed_bigint<32>(10U) <= 11U ) == true );
            static_assert( ( fixed_bigint<32>(10U) <= fixed_bigint<32>(11U) ) == true );
            static_assert( ( 10U <= fixed_bigint<32>(11U) ) == true ); // unsigned long overload
            static_assert( ( fixed_bigint<32>(11U) <= 10U ) == false );
            static_assert( ( fixed_bigint<32>(11U) <= fixed_bigint<32>(10U) ) == false );
            static_assert( ( 11U <= fixed_bigint<32>(10U) ) == false ); // unsigned long overload

            REQUIRE_EQUAL( fixed_bigint<32>(10U) <= 10U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) <= fixed_bigint<32>(10U), true )
            REQUIRE_EQUAL( 10U <= fixed_bigint<32>(10U), true ) // unsigned long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) <= 11U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) <= fixed_bigint<32>(11U), true )
            REQUIRE_EQUAL( 10U <= fixed_bigint<32>(11U), true ) // unsigned long overload
            REQUIRE_EQUAL( fixed_bigint<32>(11U) <= 10U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(11U) <= fixed_bigint<32>(10U), false )
            REQUIRE_EQUAL( 11U <= fixed_bigint<32>(10U), false ) // unsigned long overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= 0x0000FFFF00010000LL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF00010000LL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF00010000LL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) <= 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF00010000LL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= 0x0000FFFF00010000LL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= -0x0000FFFF0000FFFFLL) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) <= 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( -0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= 0x0000FFFF00010000LL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF00010000LL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF00010000LL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) <= 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= -0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL <= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) <= 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL <= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= 0x0000FFFF0000FFFFULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL <= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= 0x0000FFFF00010000ULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= fixed_bigint<64>(0x0000FFFF00010000ULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL <= fixed_bigint<64>(0x0000FFFF00010000ULL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) <= 0x0000FFFF0000FFFFULL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) <= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false );
            static_assert( ( 0x0000FFFF00010000ULL <= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == false ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= 0x0000FFFF0000FFFFULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL <= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= 0x0000FFFF00010000ULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) <= fixed_bigint<64>(0x0000FFFF00010000ULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL <= fixed_bigint<64>(0x0000FFFF00010000ULL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) <= 0x0000FFFF0000FFFFULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) <= fixed_bigint<64>(0x0000FFFF0000FFFFULL), false )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL <= fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // long long overload

            static_assert( ( fixed_bigint<32>(10) > 9 ) == true );
            static_assert( ( fixed_bigint<32>(10) > fixed_bigint<32>(9) ) == true );
            static_assert( ( 10 > fixed_bigint<32>(9) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(10) > 10 ) == false );
            static_assert( ( fixed_bigint<32>(10) > fixed_bigint<32>(10) ) == false );
            static_assert( ( 10 > fixed_bigint<32>(10) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(10) > 11 ) == false );
            static_assert( ( fixed_bigint<32>(10) > fixed_bigint<32>(11) ) == false );
            static_assert( ( 10 > fixed_bigint<32>(11) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(11) > 10 ) == true );
            static_assert( ( fixed_bigint<32>(11) > fixed_bigint<32>(10) ) == true );
            static_assert( ( 11 > fixed_bigint<32>(10) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(10) > -10) == true );
            static_assert( ( fixed_bigint<32>(10) > fixed_bigint<32>(-10) ) == true );
            static_assert( ( 10 > fixed_bigint<32>(-10) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(-10) > -10 ) == false );
            static_assert( ( fixed_bigint<32>(-10) > fixed_bigint<32>(-10) ) == false );
            static_assert( ( -10 > fixed_bigint<32>(-10) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(-10) > 10 ) == false );
            static_assert( ( fixed_bigint<32>(-10) > fixed_bigint<32>(10) ) == false );
            static_assert( ( -10 > fixed_bigint<32>(10) ) == false ); // long overload
            static_assert( ( fixed_bigint<32>(-10) > -11 ) == true );
            static_assert( ( fixed_bigint<32>(-10) > fixed_bigint<32>(-11) ) == true );
            static_assert( ( -10 > fixed_bigint<32>(-11) ) == true ); // long overload
            static_assert( ( fixed_bigint<32>(-11) > -10 ) == false );
            static_assert( ( fixed_bigint<32>(-11) > fixed_bigint<32>(-10) ) == false );
            static_assert( ( -11 > fixed_bigint<32>(-10) ) == false ); // long overload

            REQUIRE_EQUAL( fixed_bigint<32>(10) > 9, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) > fixed_bigint<32>(9), true )
            REQUIRE_EQUAL( 10 > fixed_bigint<32>(9), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) > 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) > fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( 10 > fixed_bigint<32>(10), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) > 11, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) > fixed_bigint<32>(11), false )
            REQUIRE_EQUAL( 10 > fixed_bigint<32>(11), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(11) > 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(11) > fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( 11 > fixed_bigint<32>(10), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) > -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) > fixed_bigint<32>(-10), true )
            REQUIRE_EQUAL( 10 > fixed_bigint<32>(-10), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > fixed_bigint<32>(-10), false )
            REQUIRE_EQUAL( -10 > fixed_bigint<32>(-10), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( -10 > fixed_bigint<32>(10), false ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > -11, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) > fixed_bigint<32>(-11), true )
            REQUIRE_EQUAL( -10 > fixed_bigint<32>(-11), true ) // long overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) > -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) > fixed_bigint<32>(-10), false )
            REQUIRE_EQUAL( -11 > fixed_bigint<32>(-10), false ) // long overload

            static_assert( ( fixed_bigint<32>(10U) > 9U ) == true );
            static_assert( ( fixed_bigint<32>(10U) > fixed_bigint<32>(9U) ) == true );
            static_assert( ( 10U > fixed_bigint<32>(9U) ) == true ); // unsigned long overload
            static_assert( ( fixed_bigint<32>(10U) > 10U ) == false );
            static_assert( ( fixed_bigint<32>(10U) > fixed_bigint<32>(10U) ) == false );
            static_assert( ( 10U > fixed_bigint<32>(10U) ) == false ); // unsigned long overload
            static_assert( ( fixed_bigint<32>(10U) > 11U ) == false );
            static_assert( ( fixed_bigint<32>(10U) > fixed_bigint<32>(11U) ) == false );
            static_assert( ( 10U > fixed_bigint<32>(11U) ) == false ); // unsigned long overload
            static_assert( ( fixed_bigint<32>(11U) > 10U ) == true );
            static_assert( ( fixed_bigint<32>(11U) > fixed_bigint<32>(10U) ) == true );
            static_assert( ( 11U > fixed_bigint<32>(10U) ) == true ); // unsigned long overload

            REQUIRE_EQUAL( fixed_bigint<32>(10U) > 9U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) > fixed_bigint<32>(9U), true )
            REQUIRE_EQUAL( 10U > fixed_bigint<32>(9U), true ) // unsigned long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) > 10U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) > fixed_bigint<32>(10U), false )
            REQUIRE_EQUAL( 10U > fixed_bigint<32>(10U), false ) // unsigned long overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) > 11U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) > fixed_bigint<32>(11U), false )
            REQUIRE_EQUAL( 10U > fixed_bigint<32>(11U), false ) // unsigned long overload
            REQUIRE_EQUAL( fixed_bigint<32>(11U) > 10U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(11U) > fixed_bigint<32>(10U), true )
            REQUIRE_EQUAL( 11U > fixed_bigint<32>(10U), true ) // unsigned long overload

            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFELL) == true );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFELL)) == true );
            static_assert( (0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFELL)) == true ); // long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFFLL) == false );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) ==  false );
            static_assert( (0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) == false ); // long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF00010000LL) == false );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF00010000LL)) == false );
            static_assert( (0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF00010000LL)) == false ); // long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF00010000LL) > 0x0000FFFF0000FFFFLL) == true );
            static_assert( (fixed_bigint<64>(0x0000FFFF00010000LL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) ==  true );
            static_assert( (0x0000FFFF00010000LL > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) == true ); // long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > -0x0000FFFF0000FFFFLL) == true );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(-0x0000FFFF0000FFFFLL)) ==  true );
            static_assert( (0x0000FFFF0000FFFFLL > fixed_bigint<64>(-0x0000FFFF0000FFFFLL)) == true ); // long long overload
            static_assert( (fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > -0x0000FFFF0000FFFFLL) == false );
            static_assert( (fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > fixed_bigint<64>(-0x0000FFFF0000FFFFLL)) ==  false );
            static_assert( (-0x0000FFFF0000FFFFLL > fixed_bigint<64>(-0x0000FFFF0000FFFFLL)) == false ); // long long overload
            static_assert( (fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFFLL) == false );
            static_assert( (fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) ==  false );
            static_assert( (-0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFFLL)) == false ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFELL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFELL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFELL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > 0x0000FFFF00010000LL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF00010000LL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF00010000LL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) > 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL > fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > -0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) > fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL > fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > -0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL > fixed_bigint<64>(-0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) > fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL > fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload

            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF0000FFFEULL) == true );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF0000FFFEULL)) == true );
            static_assert( (0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF0000FFFEULL)) == true ); // unsigned long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF0000FFFFULL) == false );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF0000FFFFULL)) == false );
            static_assert( (0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF0000FFFFULL)) == false ); // unsigned long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF00010000ULL) == false );
            static_assert( (fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF00010000ULL)) == false );
            static_assert( (0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF00010000ULL)) == false ); // unsigned long long overload
            static_assert( (fixed_bigint<64>(0x0000FFFF00010000ULL) > 0x0000FFFF0000FFFFULL) == true );
            static_assert( (fixed_bigint<64>(0x0000FFFF00010000ULL) > fixed_bigint<64>(0x0000FFFF0000FFFFULL)) == true );
            static_assert( (0x0000FFFF00010000ULL > fixed_bigint<64>(0x0000FFFF0000FFFFULL)) == true ); // unsigned long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF0000FFFEULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF0000FFFEULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF0000FFFEULL), true ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF0000FFFFULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF0000FFFFULL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF0000FFFFULL), false ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > 0x0000FFFF00010000ULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) > fixed_bigint<64>(0x0000FFFF00010000ULL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL > fixed_bigint<64>(0x0000FFFF00010000ULL), false ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) > 0x0000FFFF0000FFFFULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) > fixed_bigint<64>(0x0000FFFF0000FFFFULL), true )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL > fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // unsigned long long overload

            static_assert( ( fixed_bigint<32>(10) >= 9 ) == true );
            static_assert( ( fixed_bigint<32>(10) >= fixed_bigint<32>(9) ) == true );
            static_assert( ( 10 >= fixed_bigint<32>(9) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) >= 10 ) == true );
            static_assert( ( fixed_bigint<32>(10) >= fixed_bigint<32>(10) ) == true );
            static_assert( ( 10 >= fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) >= -10 ) == true );
            static_assert( ( fixed_bigint<32>(10) >= fixed_bigint<32>(-10) ) == true );
            static_assert( ( 10 >= fixed_bigint<32>(-10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(-10) >= 10 ) == false );
            static_assert( ( fixed_bigint<32>(-10) >= fixed_bigint<32>(10) ) == false );
            static_assert( ( -10 >= fixed_bigint<32>(10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-10) >= -10 ) == true );
            static_assert( ( fixed_bigint<32>(-10) >= fixed_bigint<32>(-10) ) == true );
            static_assert( ( -10 >= fixed_bigint<32>(-10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(-10) >= -11 ) == true );
            static_assert( ( fixed_bigint<32>(-10) >= fixed_bigint<32>(-11) ) == true );
            static_assert( ( -10 >= fixed_bigint<32>(-11) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(10) >= 11 ) == false );
            static_assert( ( fixed_bigint<32>(10) >= fixed_bigint<32>(11) ) == false );
            static_assert( ( 10 >= fixed_bigint<32>(11) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(11) >= 10 ) == true );
            static_assert( ( fixed_bigint<32>(11) >= fixed_bigint<32>(10) ) == true );
            static_assert( ( 11 >= fixed_bigint<32>(10) ) == true ); // int overload
            static_assert( ( fixed_bigint<32>(-11) >= 10 ) == false );
            static_assert( ( fixed_bigint<32>(-11) >= fixed_bigint<32>(10) ) == false );
            static_assert( ( -11 >= fixed_bigint<32>(10) ) == false ); // int overload
            static_assert( ( fixed_bigint<32>(-11) >= -10 ) == false );
            static_assert( ( fixed_bigint<32>(-11) >= fixed_bigint<32>(-10) ) == false );
            static_assert( ( -11 >= fixed_bigint<32>(-10) ) == false ); // int overload

            REQUIRE_EQUAL( fixed_bigint<32>(10) >= 9, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= fixed_bigint<32>(9), true )
            REQUIRE_EQUAL( 10 >= fixed_bigint<32>(9), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( 10 >= fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= fixed_bigint<32>(-10), true )
            REQUIRE_EQUAL( 10 >= fixed_bigint<32>(-10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( -10 >= fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= -10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= fixed_bigint<32>(-10), true )
            REQUIRE_EQUAL( -10 >= fixed_bigint<32>(-10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= -11, true )
            REQUIRE_EQUAL( fixed_bigint<32>(-10) >= fixed_bigint<32>(-11), true )
            REQUIRE_EQUAL( -10 >= fixed_bigint<32>(-11), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= 11, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10) >= fixed_bigint<32>(11), false )
            REQUIRE_EQUAL( 10 >= fixed_bigint<32>(11), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11) >= 10, true )
            REQUIRE_EQUAL( fixed_bigint<32>(11) >= fixed_bigint<32>(10), true )
            REQUIRE_EQUAL( 11 >= fixed_bigint<32>(10), true ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) >= 10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) >= fixed_bigint<32>(10), false )
            REQUIRE_EQUAL( -11 >= fixed_bigint<32>(10), false ) // int overload
            REQUIRE_EQUAL( fixed_bigint<32>(-11) >= -10, false )
            REQUIRE_EQUAL( fixed_bigint<32>(-11) >= fixed_bigint<32>(-10), false )
            REQUIRE_EQUAL( -11 >= fixed_bigint<32>(-10), false ) // int overload

            static_assert( ( fixed_bigint<32>(10U) >= 9U ) == true );
            static_assert( ( fixed_bigint<32>(10U) >= fixed_bigint<32>(9U) ) == true );
            static_assert( ( 10U >= fixed_bigint<32>(9U) ) == true ); // unsigned int overload
            static_assert( ( fixed_bigint<32>(10U) >= 10U ) == true );
            static_assert( ( fixed_bigint<32>(10U) >= fixed_bigint<32>(10U) ) == true );
            static_assert( ( 10U >= fixed_bigint<32>(10U) ) == true ); // unsigned int overload
            static_assert( ( fixed_bigint<32>(10U) >= 11U ) == false );
            static_assert( ( fixed_bigint<32>(10U) >= fixed_bigint<32>(11U) ) == false );
            static_assert( ( 10U >= fixed_bigint<32>(11U) ) == false ); // unsigned int overload
            static_assert( ( fixed_bigint<32>(11U) >= 10U ) == true );
            static_assert( ( fixed_bigint<32>(11U) >= fixed_bigint<32>(10U) ) == true );
            static_assert( ( 11U >= fixed_bigint<32>(10U) ) == true ); // unsigned int overload

            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= 9U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= fixed_bigint<32>(9U), true )
            REQUIRE_EQUAL( 10U >= fixed_bigint<32>(9U), true ) // unsigned int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= 10U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= fixed_bigint<32>(10U), true )
            REQUIRE_EQUAL( 10U >= fixed_bigint<32>(10U), true ) // unsigned int overload
            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= 11U, false )
            REQUIRE_EQUAL( fixed_bigint<32>(10U) >= fixed_bigint<32>(11U), false )
            REQUIRE_EQUAL( 10U >= fixed_bigint<32>(11U), false ) // unsigned int overload
            REQUIRE_EQUAL( fixed_bigint<32>(11U) >= 10U, true )
            REQUIRE_EQUAL( fixed_bigint<32>(11U) >= fixed_bigint<32>(10U), true )
            REQUIRE_EQUAL( 11U >= fixed_bigint<32>(10U), true ) // unsigned int overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFELL) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFELL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFELL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= -0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( -0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= -0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( -0x0000FFFF0000FFFFLL >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF00010000LL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF00010000LL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF00010000LL) ) == false ); // long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) >= 0x0000FFFF0000FFFFLL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000LL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true );
            static_assert( ( 0x0000FFFF00010000LL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == true ); // long long overload
            static_assert( ( fixed_bigint<64>(-0x0000FFFF00010000LL) >= 0x0000FFFF0000FFFFLL ) == false );
            static_assert( ( fixed_bigint<64>(-0x0000FFFF00010000LL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false );
            static_assert( ( -0x0000FFFF00010000LL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL) ) == false ); // long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFELL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFELL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFELL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= -0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= -0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( -0x0000FFFF0000FFFFLL >= fixed_bigint<64>(-0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= 0x0000FFFF00010000LL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFLL) >= fixed_bigint<64>(0x0000FFFF00010000LL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFLL >= fixed_bigint<64>(0x0000FFFF00010000LL), false ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) >= 0x0000FFFF0000FFFFLL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000LL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true )
            REQUIRE_EQUAL( 0x0000FFFF00010000LL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), true ) // long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF00010000LL) >= 0x0000FFFF0000FFFFLL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(-0x0000FFFF00010000LL) >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false )
            REQUIRE_EQUAL( -0x0000FFFF00010000LL >= fixed_bigint<64>(0x0000FFFF0000FFFFLL), false ) // long long overload

            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF0000FFFEULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF0000FFFEULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF0000FFFEULL) ) == true ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF0000FFFFULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true );
            static_assert( ( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF00010000ULL ) == false );
            static_assert( ( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF00010000ULL) ) == false );
            static_assert( ( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF00010000ULL) ) == false ); // unsigned long long overload
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) >= 0x0000FFFF0000FFFFULL ) == true );
            static_assert( ( fixed_bigint<64>(0x0000FFFF00010000ULL) >= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true );
            static_assert( ( 0x0000FFFF00010000ULL >= fixed_bigint<64>(0x0000FFFF0000FFFFULL) ) == true ); // unsigned long long overload

            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF0000FFFEULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF0000FFFEULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF0000FFFEULL), true ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF0000FFFFULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= 0x0000FFFF00010000ULL, false )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF0000FFFFULL) >= fixed_bigint<64>(0x0000FFFF00010000ULL), false )
            REQUIRE_EQUAL( 0x0000FFFF0000FFFFULL >= fixed_bigint<64>(0x0000FFFF00010000ULL), false ) // unsigned long long overload
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) >= 0x0000FFFF0000FFFFULL, true )
            REQUIRE_EQUAL( fixed_bigint<64>(0x0000FFFF00010000ULL) >= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true )
            REQUIRE_EQUAL( 0x0000FFFF00010000ULL >= fixed_bigint<64>(0x0000FFFF0000FFFFULL), true ) // unsigned long long overload
        }

        // Test sizes, set bits, parity etc...
        {
            static_assert( fixed_bigint<32>().is_negative() == false );
            static_assert( fixed_bigint<32>().bit_length()  == 1     );
            static_assert( fixed_bigint<32>().byte_length() == 1     );
            static_assert( fixed_bigint<32>().word_length() == 1     );
            static_assert( fixed_bigint<32>().size()        == 1     );
            static_assert( fixed_bigint<32>().test_bit(0)   == false );
            static_assert( fixed_bigint<32>().test_bit(1)   == false );
            static_assert( fixed_bigint<32>().test_bit(2)   == false );
            static_assert( fixed_bigint<32>().test_bit(3)   == false );
            static_assert( fixed_bigint<32>().test_bit(4)   == false );
            static_assert( fixed_bigint<32>().test_bit(5)   == false );
            static_assert( fixed_bigint<32>().test_bit(6)   == false );
            static_assert( fixed_bigint<32>().test_bit(7)   == false );
            static_assert( fixed_bigint<32>().test_bit(8)   == false );
            static_assert( fixed_bigint<32>().is_zero()     == true  );
            static_assert( fixed_bigint<32>().is_one()      == false );
            static_assert( fixed_bigint<32>().is_odd()      == false );
            static_assert( fixed_bigint<32>().is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>().is_negative() , false );
            REQUIRE_EQUAL( fixed_bigint<32>().bit_length()  , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>().byte_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>().word_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>().size()        , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>().test_bit(0)   , false );
            REQUIRE_EQUAL( fixed_bigint<32>().test_bit(1)   , false );
            REQUIRE_EQUAL( fixed_bigint<32>().is_zero()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>().is_one()      , false );
            REQUIRE_EQUAL( fixed_bigint<32>().is_odd()      , false );
            REQUIRE_EQUAL( fixed_bigint<32>().is_even()     , true  );

            static_assert( fixed_bigint<32>(0).is_negative() == false );
            static_assert( fixed_bigint<32>(0).bit_length()  == 1     );
            static_assert( fixed_bigint<32>(0).byte_length() == 1     );
            static_assert( fixed_bigint<32>(0).word_length() == 1     );
            static_assert( fixed_bigint<32>(0).size()        == 1     );
            static_assert( fixed_bigint<32>(0).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(0).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(0).is_zero()     == true  );
            static_assert( fixed_bigint<32>(0).is_one()      == false );
            static_assert( fixed_bigint<32>(0).is_odd()      == false );
            static_assert( fixed_bigint<32>(0).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(0).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(0).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(0).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0).is_even()    , true  );

            static_assert( fixed_bigint<32>(0U).is_negative() == false );
            static_assert( fixed_bigint<32>(0U).bit_length()  == 1     );
            static_assert( fixed_bigint<32>(0U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(0U).word_length() == 1     );
            static_assert( fixed_bigint<32>(0U).size()        == 1     );
            static_assert( fixed_bigint<32>(0U).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(0U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(0U).is_zero()     == true  );
            static_assert( fixed_bigint<32>(0U).is_one()      == false );
            static_assert( fixed_bigint<32>(0U).is_odd()      == false );
            static_assert( fixed_bigint<32>(0U).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(0U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(0U).is_even()    , true  );

            static_assert( fixed_bigint<32>(-0).is_negative() == false );
            static_assert( fixed_bigint<32>(-0).bit_length()  == 1     );
            static_assert( fixed_bigint<32>(-0).byte_length() == 1     );
            static_assert( fixed_bigint<32>(-0).word_length() == 1     );
            static_assert( fixed_bigint<32>(-0).size()        == 1     );
            static_assert( fixed_bigint<32>(-0).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(-0).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(-0).is_zero()     == true  );
            static_assert( fixed_bigint<32>(-0).is_one()      == false );
            static_assert( fixed_bigint<32>(-0).is_odd()      == false );
            static_assert( fixed_bigint<32>(-0).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(-0).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-0).is_even()    , true  );

            static_assert( fixed_bigint<64>(0LL).is_negative() == false );
            static_assert( fixed_bigint<64>(0LL).bit_length()  == 1     );
            static_assert( fixed_bigint<64>(0LL).byte_length() == 1     );
            static_assert( fixed_bigint<64>(0LL).word_length() == 1     );
            static_assert( fixed_bigint<64>(0LL).size()        == 1     );
            static_assert( fixed_bigint<64>(0LL).test_bit(0)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(1)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(2)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(3)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(4)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(5)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(6)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(7)   == false );
            static_assert( fixed_bigint<64>(0LL).test_bit(8)   == false );
            static_assert( fixed_bigint<64>(0LL).is_zero()     == true  );
            static_assert( fixed_bigint<64>(0LL).is_one()      == false );
            static_assert( fixed_bigint<64>(0LL).is_odd()      == false );
            static_assert( fixed_bigint<64>(0LL).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<64>(0LL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0LL).is_even()    , true  );

            static_assert( fixed_bigint<64>(0ULL).is_negative() == false );
            static_assert( fixed_bigint<64>(0ULL).bit_length()  == 1     );
            static_assert( fixed_bigint<64>(0ULL).byte_length() == 1     );
            static_assert( fixed_bigint<64>(0ULL).word_length() == 1     );
            static_assert( fixed_bigint<64>(0ULL).size()        == 1     );
            static_assert( fixed_bigint<64>(0ULL).test_bit(0)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(1)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(2)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(3)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(4)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(5)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(6)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(7)   == false );
            static_assert( fixed_bigint<64>(0ULL).test_bit(8)   == false );
            static_assert( fixed_bigint<64>(0ULL).is_zero()     == true  );
            static_assert( fixed_bigint<64>(0ULL).is_one()      == false );
            static_assert( fixed_bigint<64>(0ULL).is_odd()      == false );
            static_assert( fixed_bigint<64>(0ULL).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0ULL).is_even()    , true  );

            static_assert( fixed_bigint<64>(-0LL).is_negative() == false );
            static_assert( fixed_bigint<64>(-0LL).bit_length()  == 1     );
            static_assert( fixed_bigint<64>(-0LL).byte_length() == 1     );
            static_assert( fixed_bigint<64>(-0LL).word_length() == 1     );
            static_assert( fixed_bigint<64>(-0LL).size()        == 1     );
            static_assert( fixed_bigint<64>(-0LL).test_bit(0)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(1)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(2)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(3)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(4)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(5)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(6)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(7)   == false );
            static_assert( fixed_bigint<64>(-0LL).test_bit(8)   == false );
            static_assert( fixed_bigint<64>(-0LL).is_zero()     == true  );
            static_assert( fixed_bigint<64>(-0LL).is_one()      == false );
            static_assert( fixed_bigint<64>(-0LL).is_odd()      == false );
            static_assert( fixed_bigint<64>(-0LL).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).is_zero()    , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-0LL).is_even()    , true  );

            static_assert( fixed_bigint<32>(1).is_negative() == false );
            static_assert( fixed_bigint<32>(1).bit_length()  == 1     );
            static_assert( fixed_bigint<32>(1).byte_length() == 1     );
            static_assert( fixed_bigint<32>(1).word_length() == 1     );
            static_assert( fixed_bigint<32>(1).size()        == 1     );
            static_assert( fixed_bigint<32>(1).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(1).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(1).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(1).is_zero()     == false );
            static_assert( fixed_bigint<32>(1).is_one()      == true  );
            static_assert( fixed_bigint<32>(1).is_odd()      == true  );
            static_assert( fixed_bigint<32>(1).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(1).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(1).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(1).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(1).is_one()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1).is_even()    , false );

            static_assert( fixed_bigint<32>(1U).is_negative() == false );
            static_assert( fixed_bigint<32>(1U).bit_length()  == 1     );
            static_assert( fixed_bigint<32>(1U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(1U).word_length() == 1     );
            static_assert( fixed_bigint<32>(1U).size()        == 1     );
            static_assert( fixed_bigint<32>(1U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(1U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(1U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(1U).is_zero()     == false );
            static_assert( fixed_bigint<32>(1U).is_one()      == true  );
            static_assert( fixed_bigint<32>(1U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(1U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(1U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).is_one()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(1U).is_even()    , false );

            static_assert( fixed_bigint<64>(1LL).is_negative() == false );
            static_assert( fixed_bigint<64>(1LL).bit_length()  == 1     );
            static_assert( fixed_bigint<64>(1LL).byte_length() == 1     );
            static_assert( fixed_bigint<64>(1LL).word_length() == 1     );
            static_assert( fixed_bigint<64>(1LL).size()        == 1     );
            static_assert( fixed_bigint<64>(1LL).test_bit(0)   == true  );
            static_assert( fixed_bigint<64>(1LL).test_bit(1)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(2)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(3)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(4)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(5)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(6)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(7)   == false );
            static_assert( fixed_bigint<64>(1LL).test_bit(8)   == false );
            static_assert( fixed_bigint<64>(1LL).is_zero()     == false );
            static_assert( fixed_bigint<64>(1LL).is_one()      == true  );
            static_assert( fixed_bigint<64>(1LL).is_odd()      == true  );
            static_assert( fixed_bigint<64>(1LL).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<64>(1LL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).is_one()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1LL).is_even()    , false );

            static_assert( fixed_bigint<64>(1ULL).is_negative() == false );
            static_assert( fixed_bigint<64>(1ULL).bit_length()  == 1     );
            static_assert( fixed_bigint<64>(1ULL).byte_length() == 1     );
            static_assert( fixed_bigint<64>(1ULL).word_length() == 1     );
            static_assert( fixed_bigint<64>(1ULL).size()        == 1     );
            static_assert( fixed_bigint<64>(1ULL).test_bit(0)   == true  );
            static_assert( fixed_bigint<64>(1ULL).test_bit(1)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(2)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(3)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(4)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(5)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(6)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(7)   == false );
            static_assert( fixed_bigint<64>(1ULL).test_bit(8)   == false );
            static_assert( fixed_bigint<64>(1ULL).is_zero()     == false );
            static_assert( fixed_bigint<64>(1ULL).is_one()      == true  );
            static_assert( fixed_bigint<64>(1ULL).is_odd()      == true  );
            static_assert( fixed_bigint<64>(1ULL).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).bit_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).is_one()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(1ULL).is_even()    , false );

            static_assert( fixed_bigint<32>(2).is_negative() == false );
            static_assert( fixed_bigint<32>(2).bit_length()  == 2     );
            static_assert( fixed_bigint<32>(2).byte_length() == 1     );
            static_assert( fixed_bigint<32>(2).word_length() == 1     );
            static_assert( fixed_bigint<32>(2).size()        == 1     );
            static_assert( fixed_bigint<32>(2).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(2).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(2).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(2).is_zero()     == false );
            static_assert( fixed_bigint<32>(2).is_one()      == false );
            static_assert( fixed_bigint<32>(2).is_odd()      == false );
            static_assert( fixed_bigint<32>(2).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(2).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(2).bit_length() , 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(2).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(2).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2).is_even()    , true  );

            static_assert( fixed_bigint<32>(2U).is_negative() == false );
            static_assert( fixed_bigint<32>(2U).bit_length()  == 2     );
            static_assert( fixed_bigint<32>(2U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(2U).word_length() == 1     );
            static_assert( fixed_bigint<32>(2U).size()        == 1     );
            static_assert( fixed_bigint<32>(2U).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(2U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(2U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(2U).is_zero()     == false );
            static_assert( fixed_bigint<32>(2U).is_one()      == false );
            static_assert( fixed_bigint<32>(2U).is_odd()      == false );
            static_assert( fixed_bigint<32>(2U).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(2U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).bit_length() , 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(2U).is_even()    , true  );

            static_assert( fixed_bigint<32>(3).is_negative() == false );
            static_assert( fixed_bigint<32>(3).bit_length()  == 2     );
            static_assert( fixed_bigint<32>(3).byte_length() == 1     );
            static_assert( fixed_bigint<32>(3).word_length() == 1     );
            static_assert( fixed_bigint<32>(3).size()        == 1     );
            static_assert( fixed_bigint<32>(3).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(3).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(3).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(3).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(3).is_zero()     == false );
            static_assert( fixed_bigint<32>(3).is_one()      == false );
            static_assert( fixed_bigint<32>(3).is_odd()      == true  );
            static_assert( fixed_bigint<32>(3).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(3).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(3).bit_length() , 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(3).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(3).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(3).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3).is_even()    , false );

            static_assert( fixed_bigint<32>(3U).is_negative() == false );
            static_assert( fixed_bigint<32>(3U).bit_length()  == 2     );
            static_assert( fixed_bigint<32>(3U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(3U).word_length() == 1     );
            static_assert( fixed_bigint<32>(3U).size()        == 1     );
            static_assert( fixed_bigint<32>(3U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(3U).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(3U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(3U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(3U).is_zero()     == false );
            static_assert( fixed_bigint<32>(3U).is_one()      == false );
            static_assert( fixed_bigint<32>(3U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(3U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(3U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).bit_length() , 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(3U).is_even()    , false );

            static_assert( fixed_bigint<32>(4).is_negative() == false );
            static_assert( fixed_bigint<32>(4).bit_length()  == 3     );
            static_assert( fixed_bigint<32>(4).byte_length() == 1     );
            static_assert( fixed_bigint<32>(4).word_length() == 1     );
            static_assert( fixed_bigint<32>(4).size()        == 1     );
            static_assert( fixed_bigint<32>(4).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(4).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(4).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(4).is_zero()     == false );
            static_assert( fixed_bigint<32>(4).is_one()      == false );
            static_assert( fixed_bigint<32>(4).is_odd()      == false );
            static_assert( fixed_bigint<32>(4).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(4).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(4).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(4).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4).is_even()    , true  );

            static_assert( fixed_bigint<32>(4U).is_negative() == false );
            static_assert( fixed_bigint<32>(4U).bit_length()  == 3     );
            static_assert( fixed_bigint<32>(4U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(4U).word_length() == 1     );
            static_assert( fixed_bigint<32>(4U).size()        == 1     );
            static_assert( fixed_bigint<32>(4U).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(4U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(4U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(4U).is_zero()     == false );
            static_assert( fixed_bigint<32>(4U).is_one()      == false );
            static_assert( fixed_bigint<32>(4U).is_odd()      == false );
            static_assert( fixed_bigint<32>(4U).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(4U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(4U).is_even()    , true  );

            static_assert( fixed_bigint<32>(5).is_negative() == false );
            static_assert( fixed_bigint<32>(5).bit_length()  == 3     );
            static_assert( fixed_bigint<32>(5).byte_length() == 1     );
            static_assert( fixed_bigint<32>(5).word_length() == 1     );
            static_assert( fixed_bigint<32>(5).size()        == 1     );
            static_assert( fixed_bigint<32>(5).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(5).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(5).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(5).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(5).is_zero()     == false );
            static_assert( fixed_bigint<32>(5).is_one()      == false );
            static_assert( fixed_bigint<32>(5).is_odd()      == true  );
            static_assert( fixed_bigint<32>(5).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(5).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(5).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(5).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5).is_even()    , false );

            static_assert( fixed_bigint<32>(5U).is_negative() == false );
            static_assert( fixed_bigint<32>(5U).bit_length()  == 3     );
            static_assert( fixed_bigint<32>(5U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(5U).word_length() == 1     );
            static_assert( fixed_bigint<32>(5U).size()        == 1     );
            static_assert( fixed_bigint<32>(5U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(5U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(5U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(5U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(5U).is_zero()     == false );
            static_assert( fixed_bigint<32>(5U).is_one()      == false );
            static_assert( fixed_bigint<32>(5U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(5U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(5U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(5U).is_even()    , false );

            REQUIRE_EQUAL( fixed_bigint<32>(6).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(6).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(6).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(6).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(6).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6).is_one()     , false );

            REQUIRE_EQUAL( fixed_bigint<32>(6U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(6U).is_one()     , false );

            REQUIRE_EQUAL( fixed_bigint<32>(7).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(7).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(7).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7).is_even()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(7).is_one()     , false );

            REQUIRE_EQUAL( fixed_bigint<32>(7U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).bit_length() , 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).is_even()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(7U).is_one()     , false );

            REQUIRE_EQUAL( fixed_bigint<32>(8).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(8).bit_length() , 4     );
            REQUIRE_EQUAL( fixed_bigint<32>(8).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(8).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(8).is_one()     , false );

            REQUIRE_EQUAL( fixed_bigint<32>(8U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).bit_length() , 4     );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(8U).is_one()     , false );

            static_assert( fixed_bigint<32>(127).is_negative() == false );
            static_assert( fixed_bigint<32>(127).bit_length()  == 7     );
            static_assert( fixed_bigint<32>(127).byte_length() == 1     );
            static_assert( fixed_bigint<32>(127).word_length() == 1     );
            static_assert( fixed_bigint<32>(127).size()        == 1     );
            static_assert( fixed_bigint<32>(127).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(3)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(4)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(5)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(6)   == true  );
            static_assert( fixed_bigint<32>(127).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(127).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(127).is_zero()     == false );
            static_assert( fixed_bigint<32>(127).is_one()      == false );
            static_assert( fixed_bigint<32>(127).is_odd()      == true  );
            static_assert( fixed_bigint<32>(127).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(127).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(127).bit_length() , 7     );
            REQUIRE_EQUAL( fixed_bigint<32>(127).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127).is_even()    , false );

            static_assert( fixed_bigint<32>(127U).is_negative() == false );
            static_assert( fixed_bigint<32>(127U).bit_length()  == 7     );
            static_assert( fixed_bigint<32>(127U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(127U).word_length() == 1     );
            static_assert( fixed_bigint<32>(127U).size()        == 1     );
            static_assert( fixed_bigint<32>(127U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(3)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(4)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(5)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(6)   == true  );
            static_assert( fixed_bigint<32>(127U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(127U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(127U).is_zero()     == false );
            static_assert( fixed_bigint<32>(127U).is_one()      == false );
            static_assert( fixed_bigint<32>(127U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(127U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(127U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).bit_length() , 7     );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(127U).is_even()    , false );

            static_assert( fixed_bigint<32>(128).is_negative() == false );
            static_assert( fixed_bigint<32>(128).bit_length()  == 8     );
            static_assert( fixed_bigint<32>(128).byte_length() == 1     );
            static_assert( fixed_bigint<32>(128).word_length() == 1     );
            static_assert( fixed_bigint<32>(128).size()        == 1     );
            static_assert( fixed_bigint<32>(128).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(128).test_bit(7)   == true  );
            static_assert( fixed_bigint<32>(128).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(128).is_zero()     == false );
            static_assert( fixed_bigint<32>(128).is_one()      == false );
            static_assert( fixed_bigint<32>(128).is_odd()      == false );
            static_assert( fixed_bigint<32>(128).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(128).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(128).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(128).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128).is_even()    , true  );

            static_assert( fixed_bigint<32>(128U).is_negative() == false );
            static_assert( fixed_bigint<32>(128U).bit_length()  == 8     );
            static_assert( fixed_bigint<32>(128U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(128U).word_length() == 1     );
            static_assert( fixed_bigint<32>(128U).size()        == 1     );
            static_assert( fixed_bigint<32>(128U).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(128U).test_bit(7)   == true  );
            static_assert( fixed_bigint<32>(128U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(128U).is_zero()     == false );
            static_assert( fixed_bigint<32>(128U).is_one()      == false );
            static_assert( fixed_bigint<32>(128U).is_odd()      == false );
            static_assert( fixed_bigint<32>(128U).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(128U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(128U).is_even()    , true  );

            REQUIRE_EQUAL( fixed_bigint<32>(254).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(254).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254).is_even()    , true  );

            REQUIRE_EQUAL( fixed_bigint<32>(254U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(254U).is_one()     , false );

            static_assert( fixed_bigint<32>(255).is_negative() == false );
            static_assert( fixed_bigint<32>(255).bit_length()  == 8     );
            static_assert( fixed_bigint<32>(255).byte_length() == 1     );
            static_assert( fixed_bigint<32>(255).word_length() == 1     );
            static_assert( fixed_bigint<32>(255).size()        == 1     );
            static_assert( fixed_bigint<32>(255).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(3)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(4)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(5)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(6)   == true  );
            static_assert( fixed_bigint<32>(255).test_bit(7)   == true );
            static_assert( fixed_bigint<32>(255).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(255).is_zero()     == false );
            static_assert( fixed_bigint<32>(255).is_one()      == false );
            static_assert( fixed_bigint<32>(255).is_odd()      == true  );
            static_assert( fixed_bigint<32>(255).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(255).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(255).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(255).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255).is_even()    , false );

            static_assert( fixed_bigint<32>(255U).is_negative() == false );
            static_assert( fixed_bigint<32>(255U).bit_length()  == 8     );
            static_assert( fixed_bigint<32>(255U).byte_length() == 1     );
            static_assert( fixed_bigint<32>(255U).word_length() == 1     );
            static_assert( fixed_bigint<32>(255U).size()        == 1     );
            static_assert( fixed_bigint<32>(255U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(1)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(2)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(3)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(4)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(5)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(6)   == true  );
            static_assert( fixed_bigint<32>(255U).test_bit(7)   == true );
            static_assert( fixed_bigint<32>(255U).test_bit(8)   == false );
            static_assert( fixed_bigint<32>(255U).is_zero()     == false );
            static_assert( fixed_bigint<32>(255U).is_one()      == false );
            static_assert( fixed_bigint<32>(255U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(255U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(255U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(255U).is_even()    , false );

            static_assert( fixed_bigint<32>(256).is_negative() ==  false );
            static_assert( fixed_bigint<32>(256).bit_length()  ==  9     );
            static_assert( fixed_bigint<32>(256).byte_length() ==  2     );
            static_assert( fixed_bigint<32>(256).word_length() ==  1     );
            static_assert( fixed_bigint<32>(256).size()        ==  1     );
            static_assert( fixed_bigint<32>(256).test_bit(0)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(1)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(2)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(3)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(4)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(5)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(6)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(7)   ==  false );
            static_assert( fixed_bigint<32>(256).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<32>(256).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(256).is_one()      ==  false );
            static_assert( fixed_bigint<32>(256).is_odd()      ==  false );
            static_assert( fixed_bigint<32>(256).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<32>(256).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).bit_length() , 9     );
            REQUIRE_EQUAL( fixed_bigint<32>(256).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(256).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(256).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(256).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256).is_even()    , true  );

            static_assert( fixed_bigint<32>(256U).is_negative() ==  false );
            static_assert( fixed_bigint<32>(256U).bit_length()  ==  9     );
            static_assert( fixed_bigint<32>(256U).byte_length() ==  2     );
            static_assert( fixed_bigint<32>(256U).word_length() ==  1     );
            static_assert( fixed_bigint<32>(256U).size()        ==  1     );
            static_assert( fixed_bigint<32>(256U).test_bit(0)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(1)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(2)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(3)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(4)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(5)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(6)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(7)   ==  false );
            static_assert( fixed_bigint<32>(256U).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<32>(256U).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(256U).is_one()      ==  false );
            static_assert( fixed_bigint<32>(256U).is_odd()      ==  false );
            static_assert( fixed_bigint<32>(256U).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<32>(256U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).bit_length() , 9     );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).is_even()    , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(256U).is_one()     , false );

            static_assert( fixed_bigint<32>(65535).is_negative() ==  false );
            static_assert( fixed_bigint<32>(65535).bit_length()  ==  16    );
            static_assert( fixed_bigint<32>(65535).byte_length() ==  2     );
            static_assert( fixed_bigint<32>(65535).word_length() ==  1     );
            static_assert( fixed_bigint<32>(65535).size()        ==  1     );
            static_assert( fixed_bigint<32>(65535).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(9)   ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(10)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(11)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(12)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(13)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(14)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(15)  ==  true  );
            static_assert( fixed_bigint<32>(65535).test_bit(16)  ==  false );
            static_assert( fixed_bigint<32>(65535).test_bit(17)  ==  false );
            static_assert( fixed_bigint<32>(65535).test_bit(18)  ==  false );
            static_assert( fixed_bigint<32>(65535).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(65535).is_one()      ==  false );
            static_assert( fixed_bigint<32>(65535).is_odd()      ==  true  );
            static_assert( fixed_bigint<32>(65535).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<32>(65535).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).bit_length() , 16    );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(9)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(10) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(11) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(12) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(13) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(14) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(15) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(16) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(17) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535).is_even()    , false );

            static_assert( fixed_bigint<32>(65535U).is_negative() ==  false );
            static_assert( fixed_bigint<32>(65535U).bit_length()  ==  16    );
            static_assert( fixed_bigint<32>(65535U).byte_length() ==  2     );
            static_assert( fixed_bigint<32>(65535U).word_length() ==  1     );
            static_assert( fixed_bigint<32>(65535U).size()        ==  1     );
            static_assert( fixed_bigint<32>(65535U).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(9)   ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(10)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(11)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(12)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(13)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(14)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(15)  ==  true  );
            static_assert( fixed_bigint<32>(65535U).test_bit(16)  ==  false );
            static_assert( fixed_bigint<32>(65535U).test_bit(17)  ==  false );
            static_assert( fixed_bigint<32>(65535U).test_bit(18)  ==  false );
            static_assert( fixed_bigint<32>(65535U).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(65535U).is_one()      ==  false );
            static_assert( fixed_bigint<32>(65535U).is_odd()      ==  true  );
            static_assert( fixed_bigint<32>(65535U).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<32>(65535U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).bit_length() , 16    );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(9)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(10) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(11) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(12) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(13) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(14) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(15) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(16) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(17) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65535U).is_even()    , false );

            static_assert( fixed_bigint<32>(65536).is_negative() ==  false );
            static_assert( fixed_bigint<32>(65536).bit_length()  ==  17    );
            static_assert( fixed_bigint<32>(65536).byte_length() ==  3     );
            static_assert( fixed_bigint<32>(65536).word_length() ==  1     );
            static_assert( fixed_bigint<32>(65536).size()        ==  1     );
            static_assert( fixed_bigint<32>(65536).test_bit(0)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(1)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(2)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(3)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(4)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(5)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(6)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(7)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(8)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(9)   ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(10)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(11)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(12)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(13)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(14)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(15)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(16)  ==  true  );
            static_assert( fixed_bigint<32>(65536).test_bit(17)  ==  false );
            static_assert( fixed_bigint<32>(65536).test_bit(18)  ==  false );
            static_assert( fixed_bigint<32>(65536).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(65536).is_one()      ==  false );
            static_assert( fixed_bigint<32>(65536).is_odd()      ==  false );
            static_assert( fixed_bigint<32>(65536).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<32>(65536).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).bit_length() , 17    );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).byte_length(), 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(9)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(10) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(11) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(12) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(13) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(14) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(15) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(16) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(17) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536).is_even()    , true  );

            static_assert( fixed_bigint<32>(65536U).is_negative() ==  false );
            static_assert( fixed_bigint<32>(65536U).bit_length()  ==  17    );
            static_assert( fixed_bigint<32>(65536U).byte_length() ==  3     );
            static_assert( fixed_bigint<32>(65536U).word_length() ==  1     );
            static_assert( fixed_bigint<32>(65536U).size()        ==  1     );
            static_assert( fixed_bigint<32>(65536U).test_bit(0)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(1)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(2)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(3)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(4)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(5)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(6)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(7)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(8)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(9)   ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(10)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(11)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(12)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(13)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(14)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(15)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(16)  ==  true  );
            static_assert( fixed_bigint<32>(65536U).test_bit(17)  ==  false );
            static_assert( fixed_bigint<32>(65536U).test_bit(18)  ==  false );
            static_assert( fixed_bigint<32>(65536U).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(65536U).is_one()      ==  false );
            static_assert( fixed_bigint<32>(65536U).is_odd()      ==  false );
            static_assert( fixed_bigint<32>(65536U).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<32>(65536U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).bit_length() , 17    );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).byte_length(), 3     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(9)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(10) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(11) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(12) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(13) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(14) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(15) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(16) , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(17) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(65536U).is_even()    , true  );

            static_assert( fixed_bigint<64>(0xFFFFFFFF).is_negative() ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).bit_length()  ==  32    );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).byte_length() ==  4     );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).word_length() ==  1     );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).size()        ==  1     );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(9)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(10)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(11)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(12)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(13)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(14)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(15)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(16)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(18)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(19)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(20)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(21)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(22)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(23)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(24)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(25)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(26)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(27)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(28)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(29)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(30)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(31)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(32)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(33)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).test_bit(34)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).is_one()      ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).is_odd()      ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFF).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).bit_length() , 32    );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).byte_length(), 4     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(9)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(10) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(11) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(12) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(13) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(14) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(15) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(16) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(18) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(19) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(20) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(21) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(22) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(23) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(24) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(25) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(26) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(27) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(28) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(29) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(30) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(31) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(32) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(33) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).test_bit(34) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFF).is_even()    , false );

            static_assert( fixed_bigint<64>(0xFFFFFFFFU).is_negative() ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).bit_length()  ==  32    );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).byte_length() ==  4     );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).word_length() ==  1     );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).size()        ==  1     );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(9)   ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(10)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(11)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(12)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(13)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(14)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(15)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(16)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(18)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(19)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(20)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(21)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(22)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(23)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(24)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(25)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(26)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(27)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(28)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(29)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(30)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(31)  ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(32)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(33)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).test_bit(34)  ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).is_one()      ==  false );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).is_odd()      ==  true  );
            static_assert( fixed_bigint<64>(0xFFFFFFFFU).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).bit_length() , 32    );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).byte_length(), 4     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(9)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(10) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(11) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(12) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(13) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(14) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(15) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(16) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(18) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(19) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(20) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(21) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(22) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(23) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(24) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(25) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(26) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(27) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(28) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(29) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(30) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(31) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(32) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(33) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).test_bit(34) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0xFFFFFFFFU).is_even()    , false );

            static_assert( fixed_bigint<64>(0x100000000LL).is_negative() ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).bit_length()  ==  33    );
            static_assert( fixed_bigint<64>(0x100000000LL).byte_length() ==  5     );
            static_assert( fixed_bigint<64>(0x100000000LL).word_length() ==  2     );
            static_assert( fixed_bigint<64>(0x100000000LL).size()        ==  2     );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(0)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(1)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(2)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(3)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(4)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(5)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(6)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(7)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(8)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(9)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(10)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(11)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(12)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(13)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(14)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(15)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(16)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(18)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(19)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(20)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(21)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(22)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(23)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(24)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(25)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(26)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(27)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(28)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(29)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(30)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(31)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(32)  ==  true  );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(33)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).test_bit(34)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).is_one()      ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).is_odd()      ==  false );
            static_assert( fixed_bigint<64>(0x100000000LL).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).bit_length() , 33    );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).byte_length(), 5     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).word_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).size()       , 2     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(9)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(10) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(11) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(12) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(13) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(14) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(15) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(16) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(19) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(20) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(21) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(22) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(23) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(24) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(25) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(26) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(27) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(28) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(29) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(30) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(31) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(32) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(33) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).test_bit(34) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000LL).is_even()    , true  );

            static_assert( fixed_bigint<64>(0x100000000ULL).is_negative() ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).bit_length()  ==  33    );
            static_assert( fixed_bigint<64>(0x100000000ULL).byte_length() ==  5     );
            static_assert( fixed_bigint<64>(0x100000000ULL).word_length() ==  2     );
            static_assert( fixed_bigint<64>(0x100000000ULL).size()        ==  2     );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(0)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(1)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(2)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(3)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(4)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(5)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(6)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(7)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(8)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(9)   ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(10)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(11)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(12)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(13)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(14)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(15)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(16)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(18)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(19)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(20)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(21)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(22)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(23)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(24)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(25)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(26)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(27)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(28)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(29)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(30)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(31)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(32)  ==  true  );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(33)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).test_bit(34)  ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).is_one()      ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).is_odd()      ==  false );
            static_assert( fixed_bigint<64>(0x100000000ULL).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).bit_length() , 33    );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).byte_length(), 5     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).word_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).size()       , 2     );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(8)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(9)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(10) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(11) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(12) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(13) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(14) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(15) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(16) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(18) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(19) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(20) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(21) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(22) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(23) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(24) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(25) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(26) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(27) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(28) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(29) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(30) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(31) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(32) , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(33) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).test_bit(34) , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(0x100000000ULL).is_even()    , true  );

            static_assert( fixed_bigint<32>(-1).is_negative()  ==  true  );
            static_assert( fixed_bigint<32>(-1).bit_length()   ==  1     );
            static_assert( fixed_bigint<32>(-1).byte_length()  ==  1     );
            static_assert( fixed_bigint<32>(-1).word_length()  ==  1     );
            static_assert( fixed_bigint<32>(-1).size()         ==  1     );
            static_assert( fixed_bigint<32>(-1).test_bit(0)    ==  true  );
            static_assert( fixed_bigint<32>(-1).test_bit(1)    ==  false );
            static_assert( fixed_bigint<32>(-1).is_zero()      ==  false );
            static_assert( fixed_bigint<32>(-1).is_one()       ==  false );
            static_assert( fixed_bigint<32>(-1).is_odd()       ==  true  );
            static_assert( fixed_bigint<32>(-1).is_even()      ==  false );

            REQUIRE_EQUAL( fixed_bigint<32>(-1).is_negative() , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).bit_length()  , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).byte_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).word_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).size()        , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).test_bit(0)   , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).test_bit(1)   , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).is_zero()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).is_one()      , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).is_odd()      , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-1).is_even()     , false );

            static_assert( fixed_bigint<64>(-1LL).is_negative()  ==  true  );
            static_assert( fixed_bigint<64>(-1LL).bit_length()   ==  1     );
            static_assert( fixed_bigint<64>(-1LL).byte_length()  ==  1     );
            static_assert( fixed_bigint<64>(-1LL).word_length()  ==  1     );
            static_assert( fixed_bigint<64>(-1LL).size()         ==  1     );
            static_assert( fixed_bigint<64>(-1LL).test_bit(0)    ==  true  );
            static_assert( fixed_bigint<64>(-1LL).test_bit(1)    ==  false );
            static_assert( fixed_bigint<64>(-1LL).is_zero()      ==  false );
            static_assert( fixed_bigint<64>(-1LL).is_one()       ==  false );
            static_assert( fixed_bigint<64>(-1LL).is_odd()       ==  true  );
            static_assert( fixed_bigint<64>(-1LL).is_even()      ==  false );

            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).is_negative() , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).bit_length()  , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).byte_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).word_length() , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).size()        , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).test_bit(0)   , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).test_bit(1)   , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).is_zero()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).is_one()      , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).is_odd()      , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-1LL).is_even()     , false );

            static_assert( fixed_bigint<32>(-2).is_negative()  ==  true  );
            static_assert( fixed_bigint<32>(-2).bit_length()   ==  2     );
            static_assert( fixed_bigint<32>(-2).byte_length()  ==  1     );
            static_assert( fixed_bigint<32>(-2).word_length()  ==  1     );
            static_assert( fixed_bigint<32>(-2).size()         ==  1     );
            static_assert( fixed_bigint<32>(-2).test_bit(0)    ==  false );
            static_assert( fixed_bigint<32>(-2).test_bit(1)    ==  true  );
            static_assert( fixed_bigint<32>(-2).is_zero()      ==  false );
            static_assert( fixed_bigint<32>(-2).is_one()       ==  false );
            static_assert( fixed_bigint<32>(-2).is_odd()       ==  false );
            static_assert( fixed_bigint<32>(-2).is_even()      ==  true  );

            REQUIRE_EQUAL( fixed_bigint<32>(-2).is_negative() , true  )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).bit_length()  , 2     )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).byte_length() , 1     )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).word_length() , 1     )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).size()        , 1     )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).test_bit(0)   , false )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).test_bit(1)   , true  )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).is_zero()     , false )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).is_one()      , false )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).is_odd()      , false )
            REQUIRE_EQUAL( fixed_bigint<32>(-2).is_even()     , true  )

            static_assert( fixed_bigint<64>(-2LL).is_negative()  ==  true  );
            static_assert( fixed_bigint<64>(-2LL).bit_length()   ==  2     );
            static_assert( fixed_bigint<64>(-2LL).byte_length()  ==  1     );
            static_assert( fixed_bigint<64>(-2LL).word_length()  ==  1     );
            static_assert( fixed_bigint<64>(-2LL).size()         ==  1     );
            static_assert( fixed_bigint<64>(-2LL).test_bit(0)    ==  false );
            static_assert( fixed_bigint<64>(-2LL).test_bit(1)    ==  true  );
            static_assert( fixed_bigint<64>(-2LL).is_zero()      ==  false );
            static_assert( fixed_bigint<64>(-2LL).is_one()       ==  false );
            static_assert( fixed_bigint<64>(-2LL).is_odd()       ==  false );
            static_assert( fixed_bigint<64>(-2LL).is_even()      ==  true  );

            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).is_negative() , true  )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).bit_length()  , 2     )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).byte_length() , 1     )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).word_length() , 1     )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).size()        , 1     )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).test_bit(0)   , false )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).test_bit(1)   , true  )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).is_zero()     , false )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).is_one()      , false )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).is_odd()      , false )
            REQUIRE_EQUAL( fixed_bigint<64>(-2LL).is_even()     , true  )

            static_assert( fixed_bigint<32>(-255).is_negative() ==  true );
            static_assert( fixed_bigint<32>(-255).bit_length()  ==  8     );
            static_assert( fixed_bigint<32>(-255).byte_length() ==  1     );
            static_assert( fixed_bigint<32>(-255).word_length() ==  1     );
            static_assert( fixed_bigint<32>(-255).size()        ==  1     );
            static_assert( fixed_bigint<32>(-255).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<32>(-255).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<32>(-255).is_zero()     ==  false );
            static_assert( fixed_bigint<32>(-255).is_one()      ==  false );
            static_assert( fixed_bigint<32>(-255).is_odd()      ==  true  );
            static_assert( fixed_bigint<32>(-255).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<32>(-255).is_negative(), true );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255).is_even()    , false );

            static_assert( fixed_bigint<64>(-255LL).is_negative() ==  true );
            static_assert( fixed_bigint<64>(-255LL).bit_length()  ==  8     );
            static_assert( fixed_bigint<64>(-255LL).byte_length() ==  1     );
            static_assert( fixed_bigint<64>(-255LL).word_length() ==  1     );
            static_assert( fixed_bigint<64>(-255LL).size()        ==  1     );
            static_assert( fixed_bigint<64>(-255LL).test_bit(0)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(1)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(2)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(3)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(4)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(5)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(6)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).test_bit(7)   ==  true  );
            static_assert( fixed_bigint<64>(-255LL).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(-255LL).is_one()      ==  false );
            static_assert( fixed_bigint<64>(-255LL).is_odd()      ==  true  );
            static_assert( fixed_bigint<64>(-255LL).is_even()     ==  false );

            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).is_negative(), true );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).bit_length() , 8     );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).byte_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(1)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(2)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(3)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(4)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(5)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(6)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).test_bit(7)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-255LL).is_even()    , false );

            // 0xFFFFFF01
            static_assert( fixed_bigint<32>(-255U).is_negative() == false );
            static_assert( fixed_bigint<32>(-255U).bit_length()  == 32    );
            static_assert( fixed_bigint<32>(-255U).byte_length() == 4     );
            static_assert( fixed_bigint<32>(-255U).word_length() == 1     );
            static_assert( fixed_bigint<32>(-255U).size()        == 1     );
            static_assert( fixed_bigint<32>(-255U).test_bit(0)   == true  );
            static_assert( fixed_bigint<32>(-255U).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(-255U).test_bit(8)   == true  );
            static_assert( fixed_bigint<64>(-255U).is_zero()     == false );
            static_assert( fixed_bigint<64>(-255U).is_one()      == false );
            static_assert( fixed_bigint<32>(-255U).is_odd()      == true  );
            static_assert( fixed_bigint<32>(-255U).is_even()     == false );

            REQUIRE_EQUAL( fixed_bigint<32>(-255U).is_negative(), false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).bit_length() , 32    );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).byte_length(), 4     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(0)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).is_odd()     , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-255U).is_even()    , false );

            static_assert( fixed_bigint<32>(-256).is_negative() == true  );
            static_assert( fixed_bigint<32>(-256).bit_length()  == 9     );
            static_assert( fixed_bigint<32>(-256).byte_length() == 2     );
            static_assert( fixed_bigint<32>(-256).word_length() == 1     );
            static_assert( fixed_bigint<32>(-256).size()        == 1     );
            static_assert( fixed_bigint<32>(-256).test_bit(0)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(1)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(2)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(3)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(4)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(5)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(6)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(7)   == false );
            static_assert( fixed_bigint<32>(-256).test_bit(8)   == true  );
            static_assert( fixed_bigint<32>(-256).is_zero()     == false );
            static_assert( fixed_bigint<32>(-256).is_one()      == false );
            static_assert( fixed_bigint<32>(-256).is_odd()      == false );
            static_assert( fixed_bigint<32>(-256).is_even()     == true  );

            REQUIRE_EQUAL( fixed_bigint<32>(-256).is_negative(), true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).bit_length() , 9     );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<32>(-256).is_even()    , true  );

            static_assert( fixed_bigint<64>(-256LL).is_negative() ==  true  );
            static_assert( fixed_bigint<64>(-256LL).bit_length()  ==  9     );
            static_assert( fixed_bigint<64>(-256LL).byte_length() ==  2     );
            static_assert( fixed_bigint<64>(-256LL).word_length() ==  1     );
            static_assert( fixed_bigint<64>(-256LL).size()        ==  1     );
            static_assert( fixed_bigint<64>(-256LL).test_bit(0)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(1)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(2)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(3)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(4)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(5)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(6)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(7)   ==  false );
            static_assert( fixed_bigint<64>(-256LL).test_bit(8)   ==  true  );
            static_assert( fixed_bigint<64>(-256LL).is_zero()     ==  false );
            static_assert( fixed_bigint<64>(-256LL).is_one()      ==  false );
            static_assert( fixed_bigint<64>(-256LL).is_odd()      ==  false );
            static_assert( fixed_bigint<64>(-256LL).is_even()     ==  true  );

            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).is_negative(), true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).bit_length() , 9     );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).byte_length(), 2     );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).word_length(), 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).size()       , 1     );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(0)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(1)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(2)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(3)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(4)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(5)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(6)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(7)  , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).test_bit(8)  , true  );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).is_zero()    , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).is_one()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).is_odd()     , false );
            REQUIRE_EQUAL( fixed_bigint<64>(-256LL).is_even()    , true  );
        }

        /* Test setting bit and operators '&' and '|'  */
        {
            using bn_t = fixed_bigint<64>;
            bn_t x = 0;
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ) == 0,  true ); // Test no bits are set
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.bit_length(), 1 );

            x.set_bit( 0, true );
            REQUIRE_EQUAL( x.test_bit( 0 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 1 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 0, false );
            REQUIRE_EQUAL( x.test_bit( 0 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 7, true );
            REQUIRE_EQUAL( x.test_bit( 7 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x80 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 8 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 7, false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 8, true );
            REQUIRE_EQUAL( x.test_bit( 8 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x100 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 9 );
            REQUIRE_EQUAL( x.byte_length(), 2 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 8, false );
            REQUIRE_EQUAL( x.test_bit( 8 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 15, true );
            REQUIRE_EQUAL( x.test_bit( 15 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x8000 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 16 );
            REQUIRE_EQUAL( x.byte_length(), 2 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 15, false );
            REQUIRE_EQUAL( x.test_bit( 15 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 16, true );
            REQUIRE_EQUAL( x.test_bit( 16 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x10000 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 17 );
            REQUIRE_EQUAL( x.byte_length(), 3 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 16, false );
            REQUIRE_EQUAL( x.test_bit( 16 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 23, true );
            REQUIRE_EQUAL( x.test_bit( 23 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x800000 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 24 );
            REQUIRE_EQUAL( x.byte_length(), 3 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 23, false );
            REQUIRE_EQUAL( x.test_bit( 23 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 24, true );
            REQUIRE_EQUAL( x.test_bit( 24 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x1000000 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 25 );
            REQUIRE_EQUAL( x.byte_length(), 4 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 24, false );
            REQUIRE_EQUAL( x.test_bit( 24 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 31, true );
            REQUIRE_EQUAL( x.test_bit( 31 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x80000000 );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 32 );
            REQUIRE_EQUAL( x.byte_length(), 4 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 31, false );
            REQUIRE_EQUAL( x.test_bit( 31 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 32, true );
            REQUIRE_EQUAL( x.test_bit( 32 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x100000000ULL );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 33 );
            REQUIRE_EQUAL( x.byte_length(), 5 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 32, false );
            REQUIRE_EQUAL( x.test_bit( 32 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 39, true );
            REQUIRE_EQUAL( x.test_bit( 39 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x8000000000ULL );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 40 );
            REQUIRE_EQUAL( x.byte_length(), 5 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 39, false );
            REQUIRE_EQUAL( x.test_bit( 39 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 40, true );
            REQUIRE_EQUAL( x.test_bit( 40 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x10000000000ULL );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 41 );
            REQUIRE_EQUAL( x.byte_length(), 6 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 40, false );
            REQUIRE_EQUAL( x.test_bit( 40 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 63, true );
            REQUIRE_EQUAL( x.test_bit( 63 ), true );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x8000000000000000ULL );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 64 );
            REQUIRE_EQUAL( x.byte_length(), 8 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 63, false );
            REQUIRE_EQUAL( x.test_bit( 63 ), false );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            // Test setting and un-setting multiple bits
            REQUIRE_EQUAL( x, 0 );
            x.set_bit( 0, true );
            x.set_bit( 1, true );
            x.set_bit( 2, true );
            REQUIRE_EQUAL( x, 7 );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x7ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), true );
            REQUIRE_EQUAL( x.test_bit( 1 ), true );
            REQUIRE_EQUAL( x.test_bit( 2 ), true );
            REQUIRE_EQUAL( x.test_bit( 3 ), false );
            REQUIRE_EQUAL( x.test_bit( 4 ), false );
            REQUIRE_EQUAL( x.test_bit( 5 ), false );
            REQUIRE_EQUAL( x.test_bit( 6 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 3 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 0, false );
            REQUIRE_EQUAL( x, 6 );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x6ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), false );
            REQUIRE_EQUAL( x.test_bit( 1 ), true );
            REQUIRE_EQUAL( x.test_bit( 2 ), true );
            REQUIRE_EQUAL( x.test_bit( 3 ), false );
            REQUIRE_EQUAL( x.test_bit( 4 ), false );
            REQUIRE_EQUAL( x.test_bit( 5 ), false );
            REQUIRE_EQUAL( x.test_bit( 6 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 3 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 1, false );
            REQUIRE_EQUAL( x, 4 );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x4ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), false );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 2 ), true );
            REQUIRE_EQUAL( x.test_bit( 3 ), false );
            REQUIRE_EQUAL( x.test_bit( 4 ), false );
            REQUIRE_EQUAL( x.test_bit( 5 ), false );
            REQUIRE_EQUAL( x.test_bit( 6 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 3 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 2, false );
            REQUIRE_EQUAL( x, 0ULL );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), false );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 2 ), false );
            REQUIRE_EQUAL( x.test_bit( 3 ), false );
            REQUIRE_EQUAL( x.test_bit( 4 ), false );
            REQUIRE_EQUAL( x.test_bit( 5 ), false );
            REQUIRE_EQUAL( x.test_bit( 6 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.is_zero(), true );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 1 );
            REQUIRE_EQUAL( x.byte_length(), 1 );
            REQUIRE_EQUAL( x.word_length(), 1 );
            REQUIRE_EQUAL( x.size(), 1 );

            x.set_bit( 0, true );
            x.set_bit( 8, true );
            x.set_bit( 16, true );
            x.set_bit( 24, true );
            x.set_bit( 32, true );
            x.set_bit( 40, true );
            x.set_bit( 48, true );
            x.set_bit( 63, true );
            REQUIRE_EQUAL( x, 0x8001010101010101ULL );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x8001010101010101ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), true );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.test_bit( 8 ), true );
            REQUIRE_EQUAL( x.test_bit( 9 ), false );
            REQUIRE_EQUAL( x.test_bit( 15 ), false );
            REQUIRE_EQUAL( x.test_bit( 16 ), true );
            REQUIRE_EQUAL( x.test_bit( 17 ), false );
            REQUIRE_EQUAL( x.test_bit( 23 ), false );
            REQUIRE_EQUAL( x.test_bit( 24 ), true );
            REQUIRE_EQUAL( x.test_bit( 25 ), false );
            REQUIRE_EQUAL( x.test_bit( 31 ), false );
            REQUIRE_EQUAL( x.test_bit( 32 ), true );
            REQUIRE_EQUAL( x.test_bit( 33 ), false );
            REQUIRE_EQUAL( x.test_bit( 39 ), false );
            REQUIRE_EQUAL( x.test_bit( 40 ), true );
            REQUIRE_EQUAL( x.test_bit( 41 ), false );
            REQUIRE_EQUAL( x.test_bit( 47 ), false );
            REQUIRE_EQUAL( x.test_bit( 48 ), true );
            REQUIRE_EQUAL( x.test_bit( 49 ), false );
            REQUIRE_EQUAL( x.test_bit( 55 ), false );
            REQUIRE_EQUAL( x.test_bit( 56 ), false );
            REQUIRE_EQUAL( x.test_bit( 57 ), false );
            REQUIRE_EQUAL( x.test_bit( 58 ), false );
            REQUIRE_EQUAL( x.test_bit( 59 ), false );
            REQUIRE_EQUAL( x.test_bit( 60 ), false );
            REQUIRE_EQUAL( x.test_bit( 61 ), false );
            REQUIRE_EQUAL( x.test_bit( 62 ), false );
            REQUIRE_EQUAL( x.test_bit( 63 ), true );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 64 );
            REQUIRE_EQUAL( x.byte_length(), 8 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 0, false );
            REQUIRE_EQUAL( x, 0x8001010101010100ULL );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x8001010101010100ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), false );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.test_bit( 8 ), true );
            REQUIRE_EQUAL( x.test_bit( 9 ), false );
            REQUIRE_EQUAL( x.test_bit( 15 ), false );
            REQUIRE_EQUAL( x.test_bit( 16 ), true );
            REQUIRE_EQUAL( x.test_bit( 17 ), false );
            REQUIRE_EQUAL( x.test_bit( 23 ), false );
            REQUIRE_EQUAL( x.test_bit( 24 ), true );
            REQUIRE_EQUAL( x.test_bit( 25 ), false );
            REQUIRE_EQUAL( x.test_bit( 31 ), false );
            REQUIRE_EQUAL( x.test_bit( 32 ), true );
            REQUIRE_EQUAL( x.test_bit( 33 ), false );
            REQUIRE_EQUAL( x.test_bit( 39 ), false );
            REQUIRE_EQUAL( x.test_bit( 40 ), true );
            REQUIRE_EQUAL( x.test_bit( 41 ), false );
            REQUIRE_EQUAL( x.test_bit( 47 ), false );
            REQUIRE_EQUAL( x.test_bit( 48 ), true );
            REQUIRE_EQUAL( x.test_bit( 49 ), false );
            REQUIRE_EQUAL( x.test_bit( 55 ), false );
            REQUIRE_EQUAL( x.test_bit( 56 ), false );
            REQUIRE_EQUAL( x.test_bit( 57 ), false );
            REQUIRE_EQUAL( x.test_bit( 58 ), false );
            REQUIRE_EQUAL( x.test_bit( 59 ), false );
            REQUIRE_EQUAL( x.test_bit( 60 ), false );
            REQUIRE_EQUAL( x.test_bit( 61 ), false );
            REQUIRE_EQUAL( x.test_bit( 62 ), false );
            REQUIRE_EQUAL( x.test_bit( 63 ), true );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 64 );
            REQUIRE_EQUAL( x.byte_length(), 8 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 0, true );
            x.set_bit( 63, false );
            REQUIRE_EQUAL( x, 0x1010101010101ULL );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x1010101010101ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), true );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.test_bit( 8 ), true );
            REQUIRE_EQUAL( x.test_bit( 9 ), false );
            REQUIRE_EQUAL( x.test_bit( 15 ), false );
            REQUIRE_EQUAL( x.test_bit( 16 ), true );
            REQUIRE_EQUAL( x.test_bit( 17 ), false );
            REQUIRE_EQUAL( x.test_bit( 23 ), false );
            REQUIRE_EQUAL( x.test_bit( 24 ), true );
            REQUIRE_EQUAL( x.test_bit( 25 ), false );
            REQUIRE_EQUAL( x.test_bit( 31 ), false );
            REQUIRE_EQUAL( x.test_bit( 32 ), true );
            REQUIRE_EQUAL( x.test_bit( 33 ), false );
            REQUIRE_EQUAL( x.test_bit( 39 ), false );
            REQUIRE_EQUAL( x.test_bit( 40 ), true );
            REQUIRE_EQUAL( x.test_bit( 41 ), false );
            REQUIRE_EQUAL( x.test_bit( 47 ), false );
            REQUIRE_EQUAL( x.test_bit( 48 ), true );
            REQUIRE_EQUAL( x.test_bit( 49 ), false );
            REQUIRE_EQUAL( x.test_bit( 55 ), false );
            REQUIRE_EQUAL( x.test_bit( 56 ), false );
            REQUIRE_EQUAL( x.test_bit( 57 ), false );
            REQUIRE_EQUAL( x.test_bit( 58 ), false );
            REQUIRE_EQUAL( x.test_bit( 59 ), false );
            REQUIRE_EQUAL( x.test_bit( 60 ), false );
            REQUIRE_EQUAL( x.test_bit( 61 ), false );
            REQUIRE_EQUAL( x.test_bit( 62 ), false );
            REQUIRE_EQUAL( x.test_bit( 63 ), false );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 49 );
            REQUIRE_EQUAL( x.byte_length(), 7 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 32, false );
            REQUIRE_EQUAL( x, 0x1010001010101ULL );
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x1010001010101ULL );
            REQUIRE_EQUAL( x.test_bit( 0 ), true );
            REQUIRE_EQUAL( x.test_bit( 1 ), false );
            REQUIRE_EQUAL( x.test_bit( 7 ), false );
            REQUIRE_EQUAL( x.test_bit( 8 ), true );
            REQUIRE_EQUAL( x.test_bit( 9 ), false );
            REQUIRE_EQUAL( x.test_bit( 15 ), false );
            REQUIRE_EQUAL( x.test_bit( 16 ), true );
            REQUIRE_EQUAL( x.test_bit( 17 ), false );
            REQUIRE_EQUAL( x.test_bit( 23 ), false );
            REQUIRE_EQUAL( x.test_bit( 24 ), true );
            REQUIRE_EQUAL( x.test_bit( 25 ), false );
            REQUIRE_EQUAL( x.test_bit( 31 ), false );
            REQUIRE_EQUAL( x.test_bit( 32 ), false );
            REQUIRE_EQUAL( x.test_bit( 33 ), false );
            REQUIRE_EQUAL( x.test_bit( 39 ), false );
            REQUIRE_EQUAL( x.test_bit( 40 ), true );
            REQUIRE_EQUAL( x.test_bit( 41 ), false );
            REQUIRE_EQUAL( x.test_bit( 47 ), false );
            REQUIRE_EQUAL( x.test_bit( 48 ), true );
            REQUIRE_EQUAL( x.test_bit( 49 ), false );
            REQUIRE_EQUAL( x.test_bit( 55 ), false );
            REQUIRE_EQUAL( x.test_bit( 56 ), false );
            REQUIRE_EQUAL( x.test_bit( 57 ), false );
            REQUIRE_EQUAL( x.test_bit( 58 ), false );
            REQUIRE_EQUAL( x.test_bit( 59 ), false );
            REQUIRE_EQUAL( x.test_bit( 60 ), false );
            REQUIRE_EQUAL( x.test_bit( 61 ), false );
            REQUIRE_EQUAL( x.test_bit( 62 ), false );
            REQUIRE_EQUAL( x.test_bit( 63 ), false );
            REQUIRE_EQUAL( x.is_zero(), false );
            REQUIRE_EQUAL( x.is_negative(), false );
            REQUIRE_EQUAL( x.bit_length(), 49 );
            REQUIRE_EQUAL( x.byte_length(), 7 );
            REQUIRE_EQUAL( x.word_length(), 2 );
            REQUIRE_EQUAL( x.size(), 2 );

            x.set_bit( 48, false );
            REQUIRE_EQUAL( x, 0x10001010101ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x10001010101ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), true  )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), true  )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), true  )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), true  )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), true  )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), false )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 41 )
            REQUIRE_EQUAL( x.byte_length(), 6 )
            REQUIRE_EQUAL( x.word_length(), 2 )
            REQUIRE_EQUAL( x.size(), 2 )

            x.set_bit( 8, false );
            REQUIRE_EQUAL( x, 0x10001010001ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x10001010001ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), true  )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), false )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), true  )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), true  )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), true  )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), false )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 41 )
            REQUIRE_EQUAL( x.byte_length(), 6 )
            REQUIRE_EQUAL( x.word_length(), 2 )
            REQUIRE_EQUAL( x.size(), 2 )

            x.set_bit( 16, false );
            REQUIRE_EQUAL( x, 0x10001000001ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x10001000001ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), true )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), false )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), false )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), true  )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), true  )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), false )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 41 )
            REQUIRE_EQUAL( x.byte_length(), 6 )
            REQUIRE_EQUAL( x.word_length(), 2 )
            REQUIRE_EQUAL( x.size(), 2 )

            x.set_bit( 40, false );
            REQUIRE_EQUAL( x, 0x1000001ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x1000001ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), true )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), false )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), false )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), true  )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), false )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), false )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 25 )
            REQUIRE_EQUAL( x.byte_length(), 4 )
            REQUIRE_EQUAL( x.word_length(), 1 )
            REQUIRE_EQUAL( x.size(), 1 )

            x.set_bit( 0, false );
            REQUIRE_EQUAL( x, 0x1000000ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0x1000000ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), false )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), false )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), false )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), true  )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), false )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), false )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 25 )
            REQUIRE_EQUAL( x.byte_length(), 4 )
            REQUIRE_EQUAL( x.word_length(), 1 )
            REQUIRE_EQUAL( x.size(), 1 )

            x.set_bit( 24, false );
            REQUIRE_EQUAL( x, 0ULL )
            REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0ULL )
            REQUIRE_EQUAL( x.test_bit( 0 ), false )
            REQUIRE_EQUAL( x.test_bit( 1 ), false )
            REQUIRE_EQUAL( x.test_bit( 7 ), false )
            REQUIRE_EQUAL( x.test_bit( 8 ), false )
            REQUIRE_EQUAL( x.test_bit( 9 ), false )
            REQUIRE_EQUAL( x.test_bit( 15 ), false )
            REQUIRE_EQUAL( x.test_bit( 16 ), false )
            REQUIRE_EQUAL( x.test_bit( 17 ), false )
            REQUIRE_EQUAL( x.test_bit( 23 ), false )
            REQUIRE_EQUAL( x.test_bit( 24 ), false )
            REQUIRE_EQUAL( x.test_bit( 25 ), false )
            REQUIRE_EQUAL( x.test_bit( 31 ), false )
            REQUIRE_EQUAL( x.test_bit( 32 ), false )
            REQUIRE_EQUAL( x.test_bit( 33 ), false )
            REQUIRE_EQUAL( x.test_bit( 39 ), false )
            REQUIRE_EQUAL( x.test_bit( 40 ), false )
            REQUIRE_EQUAL( x.test_bit( 41 ), false )
            REQUIRE_EQUAL( x.test_bit( 47 ), false )
            REQUIRE_EQUAL( x.test_bit( 48 ), false )
            REQUIRE_EQUAL( x.test_bit( 49 ), false )
            REQUIRE_EQUAL( x.test_bit( 55 ), false )
            REQUIRE_EQUAL( x.test_bit( 56 ), false )
            REQUIRE_EQUAL( x.test_bit( 57 ), false )
            REQUIRE_EQUAL( x.test_bit( 58 ), false )
            REQUIRE_EQUAL( x.test_bit( 59 ), false )
            REQUIRE_EQUAL( x.test_bit( 60 ), false )
            REQUIRE_EQUAL( x.test_bit( 61 ), false )
            REQUIRE_EQUAL( x.test_bit( 62 ), false )
            REQUIRE_EQUAL( x.test_bit( 63 ), false )
            REQUIRE_EQUAL( x.is_zero(), true )
            REQUIRE_EQUAL( x.is_negative(), false )
            REQUIRE_EQUAL( x.bit_length(), 1 )
            REQUIRE_EQUAL( x.byte_length(), 1 )
            REQUIRE_EQUAL( x.word_length(), 1 )
            REQUIRE_EQUAL( x.size(), 1 )

            // Test bit operations on single bit up to 64 bits
            for ( uint64_t i = 0; i < 64; i++ ) {
                x.set_bit(i, true);
                REQUIRE_EQUAL( x.test_bit(i), true )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), ( 1ULL << i ) )

                x.set_bit(i, false);
                REQUIRE_EQUAL( x.test_bit(i), false )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 )
                REQUIRE_EQUAL( x.is_zero(), true )

                REQUIRE_EQUAL( ( x | (1ULL << i) ), ( 1ULL << i ))
                REQUIRE_EQUAL( x.test_bit(i), false )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 )
                REQUIRE_EQUAL( x.is_zero(), true )

                x |= ( 1ULL << i );
                REQUIRE_EQUAL( x.test_bit(i), true )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), ( 1ULL << i ))

                REQUIRE_EQUAL( ( x & ~( 1ULL << i ) ), 0 )
                REQUIRE_EQUAL( x.test_bit(i), true )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), ( 1ULL << i ))

                x &=  ~( 1ULL << i );
                REQUIRE_EQUAL( x.test_bit(i), false )
                REQUIRE_EQUAL( ( x & 0xFFFFFFFFFFFFFFFFULL ), 0 )
                REQUIRE_EQUAL( x.is_zero(), true )
            }
        }

        // Test construction and serialization from hex strings & byte arrays
        {
            using bn_t = fixed_bigint<512>;
            REQUIRE_EQUAL( bn_t( fixed_bytes<0>() ).size() , 1 )
            REQUIRE_EQUAL( bn_t( fixed_bytes<0>() ).word_length() , 1 )
            REQUIRE_EQUAL( bn_t( fixed_bytes<0>() ).byte_length() , 1 )
            REQUIRE_EQUAL( bn_t( fixed_bytes<0>() ).bit_length() , 1 )
            REQUIRE_EQUAL( bn_t( fixed_bytes<0>() ).is_negative() , false )
            REQUIRE_EQUAL( (bn_t(-0x800000) = fixed_bytes<0>()).size() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = fixed_bytes<0>()).word_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = fixed_bytes<0>()).byte_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = fixed_bytes<0>()).bit_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = fixed_bytes<0>()).is_negative() , false )

            REQUIRE_EQUAL( bn_t( bytes() ).size() , 1 )
            REQUIRE_EQUAL( bn_t( bytes() ).word_length() , 1 )
            REQUIRE_EQUAL( bn_t( bytes() ).byte_length() , 1 )
            REQUIRE_EQUAL( bn_t( bytes() ).bit_length() , 1 )
            REQUIRE_EQUAL( bn_t( bytes() ).is_negative() , false )
            REQUIRE_EQUAL( (bn_t(-0x800000) = bytes()).size() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = bytes()).word_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = bytes()).byte_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = bytes()).bit_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = bytes()).is_negative() , false )

            REQUIRE_EQUAL( bn_t( "" ).size() , 1 );
            REQUIRE_EQUAL( bn_t( "" ).word_length() , 1 )
            REQUIRE_EQUAL( bn_t( "" ).byte_length() , 1 )
            REQUIRE_EQUAL( bn_t( "" ).bit_length() , 1 )
            REQUIRE_EQUAL( bn_t( "" ).is_negative() , false )
            REQUIRE_EQUAL( (bn_t(-0x800000) = "").size() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = "").word_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = "").byte_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = "").bit_length() , 1 )
            REQUIRE_EQUAL( (bn_t(-0x800000) = "").is_negative() , false )

            bn_t t(-0x800000);
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 3 )
            REQUIRE_EQUAL( t.bit_length()  , 24 )
            REQUIRE_EQUAL( t.is_negative() , true )

            t = fixed_bytes<0>();
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 1 )
            REQUIRE_EQUAL( t.bit_length()  , 1 )
            REQUIRE_EQUAL( t.is_negative() , false )

            t = -0x800000;
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 3 )
            REQUIRE_EQUAL( t.bit_length()  , 24 )
            REQUIRE_EQUAL( t.is_negative() , true )

            t = bytes();
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 1 )
            REQUIRE_EQUAL( t.bit_length()  , 1 )
            REQUIRE_EQUAL( t.is_negative() , false )

            t = -0x800000;
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 3 )
            REQUIRE_EQUAL( t.bit_length()  , 24 )
            REQUIRE_EQUAL( t.is_negative() , true )

            t = "";
            REQUIRE_EQUAL( t.size() , 1 )
            REQUIRE_EQUAL( t.word_length() , 1 )
            REQUIRE_EQUAL( t.byte_length() , 1 )
            REQUIRE_EQUAL( t.bit_length()  , 1 )
            REQUIRE_EQUAL( t.is_negative() , false )

            bigint_ser_test<tv1>().do_tests();
            bigint_ser_test<tv2>().do_tests();
            bigint_ser_test<tv3>().do_tests();
            bigint_ser_test<tv4>().do_tests();
            bigint_ser_test<tv5>().do_tests();
            bigint_ser_test<tv6>().do_tests();
            bigint_ser_test<tv7>().do_tests();
            bigint_ser_test<tv8>().do_tests();
            bigint_ser_test<tv9>().do_tests();
            bigint_ser_test<tv10>().do_tests();
            bigint_ser_test<tv11>().do_tests();
            bigint_ser_test<tv12>().do_tests();
            bigint_ser_test<tv13>().do_tests();
            bigint_ser_test<tv14>().do_tests();
            bigint_ser_test<tv15>().do_tests();
            bigint_ser_test<tv16>().do_tests();
            bigint_ser_test<tv17>().do_tests();
            bigint_ser_test<tv18>().do_tests();
            bigint_ser_test<tv19>().do_tests();
            bigint_ser_test<tv20>().do_tests();
            bigint_ser_test<tv21>().do_tests();
            bigint_ser_test<tv22>().do_tests();
            bigint_ser_test<tv23>().do_tests();
            bigint_ser_test<tv24>().do_tests();
            bigint_ser_test<tv25>().do_tests();
            bigint_ser_test<tv26>().do_tests();
            bigint_ser_test<tv27>().do_tests();
            bigint_ser_test<tv28>().do_tests();
            bigint_ser_test<tv29>().do_tests();
            bigint_ser_test<tv30>().do_tests();
            bigint_ser_test<tv31>().do_tests();
            bigint_ser_test<tv32>().do_tests();
            bigint_ser_test<tv33>().do_tests();
            bigint_ser_test<tv34>().do_tests();
            bigint_ser_test<tv35>().do_tests();
            bigint_ser_test<tv36>().do_tests();
            bigint_ser_test<tv37>().do_tests();
            bigint_ser_test<tv38>().do_tests();
            bigint_ser_test<tv39>().do_tests();
            bigint_ser_test<tv40>().do_tests();
            bigint_ser_test<tv41>().do_tests();
            bigint_ser_test<tv42>().do_tests();
            bigint_ser_test<tv43>().do_tests();
            bigint_ser_test<tv44>().do_tests();
            bigint_ser_test<tv45>().do_tests();
            bigint_ser_test<tv46>().do_tests();
            bigint_ser_test<tv47>().do_tests();
            bigint_ser_test<tv48>().do_tests();
            bigint_ser_test<tv49>().do_tests();
            bigint_ser_test<tv50>().do_tests();
            bigint_ser_test<tv51>().do_tests();
            bigint_ser_test<tv52>().do_tests();
            bigint_ser_test<tv53>().do_tests();
            bigint_ser_test<tv54>().do_tests();
            bigint_ser_test<tv55>().do_tests();
            bigint_ser_test<tv56>().do_tests();
            bigint_ser_test<tv57>().do_tests();
            bigint_ser_test<tv58>().do_tests();
            bigint_ser_test<tv59>().do_tests();
            bigint_ser_test<tv60>().do_tests();
            bigint_ser_test<tv61>().do_tests();
            bigint_ser_test<tv62>().do_tests();
            bigint_ser_test<tv63>().do_tests();
            bigint_ser_test<tv64>().do_tests();
            bigint_ser_test<tv65>().do_tests();
            bigint_ser_test<tv66>().do_tests();
            bigint_ser_test<tv67>().do_tests();
            bigint_ser_test<tv68>().do_tests();
            bigint_ser_test<tv69>().do_tests();
            bigint_ser_test<tv70>().do_tests();
            bigint_ser_test<tv71>().do_tests();
            bigint_ser_test<tv72>().do_tests();
            bigint_ser_test<tv73>().do_tests();
            bigint_ser_test<tv74>().do_tests();
            bigint_ser_test<tv75>().do_tests();
            bigint_ser_test<tv76>().do_tests();
            bigint_ser_test<tv77>().do_tests();
            bigint_ser_test<tv78>().do_tests();
            bigint_ser_test<tv79>().do_tests();
            bigint_ser_test<tv80>().do_tests();
            bigint_ser_test<tv81>().do_tests();
            bigint_ser_test<tv82>().do_tests();
            bigint_ser_test<tv83>().do_tests();
            bigint_ser_test<tv84>().do_tests();
            bigint_ser_test<tv85>().do_tests();
            bigint_ser_test<tv86>().do_tests();
            bigint_ser_test<tv87>().do_tests();
        }
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( bigint_arithmetic_test )
        using namespace detail;

        // Test negation
        {
            using bn_t = fixed_bigint<32>;
            REQUIRE_EQUAL( bn_t(0).neg(), 0 )
            REQUIRE_EQUAL( -bn_t(0), 0 )
            REQUIRE_EQUAL( bn_t(0).neg().is_negative(), false )
            REQUIRE_EQUAL( ( -bn_t(0) ).is_negative(), false )
            REQUIRE_EQUAL( bn_t(0).neg().neg().is_negative(), false )
            REQUIRE_EQUAL( ( -( -bn_t(0) )).is_negative(), false )
            REQUIRE_EQUAL( bn_t(-1).is_negative(), true )
            REQUIRE_EQUAL( bn_t(1).neg().is_negative(), true )
            REQUIRE_EQUAL( ( -bn_t(1) ).is_negative(), true )
            REQUIRE_EQUAL( bn_t(1).neg().neg().is_negative(), false )
            REQUIRE_EQUAL( ( -( -bn_t(1) )).is_negative(), false )
            REQUIRE_EQUAL( bn_t(-1).neg().neg().is_negative(), true )
            REQUIRE_EQUAL( ( -( -bn_t(-1) )).is_negative(), true )
            REQUIRE_EQUAL( bn_t(1).neg(), -1 )
            REQUIRE_EQUAL( -bn_t(1), -1 )
            REQUIRE_EQUAL( bn_t(-1).neg(), 1 )
            REQUIRE_EQUAL( -bn_t(-1), 1 )
            REQUIRE_EQUAL( bn_t(0x7FFFFFFF).neg(), -0x7FFFFFFF )
            REQUIRE_EQUAL( -bn_t(0x7FFFFFFF), -0x7FFFFFFF )
            REQUIRE_EQUAL( bn_t(-0x7FFFFFFF).neg(), 0x7FFFFFFF )
            REQUIRE_EQUAL( -bn_t(-0x7FFFFFFF), 0x7FFFFFFF )
            REQUIRE_EQUAL( bn_t(0x80000000).is_negative(), false )
            REQUIRE_EQUAL( bn_t(0x80000000).neg().is_negative(), true )
            REQUIRE_EQUAL( ( -bn_t(0x80000000) ).is_negative(), true )
            REQUIRE_EQUAL( bn_t(0x80000000).neg().is_negative(), true )
            REQUIRE_EQUAL( ( -bn_t(-0x80000000) ).neg().is_negative(), false )
            REQUIRE_EQUAL( bn_t(0x8000000).neg(), -0x8000000 ) // internally -0x80000000 is invalid var and can be directly tested, so we use -0x8000000
            REQUIRE_EQUAL( -bn_t(0x8000000), -0x8000000 )
            REQUIRE_EQUAL( bn_t(-0x8000000).neg(), 0x8000000 )
            REQUIRE_EQUAL( -bn_t(-0x8000000), 0x8000000 )
            REQUIRE_EQUAL( bn_t(0x8000001).neg(), -0x8000001 )
            REQUIRE_EQUAL( -bn_t(0x8000001), -0x8000001 )
            REQUIRE_EQUAL( bn_t(-0x8000001).neg(), 0x8000001 )
            REQUIRE_EQUAL( -bn_t(-0x8000001), 0x8000001 )
        }

        // Test absolute value
        {
            using bn_t = fixed_bigint<512>;
            REQUIRE_EQUAL( bn_t::abs(bn_t(0)), 0 )
            REQUIRE_EQUAL( bn_t(0).abs().is_negative(), false )
            REQUIRE_EQUAL( bn_t::abs(bn_t(0)).is_negative(), false )
            REQUIRE_EQUAL( bn_t(0).abs(), 0 )

            REQUIRE_EQUAL( bn_t::abs(bn_t(1)).is_negative(), false )
            REQUIRE_EQUAL( bn_t::abs(bn_t::abs(bn_t(1))).is_negative(), false )
            REQUIRE_EQUAL( bn_t::abs(bn_t(-1)).is_negative(), false )
            REQUIRE_EQUAL( bn_t::abs(bn_t::abs(bn_t(-1))).is_negative(), false )
            REQUIRE_EQUAL( bn_t::abs(bn_t::abs(bn_t::abs(bn_t(-1)))).is_negative(), false )

            REQUIRE_EQUAL( bn_t(1).abs().is_negative(), false )
            REQUIRE_EQUAL( bn_t(1).abs().abs().is_negative(), false )
            REQUIRE_EQUAL( bn_t(-1).abs().is_negative(), false )
            REQUIRE_EQUAL( bn_t(-1).abs().abs().is_negative(), false )
            REQUIRE_EQUAL( bn_t(-1).abs().abs().abs().is_negative(), false )

            REQUIRE_EQUAL( bn_t::abs(bn_t(1)), 1 )
            REQUIRE_EQUAL( bn_t(1).abs(), 1 )
            REQUIRE_EQUAL( bn_t::abs(bn_t(-1)), 1 )
            REQUIRE_EQUAL( bn_t(-1).abs(), 1 )
            REQUIRE_EQUAL( bn_t(-1).abs().abs(), 1 )

            REQUIRE_EQUAL( bn_t::abs(bn_t(0x7FFFFFFF)), 0x7FFFFFFF ) // 2147483647 is the largest positive 32-bit signed integer
            REQUIRE_EQUAL( bn_t(0x7FFFFFFF).abs(), 0x7FFFFFFF )
            REQUIRE_EQUAL( bn_t::abs(bn_t(-0x7FFFFFFF)), 0x7FFFFFFF )
            REQUIRE_EQUAL( bn_t(-0x7FFFFFFF).abs(), 0x7FFFFFFF )
            REQUIRE_EQUAL( bn_t::abs(bn_t(0x80000000)), 0x80000000 ) // 2147483648 is the largest positive 32-bit signed integer + 1
            REQUIRE_EQUAL( bn_t(0x80000000).abs(), 0x80000000 )
            REQUIRE_EQUAL( bn_t::abs(bn_t(-0x80000000)), 0x80000000 )
            REQUIRE_EQUAL( bn_t(-0x80000000).abs(), 0x80000000 )
            REQUIRE_EQUAL( bn_t::abs(bn_t(0x80000001)), 0x80000001 )
            REQUIRE_EQUAL( bn_t(0x80000001).abs(), 0x80000001 )
            REQUIRE_EQUAL( bn_t::abs(-bn_t(0x80000001)), 0x80000001 )
            REQUIRE_EQUAL( ( -bn_t(0x80000001) ).abs(), 0x80000001 )

            // Test absolute value of 64bit values
            REQUIRE_EQUAL( bn_t::abs(bn_t(0x7FFFFFFFFFFFFFFFLL)), 0x7FFFFFFFFFFFFFFFLL ) // 9223372036854775807 is the largest positive 64-bit signed integer
            REQUIRE_EQUAL( bn_t(0x7FFFFFFFFFFFFFFFLL).abs(), 0x7FFFFFFFFFFFFFFFLL )
            REQUIRE_EQUAL( bn_t::abs(-bn_t(0x7FFFFFFFFFFFFFFFLL)), 0x7FFFFFFFFFFFFFFFLL ) // 9223372036854775807 is the largest positive 64-bit signed integer
            REQUIRE_EQUAL( ( -bn_t(0x7FFFFFFFFFFFFFFFLL) ).abs(), 0x7FFFFFFFFFFFFFFFLL )
            REQUIRE_EQUAL( bn_t::abs(bn_t(-0x8000000000000000LL)), 0x8000000000000000ULL ) // -9223372036854775808 is the smallest negative 64-bit signed integer
            REQUIRE_EQUAL( ( bn_t(-0x8000000000000000LL) ).abs(), 0x8000000000000000ULL )
            REQUIRE_EQUAL( bn_t::abs(-bn_t(0x8000000000000000ULL)), 0x8000000000000000ULL ) // 18446744073709551615 is the largest positive 64-bit unsigned integer
            REQUIRE_EQUAL( ( -bn_t(0x8000000000000000ULL) ).abs(), 0x8000000000000000ULL )

            // Some larger integer tests
            REQUIRE_EQUAL( bn_t::abs(bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")), "FFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF").abs()     , "FFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t::abs(-bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")), "FFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( ( -bn_t("FFFFFFFFFFFFFFFFFFFFFFFF") ).abs() , "FFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").abs()     , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t::abs( -bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( ( -bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ).abs()   , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").abs()     , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t::abs(-bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( ( -bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ).abs() , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            REQUIRE_EQUAL( bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").abs()     , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            REQUIRE_EQUAL( bn_t::abs(-bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            REQUIRE_EQUAL( ( -bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ).abs() , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

            REQUIRE_EQUAL( bn_t::abs(-bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").abs()      , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(-bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( ( -bn_t("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ).abs() , "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" );

            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").abs(),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )

            REQUIRE_EQUAL( bn_t::abs(-bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
            REQUIRE_EQUAL( ( -bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") ).abs() ,
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" )
        }

        // Fixed addition and subtraction of 64bit values
        {
            using bn_t = fixed_bigint<64*2>;  // double size required for subtraction
            int64_t tv = -0x100000;
            auto t = bn_t(-0x100000);
            REQUIRE_EQUAL( t + 0, tv )
            REQUIRE_EQUAL( t + bn_t(0), tv )
            REQUIRE_EQUAL( t + 0, tv + 0 )
            REQUIRE_EQUAL( 0 + t, tv )
            REQUIRE_EQUAL( bn_t(0) + t, tv )
            REQUIRE_EQUAL( 0 + t, 0 + tv )
            REQUIRE_EQUAL( t - 0, tv )
            REQUIRE_EQUAL( t - bn_t(0), tv )
            REQUIRE_EQUAL( t - 0, tv - 0 )
            REQUIRE_EQUAL( 0 - t, -tv )
            REQUIRE_EQUAL( bn_t(0) - t, -tv )
            REQUIRE_EQUAL( 0 - t, 0 - tv )

            // Test 32bit integer addition to final sum 1742343624 (0x67a0dc98)
            for ( uint32_t i = 1; i < 0x7FFFFFFE; i *= ( i %2 ? 3 : 2 )) {
                REQUIRE_EQUAL( t + i, int32_t(tv + i) )
                REQUIRE_EQUAL( i + t, int32_t(i + tv) )

                REQUIRE_EQUAL( t + bn_t( i ), int32_t(tv + i) )
                REQUIRE_EQUAL( bn_t( i ) + t, int32_t(i + tv) )

                auto tmp = t;
                tmp += bn_t( i );

                t  += i;
                tv += i;
                REQUIRE_EQUAL(   t, tv )
                REQUIRE_EQUAL( tmp, tv )
                REQUIRE_EQUAL( t.bit_length() , bit_width( tv ) )
                REQUIRE_EQUAL( t.is_zero()    , ( tv == 0 ) )
                REQUIRE_EQUAL( t.is_negative(), ( tv < 0  ) )
                REQUIRE_EQUAL( t.word_length(), 1 )
                REQUIRE_EQUAL( t.size()       , 1 )
            }
            REQUIRE_EQUAL( t, tv         )
            REQUIRE_EQUAL( t, 1742343624 )
            REQUIRE_EQUAL( t.is_negative(), false )
            REQUIRE_EQUAL( t.is_zero()    , false )
            REQUIRE_EQUAL( t.bit_length() , 31 )
            REQUIRE_EQUAL( t.byte_length(), 4  )
            REQUIRE_EQUAL( t.word_length(), 1  )
            REQUIRE_EQUAL( t.size()       , 1  )

            // Test 64bit integer addition to final 425386648345
           for ( uint64_t i = 1; i < 0x8000000000ULL; i *= ( i % 2 ? 3 : 4 ) ) {
                REQUIRE_EQUAL( t + i, int64_t(tv + i) )
                REQUIRE_EQUAL( i + t, int64_t(i + tv) )

                REQUIRE_EQUAL( t + bn_t( i ), int64_t(tv + i) )
                REQUIRE_EQUAL( bn_t( i ) + t, int64_t(i + tv) )

                auto tmp = t;
                tmp += bn_t( i );

                t  += i;
                tv += i;
                REQUIRE_EQUAL(   t, tv )
                REQUIRE_EQUAL( tmp, tv )
                REQUIRE_EQUAL( t  , tv )
                REQUIRE_EQUAL( tmp, tv )
                REQUIRE_EQUAL( t.bit_length() , bit_width( tv ) )
                REQUIRE_EQUAL( t.is_zero()    , ( tv == 0 ) )
                REQUIRE_EQUAL( t.is_negative(), ( tv < 0  ) )
                REQUIRE_EQUAL( t.word_length(), tv < 0x100000000LL ? 1 : 2 )
                REQUIRE_EQUAL( t.size()       , tv < 0x100000000LL ? 1 : 2 )
            }
            REQUIRE_EQUAL( t, tv             )
            REQUIRE_EQUAL( t, 425386648345LL )

            // Subtraction test
            REQUIRE_EQUAL( t + -bn_t(1), 425386648344LL );

            // Test subtraction to final sum -2392094318 (-0x8e94766e')
            for ( int64_t i = 0x3999999995LL; i > 0; ( i /= 2 )) {
                if ( i > t ) {
                    i /= 2;
                }

                REQUIRE_EQUAL( t - i, int64_t(tv - i) )
                REQUIRE_EQUAL( i - t, int64_t(i - tv) )

                REQUIRE_EQUAL( t - bn_t( i ), int64_t(tv - i) )
                REQUIRE_EQUAL( bn_t( i ) - t, int64_t(i - tv) )

                auto tmp = t;
                tmp -= bn_t( i );

                t  -= i;
                tv -= i;
                REQUIRE_EQUAL( t  , tv )
                REQUIRE_EQUAL( tmp, tv )
                REQUIRE_EQUAL( t  , tv )
                REQUIRE_EQUAL( tmp, tv )
                REQUIRE_EQUAL( t.bit_length() , bit_width( tv ) )
                REQUIRE_EQUAL( t.is_zero()    , ( tv == 0 ) )
                REQUIRE_EQUAL( t.is_negative(), ( tv < 0  ) )
                REQUIRE_EQUAL( t.word_length(), tv < 0x100000000LL ? 1 : 2 )
                REQUIRE_EQUAL( t.size()       , tv < 0x100000000LL ? 1 : 2 )
            }
            REQUIRE_EQUAL( t, tv            )
            REQUIRE_EQUAL( t, -2392094318LL )
        }

        // Fixed multiplication, division and modulo of 64bit values
        {
            using bn_t = fixed_bigint<384>;
            int64_t tv = 85; // b01010101
            auto t = bn_t(85);

            REQUIRE_EQUAL( t * 0, 0 )
            REQUIRE_EQUAL( t * bn_t(0), 0 )
            REQUIRE_EQUAL( t * bn_t(0), bn_t(0) )
            REQUIRE_EQUAL( t * 0, tv * 0 )
            REQUIRE_EQUAL( t * bn_t(0), tv * 0 )

            REQUIRE_EQUAL( t * 1, t )
            REQUIRE_EQUAL( t * bn_t(1), t )
            REQUIRE_EQUAL( t * bn_t(1), bn_t(t) )
            REQUIRE_EQUAL( t * 1, tv * 1 )
            REQUIRE_EQUAL( t * bn_t(1), tv * 1 )

            REQUIRE_ASSERT( "division by zero", [&]() {
                t / 0;
            })
            REQUIRE_ASSERT( "division by zero", [&]() {
                t / bn_t(0);
            })
            REQUIRE_ASSERT( "mod by zero", [&]() {
                t % 0;
            })
            REQUIRE_ASSERT( "mod by zero", [&]() {
                t % bn_t(0);
            })

            REQUIRE_EQUAL( 0 / t, 0 )
            REQUIRE_EQUAL( bn_t(0) / t, 0 )
            REQUIRE_EQUAL( bn_t(0) / t, bn_t(0) )
            REQUIRE_EQUAL( 0 / t, 0 / tv )
            REQUIRE_EQUAL( bn_t(0) / t, 0 / tv )

            REQUIRE_EQUAL( t / 1, t )
            REQUIRE_EQUAL( t / bn_t(1), t )
            REQUIRE_EQUAL( t / bn_t(1), t )
            REQUIRE_EQUAL( t / 1, tv / 1 )
            REQUIRE_EQUAL( t / bn_t(1), tv / 1 )

            REQUIRE_EQUAL( 1 / t, 0 )
            REQUIRE_EQUAL( bn_t(1) / t, 0 )
            REQUIRE_EQUAL( bn_t(1) / t, bn_t(0) )
            REQUIRE_EQUAL( 1 / t, 1 / tv )
            REQUIRE_EQUAL( bn_t(1) / t, 1 / tv )

            REQUIRE_EQUAL( 0 % t, 0 )
            REQUIRE_EQUAL( bn_t(0) % t, 0 )
            REQUIRE_EQUAL( bn_t(0) % t, bn_t(0) )
            REQUIRE_EQUAL( 0 % t, 0 % tv )
            REQUIRE_EQUAL( bn_t(0) % t, 0 % tv )

            REQUIRE_EQUAL( t % 1, 0 )
            REQUIRE_EQUAL( t % bn_t(1), 0 )
            REQUIRE_EQUAL( t % bn_t(1), 0 )
            REQUIRE_EQUAL( t % 1, tv % 1 )
            REQUIRE_EQUAL( t % bn_t(1), tv % 1 )

            REQUIRE_EQUAL( 1 % t, 1 )
            REQUIRE_EQUAL( bn_t(1) % t, 1 )
            REQUIRE_EQUAL( bn_t(1) % t, bn_t(1) )
            REQUIRE_EQUAL( 1 % t, 1 % tv )
            REQUIRE_EQUAL( bn_t(1) % t, 1 % tv )

            // Test multiplication to final sum 1742343624 (0x67a0dc98)
            for ( uint32_t i = 1; i < 729; i *= 3 ) { // at 729 tv overflows
                auto neg_i = -int32_t(i);
                REQUIRE_EQUAL( t * neg_i, int32_t(tv * neg_i) )
                REQUIRE_EQUAL( neg_i * t, int32_t(neg_i * tv) )

                REQUIRE_EQUAL( t * bn_t( neg_i ), int32_t(tv * neg_i) )
                REQUIRE_EQUAL( bn_t( neg_i ) * t, int32_t(neg_i * tv) )

                auto tmp = t;
                tmp *= bn_t( neg_i );

                t  *= neg_i;
                tv *= neg_i;
                REQUIRE_EQUAL( t  , tv )
                REQUIRE_EQUAL( tmp, tv )
            }
            REQUIRE_EQUAL( t , tv         )
            REQUIRE_EQUAL( t , 1219657095 )

            // Test division to final sum -405140023 (0xe7da0dc9)
            for ( uint32_t i = 1; i < 256; i *= 2 ) { // at 256 t & tv are 0
                auto neg_i = -int32_t(i);
                REQUIRE_EQUAL( t / neg_i, int32_t(tv / neg_i) )
                REQUIRE_EQUAL( i / neg_i, int32_t(neg_i / tv) )

                REQUIRE_EQUAL( t / bn_t( neg_i ), int32_t(tv / neg_i) )
                REQUIRE_EQUAL( bn_t( neg_i ) / t, int32_t(neg_i / tv) )

                auto tmp = t;
                tmp /= bn_t( neg_i );

                t  /= neg_i;
                tv /= neg_i;
                REQUIRE_EQUAL( t  , tv )
                REQUIRE_EQUAL( tmp, tv )
            }
            REQUIRE_EQUAL( t == 4, (tv == 4) )

            // Test modulo
            // Modulus of a positive number
            REQUIRE_EQUAL( bn_t(10) % bn_t(3), 10 % 3  )
            REQUIRE_EQUAL( bn_t(10) % bn_t(3), bn_t(1) )

            // Modulus of a negative number
            REQUIRE_EQUAL( bn_t(-10) % bn_t(3), -10 % 3 )
            REQUIRE_EQUAL( bn_t(-10) % bn_t(3), bn_t(-1) )

            // Modulus of a number with a larger divisor
            REQUIRE_EQUAL( bn_t(10) % bn_t(20), 10 % 20  )
            REQUIRE_EQUAL( bn_t(10) % bn_t(20), bn_t(10) )

            // Modulus of a number with a smaller number
            REQUIRE_EQUAL( bn_t(10) % bn_t(5), 10 % 5  )
            REQUIRE_EQUAL( bn_t(10) % bn_t(5), bn_t(0) )

            // Modulus of a number with a negative divisor
            REQUIRE_EQUAL( bn_t(10) % bn_t(-3), 10 % -3 )
            REQUIRE_EQUAL( bn_t(10) % bn_t(-3), bn_t(1) )

            // Modulus of a negative number with a negative divisor
            REQUIRE_EQUAL( bn_t(-10) % bn_t(-3), -10 % -3 )
            REQUIRE_EQUAL( bn_t(-10) % bn_t(-3), bn_t(-1) )

            // Modulus of a number with a larger negative divisor
            REQUIRE_EQUAL( bn_t(10) % bn_t(-20), 10 % -20 )
            REQUIRE_EQUAL( bn_t(10) % bn_t(-20), bn_t(10) )

            // Modulus of a number with a smaller negative divisor
            REQUIRE_EQUAL( bn_t(10) % bn_t(-5), 10 % -5 )
            REQUIRE_EQUAL( bn_t(10) % bn_t(-5), bn_t(0) )

            // Modulus of a negative number with a positive divisor
            REQUIRE_EQUAL( bn_t(-10) % bn_t(3), -10 % 3  )
            REQUIRE_EQUAL( bn_t(-10) % bn_t(3), bn_t(-1) )

            // Modulus of a number with a larger positive divisor
            REQUIRE_EQUAL( bn_t(-10) % bn_t(20), -10 % 20  )
            REQUIRE_EQUAL( bn_t(-10) % bn_t(20), bn_t(-10) )

            // Modulus of a number with a smaller positive divisor
            REQUIRE_EQUAL( bn_t(-10) % bn_t(5), -10 % 5 )
            REQUIRE_EQUAL( bn_t(-10) % bn_t(5), bn_t(0) )

            // Modulo with a 128-bit number
            REQUIRE_EQUAL( bn_t("FEDCBA9876543210") % bn_t("7FFFFFFFFFFFFFFF"), bn_t("7EDCBA9876543211") )

            // Modulo with a 256-bit number
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") % bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"), 1 )

            // Modulo with a 384-bit number
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") % bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
                bn_t("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") )

            t = 1;
            tv = 1;
            int64_t i = 2;
            for ( int64_t j = 3; i < 0x800000000000LL; j *= ( j % 2 ? 2 : 3 ) ) {
                REQUIRE_EQUAL( -( t  + 0xFFFFFFFF ) %  i, -( tv + 0xFFFFFFFF ) %  i )
                REQUIRE_EQUAL(  ( t  + 0xFFFFFFFF ) %  i,  ( tv + 0xFFFFFFFF ) %  i )
                REQUIRE_EQUAL(  ( t  + 0xFFFFFFFF ) % -i,  ( tv + 0xFFFFFFFF ) % -i )
                REQUIRE_EQUAL( -( t  + 0xFFFFFFFF ) %  i, -( tv + 0xFFFFFFFF ) %  i )
                REQUIRE_EQUAL( -( t  + 0xFFFFFFFF ) % -i, -( tv + 0xFFFFFFFF ) % -i )
                REQUIRE_EQUAL(  ( t  + 0xFFFFFFFF ) % -i,  ( tv + 0xFFFFFFFF ) % -i )
                REQUIRE_EQUAL( -( t  + 0xFFFFFFFF ) % -i, -( tv + 0xFFFFFFFF ) % -i )

                t  = ( ( t  + 0xFFFFFFFF ) % i );
                tv = ( ( tv + 0xFFFFFFFF ) % i );
                REQUIRE_EQUAL( t, tv )
                i = j;
            }
            REQUIRE_EQUAL( t == 43191120327LL, (tv == 43191120327LL) )
        }

        // Large numbers arithmetics
        {
            using bn_t = fixed_bigint<512*2>; // mul & sub require double size
            // Addition
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         + bn_t("FFFFFFFFFFFFFFFFFFFFFFFF"), bn_t("01FFFFFFFFFFFFFFFFFFFFFFFE") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         + bn_t("01"), bn_t("01000000000000000000000000") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         + 1, bn_t("01000000000000000000000000") )
            REQUIRE_EQUAL( bn_t("0100000000000000000000000000")     + bn_t("0100000000000000000000000000"), bn_t("0200000000000000000000000000") )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") + bn_t("9876543210"), bn_t("0123456789ABCDEF012345FFFFFFFFFF") )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") + bn_t("0FEDCBA9876543210123456789ABCDEF"), bn_t("111111111111111002468ACF13579BDE") )

            REQUIRE_EQUAL(bn_t("B9F0390B2768C50BFDAD8060E4C0DAEFBD24376CC2D7899D174E0F116824BCC8") + bn_t("E08B2C2E4EF3B41CBBB23D9EC4FA887C1F12CBBB420BD88BFE155C09A96C25DD"),
                bn_t("019A7B6539765C7928B95FBDFFA9BB636BDC37032804E3622915636B1B1190E2A5"))

            // Subtraction
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         - bn_t("FFFFFFFFFFFFFFFFFFFFFFFF"), 0 )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         - bn_t("01"), bn_t("FFFFFFFFFFFFFFFFFFFFFFFE") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         - 1, bn_t("FFFFFFFFFFFFFFFFFFFFFFFE") )
            REQUIRE_EQUAL( bn_t("0100000000000000000000000000")     - bn_t("0100000000000000000000000000"), 0 )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") - bn_t("9876543210"), bn_t("0123456789ABCDEF012344CF13579BDF") );
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") - bn_t("0FEDCBA9876543210123456789ABCDEF"), -bn_t("0ECA8641FDB975320000000000000000") )

            REQUIRE_EQUAL(bn_t("C38E6B0B8B98AC0CE1547F39EFAD6C16B6D78F054F0D6B0EA87AF02A6CCD9B9A") - bn_t("081932C6B917B25DD1E6EC24BCEB373F9778D9B9BBE965BBC3B84D10D62CD1E6"),
                bn_t("BB753844D280F9AF0F6D931532C234D71F5EB54B93240552E4C2A31996A0C9B4"))

            // Multiplication
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         * bn_t("FFFFFFFFFFFFFFFFFFFFFFFF"), bn_t("FFFFFFFFFFFFFFFFFFFFFFFE000000000000000000000001") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         * bn_t("01"), bn_t("FFFFFFFFFFFFFFFFFFFFFFFF") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         * 1, bn_t("FFFFFFFFFFFFFFFFFFFFFFFF") )
            REQUIRE_EQUAL( bn_t("0100000000000000000000000000")     * bn_t("0100000000000000000000000000"), bn_t("010000000000000000000000000000000000000000000000000000") )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") * bn_t("9876543210"), bn_t("AD77D7433333329092D964333333328FE5618CF0") )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") * bn_t("0FEDCBA9876543210123456789ABCDEF"), bn_t("121FA00AD77D742236D88FE5618CEFFECA9AF86B7CB49CDCA5E20890F2A521") )
            REQUIRE_EQUAL(bn_t("1C43A04AFACB371BBEEB13FBF171A060013B2FB64A9C9F0C987B2C6FE26C6EF1") * bn_t("06E107CC6B1E71D56C6F9C6D35DECF7B737A1E7AE4A92AE4BB7E8D832C0E1383"),
                bn_t("C26E0E0EE098FF07E8A08FDC286D1B07ABE7C92E56A4E125DCF5241C73A937B8771CDBE99818EE9413940A98BD8A95A0FD634576B031261092926166E6A853"))

            // Division
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         / bn_t("FFFFFFFFFFFFFFFFFFFFFFFF"), 1 )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         / bn_t("01"), bn_t("FFFFFFFFFFFFFFFFFFFFFFFF") )
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFF")         / 1, bn_t("FFFFFFFFFFFFFFFFFFFFFFFF") )
            REQUIRE_EQUAL( bn_t("0100000000000000000000000000")     / bn_t("0100000000000000000000000000"), 1)
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") / bn_t("9876543210"), bn_t("01E9131ABF0B3C0B361EAE") )
            REQUIRE_EQUAL( bn_t("0123456789ABCDEF0123456789ABCDEF") / bn_t("0FEDCBA9876543210123456789ABCDEF"), 0 )
            REQUIRE_EQUAL(bn_t("38FE76F2495078F063E1070B7D6F41EA43FA450D6CDD9C76C23E40898C41C86D") / bn_t("3B3B3E3EF08C1D15C9B2A71ABEF78C01"),
                bn_t("F6546F0BA42282D01A41C096543F0AB1"))

            // Modulo
            REQUIRE_EQUAL( bn_t("7890ABCDEF1234567890ABCDEF") % bn_t("1234567890ABCDEF7890ABCDEF"), bn_t("0B56A4FA8B0B60B9A52CA4FA55"))
            REQUIRE_EQUAL( bn_t("FEDCBA9876543210FEDCBA9876543210") % bn_t("123456789ABCDEF0"), bn_t("E2E0"))
            REQUIRE_EQUAL( bn_t("12F234E5C06B7D81B054ACFA69A654C90DB25E070") % bn_t("123456789ABCDEF0"), bn_t("09EA91C4E18F9580"))
            REQUIRE_EQUAL(bn_t("38FE76F2495078F063E1070B7D6F41EA43FA450D6CDD9C76C23E40898C41C86D") % bn_t("3B3B3E3EF08C1D15C9B2A71ABEF78C01"),
                bn_t("7AA1C6CE8C187F138A5AA240F62F1BC"))
        }

        // Test multiplicative inverse
        {
            using bn_t = fixed_bigint<1024>;

            // Test vectors generated with python
            bn_t r;
            REQUIRE_EQUAL( bn_t::modinv( r, 0, 1 ),  true )
            REQUIRE_EQUAL( r, 0 )
            REQUIRE_EQUAL( bn_t( 0  ).modinv( 1 ) ,  0 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 1 ) ,  0 )
            REQUIRE_EQUAL( bn_t::modinv( r, 1, 17 ),  true )
            REQUIRE_EQUAL( r, 1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 17 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 11 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 10 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 100 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 1000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 10000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 100000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 1000000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 10000000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 100000000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 999999999 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 1000000000 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 10000000001LL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x01 ),  0 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x10 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x1010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x10101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x1010101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x10101010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x101010101ULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x1010101010ULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x10101010101ULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x101010101010LL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x1010101010101LL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x0101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x01010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x010101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x0101010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x01010101 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x010101010 ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x0101010101ULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x01010101010LL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x010101010101ULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x0101010101010LL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0x7FFFFFFFFFFFFULL ),  1 )
            REQUIRE_EQUAL( bn_t( 1  ).modinv( 0xFFFFFFFFFFFFFLL ),  1 )
            REQUIRE_EQUAL( bn_t( "00000000000001"  ).modinv( 0xFFFFFFFFFFFFFULL ),  1 )
            REQUIRE_EQUAL( bn_t( "0000000000000000000001"  ).modinv( 0xFFFFFFFFFFFFFLL ),  1 )
            REQUIRE_EQUAL( bn_t( "0000000000000000000000000001"  ).modinv( 0xFFFFFFFFFFFFFLL ),  1 )
            REQUIRE_EQUAL( bn_t::modinv( r, 3, 10 ),  true )
            REQUIRE_EQUAL( r, 7 )
            REQUIRE_EQUAL( bn_t( 3  ).modinv( 10 ),  7 )
            REQUIRE_EQUAL( bn_t( 7  ).modinv( 10 ),  3 )
            REQUIRE_EQUAL( bn_t( 9  ).modinv( 10 ),  9 )
            REQUIRE_EQUAL( bn_t( 11 ).modinv( 10 ),  1 )
            REQUIRE_EQUAL( bn_t( 13 ).modinv( 10 ),  7 )
            REQUIRE_EQUAL( bn_t( 17 ).modinv( 10 ),  3 )
            REQUIRE_EQUAL( bn_t( 19 ).modinv( 10 ),  9 )
            REQUIRE_EQUAL( bn_t( 21 ).modinv( 10 ),  1 )
            REQUIRE_EQUAL( bn_t::modinv( r, 3, 17 ),  true )
            REQUIRE_EQUAL( r, 6 )
            REQUIRE_EQUAL( bn_t( 3  ).modinv( 17 ),  6 )
            REQUIRE_EQUAL( bn_t( 5  ).modinv( 19 ),  4 )
            REQUIRE_EQUAL( bn_t( 7  ).modinv( 23 ), 10 )
            REQUIRE_EQUAL( bn_t( 2  ).modinv( 31 ), 16 )
            REQUIRE_EQUAL( bn_t( 6  ).modinv( 47 ),  8 )
            REQUIRE_EQUAL( bn_t( 13 ).modinv( 59 ), 50 )
            REQUIRE_EQUAL( bn_t( 31 ).modinv( 61 ),  2 )
            REQUIRE_EQUAL( bn_t( 11 ).modinv( 71 ), 13 )
            REQUIRE_EQUAL( bn_t( 19 ).modinv( 79 ), 25 )
            REQUIRE_EQUAL( bn_t( 23 ).modinv( 89 ), 31 )

            bn_t m("100000000000000000039");
            for ( uint32_t i = 1; i < 100; i++ ) {
                if ( i == 53 ) continue; // 53 is not invertible for the m
                bn_t x = bn_t( i );
                auto y = x.modinv( m );
                REQUIRE_EQUAL( ( y * x ) % m, 1);
            }

            // Test vectors generated with python
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890ABCDF")), bn_t("1234567890ABCDEF7890ABCDE") )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890ABCEF")), bn_t("E06746CD311CF77BF80647D9")  )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890ACDEF")), bn_t("5A8DDC811FD157C6C6988D1")   )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890BCDEF")), bn_t("A3A488FC79674663C321C5B4")  )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890DCDEF")), bn_t("91523409246FB409CDA6E5FE")  )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7890ECDEF")), bn_t("549E5E3252D1C50553BDDC23")  )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7891FCDEF")), bn_t("10452825C5CECAF60F54E8CC2") )
            REQUIRE_EQUAL( bn_t("1234567890ABCDEF7890ABCDEF").modinv(bn_t("1234567890ABCDEF7892FCDEF")), bn_t("891267A816DE4F23C7799B2D")  )

            // Mersenne prime 2^107-1
            REQUIRE_EQUAL( bn_t::modinv( r, "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", 655 ), true )
            REQUIRE_EQUAL( r, 202 )
            REQUIRE_EQUAL( bn_t("1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000").modinv( 655 ), 202 )

            REQUIRE_EQUAL( bn_t::modinv( r, "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", "1F01A01B01C01E01D01010101010101001" ), true )
            REQUIRE_EQUAL( r, "1545D9535378BE5B27D1096E3F179B336" )
            REQUIRE_EQUAL( bn_t("1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000").modinv( "1F01A01B01C01E01D01010101010101001" ), r )

            // 256-bit numbers
            REQUIRE_EQUAL( bn_t("AE7FD295C6DF1F6F882D9A0D65D621A58AA1E0A44C0EE24A504F1C192A8E07E0")
                .modinv(bn_t("E8CCF2A301AB5C4470D1745D5A5A5D127F9A4BB3C4E31F45F37DCE98606233C5")),
                    bn_t("24AC2DD72DA1EB9A32E0AEDE37A3E4504AE6C5D56D54D87951F8778BE5C403C2") )

            // 384-bit numbers
            REQUIRE_EQUAL( bn_t("11D531E8249C1F7CFF52082098B84BCD4413B3B3A3F54FE8F2F1B9B46B1EE9822EDDF8E47555AF05C32A6C051CD42A57")
                .modinv(bn_t("C9CE7DBA10B68EF84A96DE3B2663D7C8A61E9032FBD4F9C4E383FFC0B1EF2FB5C5FE5C5AC8E5F5D5B0C12968FDFD7F1")),
                    bn_t("9C747D073689632FE68DBE0D02DA963AED83A9C23EE3391945EE5DCA2801B95469B037165468584965990F65ECC2499") )

            REQUIRE_EQUAL( bn_t("FCA038B86C937F86DEA8D2D5A5C5F04F5D5F8A5A5D202E62B7C86FEAED8E8A0BBD311122EA120AD2B1461A19E31DA7D5")
                .modinv(bn_t("17D22BB38C3F768802E39CA8D8D8A97C3F3C14139309F9DD9CCD18E424B1838647C4D4D4F1B4B4E508F1C62D3737299")),
                    bn_t("A4FD1DE359B7AD552182EA4716ED88AB4FC3B9875B9BFD76CB1A6574CC966E665D60DCB685C0A727C21ABF1885D01B") )

            // 480-bit numbers
            REQUIRE_EQUAL( bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7")
                .modinv( bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC8") ),
                    bn_t("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7") )

            REQUIRE_EQUAL( bn_t("6F2F6CA3D6E5B6EF5B1B1500A21554A28D4219BA259C23A4C61D0C4E4A178A4E0A296F1F8CDA5B08A51E52F2A6A3F168A1DDBEE5A6DAAF0C3FF3C1CEC94FF7C")
                .modinv( bn_t("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028B2C980FC13AAAFD82D3857CC8C6320FE85") ),
                    bn_t("ED5F36E5DDF6F416F56A0A6702BB9DA4082"))

            // 512-bit numbers
            REQUIRE_EQUAL( bn_t("4D08382065A3FAF00EB65E7F1290A21C43CA3B3F0C301AC9D0D85B8222F2C427D19CAB657B46204AFD6A5F6F082A6F9A6A5F5E78B262A282ECD7A634872D0BDA")
                .modinv(bn_t("BA9F9B61D6112C732F0E95EB00D266C82EE29D6706E5B6BFC57D49C02FBDE5B16111F616D62E051EF7B43C2190638E29FCD98447FCBA75B9A1F3168F0BB08D85")),
                    bn_t("379C326CA0547AB26812734CA8C73532E1F20CE77EDED7B74475832D3DB8E84D8996CA0D24C0D9C7DF8CF9340634E8823C01C5CAF32627F8E9CCB6747BD48299") )

            // 720-bit numbers
            REQUIRE_EQUAL( bn_t("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
                .modinv(bn_t("3B7BFA384EC378C938C29E1BCDA92D1949F14F6EC066C942DEEAA6E13D6BAAE09D1E6BE8F6E9DB1D85D231875D3B0A47C3FC847A111A763C0A0E81FFDB8FD9F9")),
                    bn_t("3A75FD8B2BF100AB5E2968B04A79B998D82AB3DC79536381C6BA22E86D51E6C0BB4F31F8B4D8EED62A4AF76CBADAD25C90763291D22068275A1CA0F8887E5DB9") )

            // Test failures
            REQUIRE_ASSERT( "division by zero", [&]() {
                bn_t::modinv( r, 0, 0 );
            })

            REQUIRE_ASSERT( "division by zero", [&]() {
                bn_t( 0 ).modinv( 0 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 2 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 2 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 3 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 3 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 4 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 4 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 8 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 8 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 11 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 11 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 0, 16 ), false );
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( 16 );
            })

            // Bell's prime
            REQUIRE_EQUAL( bn_t::modinv( r, 0, "359334085968622831041960188598043661065388726959079837" ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 0 ).modinv( "359334085968622831041960188598043661065388726959079837" );
            })


            REQUIRE_EQUAL( bn_t::modinv( r, 2, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 2 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 4, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 4 ).modinv( 10 );
            })

            REQUIRE_ASSERT( "division by zero", [&]() {
                bn_t::modinv( r, 5, 0 );
            })

            REQUIRE_ASSERT( "division by zero", [&]() {
                bn_t( 5 ).modinv( 0 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 5, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 5 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 6, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 6 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 8, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 8 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 10, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 10 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 12, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 12 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 14, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 14 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 15, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 15 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 16, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 16 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 18, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 18 ).modinv( 10 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, 20, 10 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( 20 ).modinv( 10 );
            })

            // Mersenne prime 2^107-1
            REQUIRE_EQUAL( bn_t::modinv( r, "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", 654 ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000" ).modinv( 654 );
            })

            REQUIRE_EQUAL( bn_t::modinv( r, "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000", "1F01A01B01C01E01D010101010101010" ), false )
            REQUIRE_ASSERT( "modular inverse failed", [&]() {
                bn_t( "1FFFFFFFFFFFFFFFFFFFFFFFFFFC00000000000000000000000000" ).modinv( "1F01A01B01C01E01D010101010101010" );
            })
        }

        // Test left and right shifts
        {
            using bn_t = fixed_bigint<384>;

            REQUIRE_EQUAL( ( bn_t(0) << word_bit_size ), 0 )
            {
                bn_t a = 0, zero = 0;
                a <<= word_bit_size;
                REQUIRE_EQUAL( a.is_zero(), true )
                REQUIRE_EQUAL( a, zero )
            }

            REQUIRE_EQUAL( ( bn_t(1) << word_bit_size ), ( 1ULL << word_bit_size ))
            {
                bn_t a = 1;
                a <<= word_bit_size;
                REQUIRE_EQUAL( a, ( 1ULL << word_bit_size ))
            }

            // Test shl and shr moving 1 bit up & down
            // and do some more bit testing
            {
                bn_t a = 1;
                for ( uint64_t i = 0; i < 64; i++ ) {
                    uint64_t mask = (1ULL << i);
                    REQUIRE_EQUAL( ( a << i ), mask)

                    a <<= i;
                    REQUIRE_EQUAL( a.test_bit( i-1   ), false )
                    REQUIRE_EQUAL( a.test_bit( i     ), true )
                    REQUIRE_EQUAL( a.test_bit( i + 1 ), false )
                    REQUIRE_EQUAL( ( a & mask ), mask )
                    a = 1;
                }

                a <<= 63;
                for ( uint64_t i = 0; i < 64; i++ ) {
                    uint64_t mask = (1ULL << 63) >> i;
                    REQUIRE_EQUAL( ( a >> i ), mask)

                    a >>= i;
                    REQUIRE_EQUAL( a.test_bit(( 63 - i ) - 1), false )
                    REQUIRE_EQUAL( a.test_bit(( 63 - i )    ), true  )
                    REQUIRE_EQUAL( a.test_bit(( 63 - i ) + 1), false  )
                    REQUIRE_EQUAL( ( a & mask ), mask )
                    a <<= i;
                }
            }

            // Test cases taken from mcl library
            bn_t x("123423424918471928374192874198274981274918274918274918243");
            bn_t y, z, s;

            // shl
            for ( size_t i = 1; i < 31; i++ ) {
                bn_t::shl(y, x, i);
                z = x * ( word_t(1) << i );
                REQUIRE_EQUAL( y, z )

                y = x << i;
                REQUIRE_EQUAL( y, z )

                y = x;
                y <<= i;
                REQUIRE_EQUAL( y, z )
            }

            for ( int i = 0; i < 4; i++ ) {
                bn_t::shl( y, x, i * word_bit_size );
                bn_t::pow( s, bn_t(2), i * word_bit_size);
                z = x * s;
                REQUIRE_EQUAL( y, z )

                y = x << ( i * word_bit_size );
                REQUIRE_EQUAL( y, z )

                y = x;
                y <<= ( i * word_bit_size );
                REQUIRE_EQUAL( y, z )
            }

            for ( int i = 0; i < 100; i++ ) {
                y = x << i;
                bn_t::pow( s, bn_t(2), i );

                z = x * s;
                REQUIRE_EQUAL( y, z )

                y = x;
                y <<= i;
                REQUIRE_EQUAL( y, z )
            }

            // shr
            for (size_t i = 1; i < 31; i++) {
                bn_t::shr(y, x, i);
                z = x / ( word_t(1) << i );
                REQUIRE_EQUAL( y, z )

                y = x >> i;
                REQUIRE_EQUAL( y, z )

                y = x;
                y >>= i;
                REQUIRE_EQUAL( y, z )
            }

            for (int i = 0; i < 3; i++) {
                bn_t::shr(y, x, i * word_bit_size);
                bn_t::pow(s, bn_t(2), i * word_bit_size);
                z = x / s;
                REQUIRE_EQUAL( y, z )

                y = x >> (i * word_bit_size);
                REQUIRE_EQUAL( y, z )

                y = x;
                y >>= (i * word_bit_size);
                REQUIRE_EQUAL( y, z )
            }

            for (int i = 0; i < 100; i++) {
                y = x >> i;
                bn_t::pow( s, bn_t(2), i );
                z = x / s;
                REQUIRE_EQUAL( y, z )

                y = x;
                y >>= i;
                REQUIRE_EQUAL( y, z )
            }
        }
    EOSIO_TEST_END

    EOSIO_TEST_BEGIN( bigint_test )
        EOSIO_TEST( bigint_miscellaneous_test )
        EOSIO_TEST( bigint_arithmetic_test )
    EOSIO_TEST_END
}
