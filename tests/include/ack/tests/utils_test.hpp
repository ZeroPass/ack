// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/types.hpp>
#include <ack/utils.hpp>

#include <eosio/tester.hpp>

#include <string>
#include <string_view>

namespace ack::tests {
    EOSIO_TEST_BEGIN( utils_test )

        // Test word_t size helper functions
        {
            static_assert( sizeof( word_t ) == 4 );

            // bitsize
            REQUIRE_EQUAL( get_word_size_from_bitsize(0), 0 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(1), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(8), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(9), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(16), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(17), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(24), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(25), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(31), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(32), 1 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(33), 2 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(48), 2 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(49), 2 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(64), 2 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(65), 3 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(96), 3 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(97), 4 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(127), 4 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(128), 4 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(129), 5 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(160), 5 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(161), 6 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(192), 6 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(193), 7 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(224), 7 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(225), 8 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(255), 8 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(256), 8 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(257), 9 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(288), 9 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(289), 10 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(320), 10 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(321), 11 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(352), 11 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(353), 12 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(383), 12 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(384), 12 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(385), 13 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(416), 13 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(417), 14 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(448), 14 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(449), 15 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(480), 15 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(481), 16 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(511), 16 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(512), 16 )
            REQUIRE_EQUAL( get_word_size_from_bitsize(513), 17 )

            // char
            REQUIRE_EQUAL( get_word_size<char>(0), 0 )
            REQUIRE_EQUAL( get_word_size<char>(1), 1 )
            REQUIRE_EQUAL( get_word_size<char>(2), 1 )
            REQUIRE_EQUAL( get_word_size<char>(3), 1 )
            REQUIRE_EQUAL( get_word_size<char>(4), 1 )
            REQUIRE_EQUAL( get_word_size<char>(5), 2 )
            REQUIRE_EQUAL( get_word_size<char>(6), 2 )
            REQUIRE_EQUAL( get_word_size<char>(7), 2 )
            REQUIRE_EQUAL( get_word_size<char>(8), 2 )
            REQUIRE_EQUAL( get_word_size<char>(9), 3 )
            REQUIRE_EQUAL( get_word_size<char>(10), 3 )
            REQUIRE_EQUAL( get_word_size<char>(11), 3 )
            REQUIRE_EQUAL( get_word_size<char>(12), 3 )
            REQUIRE_EQUAL( get_word_size<char>(13), 4 )
            REQUIRE_EQUAL( get_word_size<char>(14), 4 )
            REQUIRE_EQUAL( get_word_size<char>(15), 4 )
            REQUIRE_EQUAL( get_word_size<char>(16), 4 )
            REQUIRE_EQUAL( get_word_size<char>(17), 5 )
            REQUIRE_EQUAL( get_word_size<char>(18), 5 )
            REQUIRE_EQUAL( get_word_size<char>(19), 5 )
            REQUIRE_EQUAL( get_word_size<char>(20), 5 )
            REQUIRE_EQUAL( get_word_size<char>(21), 6 )
            REQUIRE_EQUAL( get_word_size<char>(22), 6 )
            REQUIRE_EQUAL( get_word_size<char>(23), 6 )
            REQUIRE_EQUAL( get_word_size<char>(24), 6 )
            REQUIRE_EQUAL( get_word_size<char>(25), 7 )
            REQUIRE_EQUAL( get_word_size<char>(26), 7 )
            REQUIRE_EQUAL( get_word_size<char>(27), 7 )
            REQUIRE_EQUAL( get_word_size<char>(28), 7 )
            REQUIRE_EQUAL( get_word_size<char>(29), 8 )
            REQUIRE_EQUAL( get_word_size<char>(30), 8 )
            REQUIRE_EQUAL( get_word_size<char>(31), 8 )
            REQUIRE_EQUAL( get_word_size<char>(32), 8 )
            REQUIRE_EQUAL( get_word_size<char>(33), 9 )
            REQUIRE_EQUAL( get_word_size<char>(34), 9 )
            REQUIRE_EQUAL( get_word_size<char>(35), 9 )
            REQUIRE_EQUAL( get_word_size<char>(36), 9 )
            REQUIRE_EQUAL( get_word_size<char>(37), 10 )
            REQUIRE_EQUAL( get_word_size<char>(38), 10 )
            REQUIRE_EQUAL( get_word_size<char>(39), 10 )
            REQUIRE_EQUAL( get_word_size<char>(40), 10 )
            REQUIRE_EQUAL( get_word_size<char>(41), 11 )
            REQUIRE_EQUAL( get_word_size<char>(42), 11 )
            REQUIRE_EQUAL( get_word_size<char>(43), 11 )
            REQUIRE_EQUAL( get_word_size<char>(44), 11 )
            REQUIRE_EQUAL( get_word_size<char>(45), 12 )
            REQUIRE_EQUAL( get_word_size<char>(46), 12 )
            REQUIRE_EQUAL( get_word_size<char>(47), 12 )
            REQUIRE_EQUAL( get_word_size<char>(48), 12 )
            REQUIRE_EQUAL( get_word_size<char>(49), 13 )
            REQUIRE_EQUAL( get_word_size<char>(50), 13 )
            REQUIRE_EQUAL( get_word_size<char>(51), 13 )
            REQUIRE_EQUAL( get_word_size<char>(52), 13 )
            REQUIRE_EQUAL( get_word_size<char>(53), 14 )
            REQUIRE_EQUAL( get_word_size<char>(54), 14 )
            REQUIRE_EQUAL( get_word_size<char>(55), 14 )
            REQUIRE_EQUAL( get_word_size<char>(56), 14 )
            REQUIRE_EQUAL( get_word_size<char>(57), 15 )
            REQUIRE_EQUAL( get_word_size<char>(58), 15 )
            REQUIRE_EQUAL( get_word_size<char>(59), 15 )
            REQUIRE_EQUAL( get_word_size<char>(60), 15 )
            REQUIRE_EQUAL( get_word_size<char>(61), 16 )
            REQUIRE_EQUAL( get_word_size<char>(62), 16 )
            REQUIRE_EQUAL( get_word_size<char>(63), 16 )
            REQUIRE_EQUAL( get_word_size<char>(64), 16 )
            REQUIRE_EQUAL( get_word_size<char>(65), 17 )
            REQUIRE_EQUAL( get_word_size<char>(66), 17 )
            REQUIRE_EQUAL( get_word_size<char>(67), 17 )
            REQUIRE_EQUAL( get_word_size<char>(68), 17 )

            // byte_t
            REQUIRE_EQUAL( get_word_size<byte_t>(0), 0 )
            REQUIRE_EQUAL( get_word_size<byte_t>(1), 1 )
            REQUIRE_EQUAL( get_word_size<byte_t>(2), 1 )
            REQUIRE_EQUAL( get_word_size<byte_t>(3), 1 )
            REQUIRE_EQUAL( get_word_size<byte_t>(4), 1 )
            REQUIRE_EQUAL( get_word_size<byte_t>(5), 2 )
            REQUIRE_EQUAL( get_word_size<byte_t>(6), 2 )
            REQUIRE_EQUAL( get_word_size<byte_t>(7), 2 )
            REQUIRE_EQUAL( get_word_size<byte_t>(8), 2 )
            REQUIRE_EQUAL( get_word_size<byte_t>(9), 3 )
            REQUIRE_EQUAL( get_word_size<byte_t>(10), 3 )
            REQUIRE_EQUAL( get_word_size<byte_t>(11), 3 )
            REQUIRE_EQUAL( get_word_size<byte_t>(12), 3 )
            REQUIRE_EQUAL( get_word_size<byte_t>(13), 4 )
            REQUIRE_EQUAL( get_word_size<byte_t>(14), 4 )
            REQUIRE_EQUAL( get_word_size<byte_t>(15), 4 )
            REQUIRE_EQUAL( get_word_size<byte_t>(16), 4 )
            REQUIRE_EQUAL( get_word_size<byte_t>(17), 5 )
            REQUIRE_EQUAL( get_word_size<byte_t>(18), 5 )
            REQUIRE_EQUAL( get_word_size<byte_t>(19), 5 )
            REQUIRE_EQUAL( get_word_size<byte_t>(20), 5 )
            REQUIRE_EQUAL( get_word_size<byte_t>(21), 6 )
            REQUIRE_EQUAL( get_word_size<byte_t>(22), 6 )
            REQUIRE_EQUAL( get_word_size<byte_t>(23), 6 )
            REQUIRE_EQUAL( get_word_size<byte_t>(24), 6 )
            REQUIRE_EQUAL( get_word_size<byte_t>(25), 7 )
            REQUIRE_EQUAL( get_word_size<byte_t>(26), 7 )
            REQUIRE_EQUAL( get_word_size<byte_t>(27), 7 )
            REQUIRE_EQUAL( get_word_size<byte_t>(28), 7 )
            REQUIRE_EQUAL( get_word_size<byte_t>(29), 8 )
            REQUIRE_EQUAL( get_word_size<byte_t>(30), 8 )
            REQUIRE_EQUAL( get_word_size<byte_t>(31), 8 )
            REQUIRE_EQUAL( get_word_size<byte_t>(32), 8 )
            REQUIRE_EQUAL( get_word_size<byte_t>(33), 9 )
            REQUIRE_EQUAL( get_word_size<byte_t>(34), 9 )
            REQUIRE_EQUAL( get_word_size<byte_t>(35), 9 )
            REQUIRE_EQUAL( get_word_size<byte_t>(36), 9 )
            REQUIRE_EQUAL( get_word_size<byte_t>(37), 10 )
            REQUIRE_EQUAL( get_word_size<byte_t>(38), 10 )
            REQUIRE_EQUAL( get_word_size<byte_t>(39), 10 )
            REQUIRE_EQUAL( get_word_size<byte_t>(40), 10 )
            REQUIRE_EQUAL( get_word_size<byte_t>(41), 11 )
            REQUIRE_EQUAL( get_word_size<byte_t>(42), 11 )
            REQUIRE_EQUAL( get_word_size<byte_t>(43), 11 )
            REQUIRE_EQUAL( get_word_size<byte_t>(44), 11 )
            REQUIRE_EQUAL( get_word_size<byte_t>(45), 12 )
            REQUIRE_EQUAL( get_word_size<byte_t>(46), 12 )
            REQUIRE_EQUAL( get_word_size<byte_t>(47), 12 )
            REQUIRE_EQUAL( get_word_size<byte_t>(48), 12 )
            REQUIRE_EQUAL( get_word_size<byte_t>(49), 13 )
            REQUIRE_EQUAL( get_word_size<byte_t>(50), 13 )
            REQUIRE_EQUAL( get_word_size<byte_t>(51), 13 )
            REQUIRE_EQUAL( get_word_size<byte_t>(52), 13 )
            REQUIRE_EQUAL( get_word_size<byte_t>(53), 14 )
            REQUIRE_EQUAL( get_word_size<byte_t>(54), 14 )
            REQUIRE_EQUAL( get_word_size<byte_t>(55), 14 )
            REQUIRE_EQUAL( get_word_size<byte_t>(56), 14 )
            REQUIRE_EQUAL( get_word_size<byte_t>(57), 15 )
            REQUIRE_EQUAL( get_word_size<byte_t>(58), 15 )
            REQUIRE_EQUAL( get_word_size<byte_t>(59), 15 )
            REQUIRE_EQUAL( get_word_size<byte_t>(60), 15 )
            REQUIRE_EQUAL( get_word_size<byte_t>(61), 16 )
            REQUIRE_EQUAL( get_word_size<byte_t>(62), 16 )
            REQUIRE_EQUAL( get_word_size<byte_t>(63), 16 )
            REQUIRE_EQUAL( get_word_size<byte_t>(64), 16 )
            REQUIRE_EQUAL( get_word_size<byte_t>(65), 17 )

            // short
            REQUIRE_EQUAL( get_word_size<short>(0), 0 )
            REQUIRE_EQUAL( get_word_size<short>(1), 1 )
            REQUIRE_EQUAL( get_word_size<short>(2), 1 )
            REQUIRE_EQUAL( get_word_size<short>(3), 2 )
            REQUIRE_EQUAL( get_word_size<short>(4), 2 )
            REQUIRE_EQUAL( get_word_size<short>(5), 3 )
            REQUIRE_EQUAL( get_word_size<short>(6), 3 )
            REQUIRE_EQUAL( get_word_size<short>(7), 4 )
            REQUIRE_EQUAL( get_word_size<short>(8), 4 )
            REQUIRE_EQUAL( get_word_size<short>(9), 5 )
            REQUIRE_EQUAL( get_word_size<short>(10), 5 )
            REQUIRE_EQUAL( get_word_size<short>(11), 6 )
            REQUIRE_EQUAL( get_word_size<short>(12), 6 )
            REQUIRE_EQUAL( get_word_size<short>(13), 7 )
            REQUIRE_EQUAL( get_word_size<short>(14), 7 )
            REQUIRE_EQUAL( get_word_size<short>(15), 8 )
            REQUIRE_EQUAL( get_word_size<short>(16), 8 )
            REQUIRE_EQUAL( get_word_size<short>(17), 9 )
            REQUIRE_EQUAL( get_word_size<short>(18), 9 )
            REQUIRE_EQUAL( get_word_size<short>(19), 10 )
            REQUIRE_EQUAL( get_word_size<short>(20), 10 )
            REQUIRE_EQUAL( get_word_size<short>(21), 11 )
            REQUIRE_EQUAL( get_word_size<short>(22), 11 )
            REQUIRE_EQUAL( get_word_size<short>(23), 12 )
            REQUIRE_EQUAL( get_word_size<short>(24), 12 )
            REQUIRE_EQUAL( get_word_size<short>(25), 13 )
            REQUIRE_EQUAL( get_word_size<short>(26), 13 )
            REQUIRE_EQUAL( get_word_size<short>(27), 14 )
            REQUIRE_EQUAL( get_word_size<short>(28), 14 )
            REQUIRE_EQUAL( get_word_size<short>(29), 15 )
            REQUIRE_EQUAL( get_word_size<short>(30), 15 )
            REQUIRE_EQUAL( get_word_size<short>(31), 16 )
            REQUIRE_EQUAL( get_word_size<short>(32), 16 )
            REQUIRE_EQUAL( get_word_size<short>(33), 17 )
            REQUIRE_EQUAL( get_word_size<short>(34), 17 )

            // unsigned short
            REQUIRE_EQUAL( get_word_size<unsigned short>(0), 0 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(1), 1 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(2), 1 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(3), 2 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(4), 2 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(5), 3 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(6), 3 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(7), 4 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(8), 4 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(9), 5 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(10), 5 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(11), 6 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(12), 6 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(13), 7 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(14), 7 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(15), 8 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(16), 8 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(17), 9 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(18), 9 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(19), 10 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(20), 10 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(21), 11 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(22), 11 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(23), 12 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(24), 12 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(25), 13 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(26), 13 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(27), 14 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(28), 14 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(29), 15 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(30), 15 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(31), 16 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(32), 16 )
            REQUIRE_EQUAL( get_word_size<unsigned short>(33), 17 )

            // int
            REQUIRE_EQUAL( get_word_size<int>(0), 0 )
            REQUIRE_EQUAL( get_word_size<int>(1), 1 )
            REQUIRE_EQUAL( get_word_size<int>(2), 2 )
            REQUIRE_EQUAL( get_word_size<int>(3), 3 )
            REQUIRE_EQUAL( get_word_size<int>(4), 4 )
            REQUIRE_EQUAL( get_word_size<int>(5), 5 )
            REQUIRE_EQUAL( get_word_size<int>(6), 6 )
            REQUIRE_EQUAL( get_word_size<int>(7), 7 )
            REQUIRE_EQUAL( get_word_size<int>(8), 8 )
            REQUIRE_EQUAL( get_word_size<int>(9), 9 )
            REQUIRE_EQUAL( get_word_size<int>(10), 10 )
            REQUIRE_EQUAL( get_word_size<int>(11), 11 )
            REQUIRE_EQUAL( get_word_size<int>(12), 12 )
            REQUIRE_EQUAL( get_word_size<int>(13), 13 )
            REQUIRE_EQUAL( get_word_size<int>(14), 14 )
            REQUIRE_EQUAL( get_word_size<int>(15), 15 )
            REQUIRE_EQUAL( get_word_size<int>(16), 16 )
            REQUIRE_EQUAL( get_word_size<int>(17), 17 )

            // unsigned int
            REQUIRE_EQUAL( get_word_size<unsigned int>(0), 0 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(1), 1 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(2), 2 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(3), 3 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(4), 4 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(5), 5 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(6), 6 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(7), 7 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(8), 8 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(9), 9 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(10), 10 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(11), 11 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(12), 12 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(13), 13 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(14), 14 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(15), 15 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(16), 16 )
            REQUIRE_EQUAL( get_word_size<unsigned int>(17), 17 )

            // word_t
            REQUIRE_EQUAL( get_word_size<word_t>(0), 0 )
            REQUIRE_EQUAL( get_word_size<word_t>(1), 1 )
            REQUIRE_EQUAL( get_word_size<word_t>(2), 2 )
            REQUIRE_EQUAL( get_word_size<word_t>(3), 3 )
            REQUIRE_EQUAL( get_word_size<word_t>(4), 4 )
            REQUIRE_EQUAL( get_word_size<word_t>(5), 5 )
            REQUIRE_EQUAL( get_word_size<word_t>(6), 6 )
            REQUIRE_EQUAL( get_word_size<word_t>(7), 7 )
            REQUIRE_EQUAL( get_word_size<word_t>(8), 8 )
            REQUIRE_EQUAL( get_word_size<word_t>(9), 9 )
            REQUIRE_EQUAL( get_word_size<word_t>(10), 10 )
            REQUIRE_EQUAL( get_word_size<word_t>(11), 11 )
            REQUIRE_EQUAL( get_word_size<word_t>(12), 12 )
            REQUIRE_EQUAL( get_word_size<word_t>(13), 13 )
            REQUIRE_EQUAL( get_word_size<word_t>(14), 14 )
            REQUIRE_EQUAL( get_word_size<word_t>(15), 15 )
            REQUIRE_EQUAL( get_word_size<word_t>(16), 16 )
            REQUIRE_EQUAL( get_word_size<word_t>(17), 17 )

            // 64 bit ints
            REQUIRE_EQUAL( get_word_size<int64_t>(0), 0 )
            REQUIRE_EQUAL( get_word_size<int64_t>(1), 2 )
            REQUIRE_EQUAL( get_word_size<int64_t>(2), 4 )
            REQUIRE_EQUAL( get_word_size<int64_t>(3), 6 )
            REQUIRE_EQUAL( get_word_size<int64_t>(4), 8 )
            REQUIRE_EQUAL( get_word_size<int64_t>(5), 10 )
            REQUIRE_EQUAL( get_word_size<int64_t>(6), 12 )
            REQUIRE_EQUAL( get_word_size<int64_t>(7), 14 )
            REQUIRE_EQUAL( get_word_size<int64_t>(8), 16 )
            REQUIRE_EQUAL( get_word_size<int64_t>(9), 18 )

            // 64 bit unsigned ints
            REQUIRE_EQUAL( get_word_size<uint64_t>(0), 0 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(1), 2 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(2), 4 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(3), 6 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(4), 8 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(5), 10 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(6), 12 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(7), 14 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(8), 16 )
            REQUIRE_EQUAL( get_word_size<uint64_t>(9), 18 )

            // bytes
            REQUIRE_EQUAL( get_word_size( bytes()  ), 0 )
            REQUIRE_EQUAL( get_word_size( bytes(1) ), 1 )
            REQUIRE_EQUAL( get_word_size( bytes(2) ), 1 )
            REQUIRE_EQUAL( get_word_size( bytes(3) ), 1 )
            REQUIRE_EQUAL( get_word_size( bytes(4) ), 1 )
            REQUIRE_EQUAL( get_word_size( bytes(5) ), 2 )
            REQUIRE_EQUAL( get_word_size( bytes(6) ), 2 )
            REQUIRE_EQUAL( get_word_size( bytes(7) ), 2 )
            REQUIRE_EQUAL( get_word_size( bytes(8) ), 2 )
            REQUIRE_EQUAL( get_word_size( bytes(9) ), 3 )
            REQUIRE_EQUAL( get_word_size( bytes(10) ), 3 )
            REQUIRE_EQUAL( get_word_size( bytes(11) ), 3 )
            REQUIRE_EQUAL( get_word_size( bytes(12) ), 3 )
            REQUIRE_EQUAL( get_word_size( bytes(13) ), 4 )
            REQUIRE_EQUAL( get_word_size( bytes(14) ), 4 )
            REQUIRE_EQUAL( get_word_size( bytes(15) ), 4 )
            REQUIRE_EQUAL( get_word_size( bytes(16) ), 4 )
            REQUIRE_EQUAL( get_word_size( bytes(17) ), 5 )
            REQUIRE_EQUAL( get_word_size( bytes(18) ), 5 )
            REQUIRE_EQUAL( get_word_size( bytes(19) ), 5 )
            REQUIRE_EQUAL( get_word_size( bytes(20) ), 5 )
            REQUIRE_EQUAL( get_word_size( bytes(21) ), 6 )
            REQUIRE_EQUAL( get_word_size( bytes(22) ), 6 )
            REQUIRE_EQUAL( get_word_size( bytes(23) ), 6 )
            REQUIRE_EQUAL( get_word_size( bytes(24) ), 6 )
            REQUIRE_EQUAL( get_word_size( bytes(25) ), 7 )
            REQUIRE_EQUAL( get_word_size( bytes(26) ), 7 )
            REQUIRE_EQUAL( get_word_size( bytes(27) ), 7 )
            REQUIRE_EQUAL( get_word_size( bytes(28) ), 7 )
            REQUIRE_EQUAL( get_word_size( bytes(29) ), 8 )
            REQUIRE_EQUAL( get_word_size( bytes(30) ), 8 )
            REQUIRE_EQUAL( get_word_size( bytes(31) ), 8 )
            REQUIRE_EQUAL( get_word_size( bytes(32) ), 8 )
            REQUIRE_EQUAL( get_word_size( bytes(33) ), 9 )
            REQUIRE_EQUAL( get_word_size( bytes(34) ), 9 )
            REQUIRE_EQUAL( get_word_size( bytes(35) ), 9 )
            REQUIRE_EQUAL( get_word_size( bytes(36) ), 9 )
            REQUIRE_EQUAL( get_word_size( bytes(37) ), 10 )
            REQUIRE_EQUAL( get_word_size( bytes(38) ), 10 )
            REQUIRE_EQUAL( get_word_size( bytes(39) ), 10 )
            REQUIRE_EQUAL( get_word_size( bytes(40) ), 10 )
            REQUIRE_EQUAL( get_word_size( bytes(41) ), 11 )
            REQUIRE_EQUAL( get_word_size( bytes(42) ), 11 )
            REQUIRE_EQUAL( get_word_size( bytes(43) ), 11 )
            REQUIRE_EQUAL( get_word_size( bytes(44) ), 11 )
            REQUIRE_EQUAL( get_word_size( bytes(45) ), 12 )
            REQUIRE_EQUAL( get_word_size( bytes(46) ), 12 )
            REQUIRE_EQUAL( get_word_size( bytes(47) ), 12 )
            REQUIRE_EQUAL( get_word_size( bytes(48) ), 12 )
            REQUIRE_EQUAL( get_word_size( bytes(49) ), 13 )
            REQUIRE_EQUAL( get_word_size( bytes(50) ), 13 )
            REQUIRE_EQUAL( get_word_size( bytes(51) ), 13 )
            REQUIRE_EQUAL( get_word_size( bytes(52) ), 13 )
            REQUIRE_EQUAL( get_word_size( bytes(53) ), 14 )
            REQUIRE_EQUAL( get_word_size( bytes(54) ), 14 )
            REQUIRE_EQUAL( get_word_size( bytes(55) ), 14 )
            REQUIRE_EQUAL( get_word_size( bytes(56) ), 14 )
            REQUIRE_EQUAL( get_word_size( bytes(57) ), 15 )
            REQUIRE_EQUAL( get_word_size( bytes(58) ), 15 )
            REQUIRE_EQUAL( get_word_size( bytes(59) ), 15 )
            REQUIRE_EQUAL( get_word_size( bytes(60) ), 15 )
            REQUIRE_EQUAL( get_word_size( bytes(61) ), 16 )
            REQUIRE_EQUAL( get_word_size( bytes(62) ), 16 )
            REQUIRE_EQUAL( get_word_size( bytes(63) ), 16 )
            REQUIRE_EQUAL( get_word_size( bytes(64) ), 16 )
            REQUIRE_EQUAL( get_word_size( bytes(65) ), 17 )

            // fixed_bytes
            REQUIRE_EQUAL( get_word_size( fixed_bytes<0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<1>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<2>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<3>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<4>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<5>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<6>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<7>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<8>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<9>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<10>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<11>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<12>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<13>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<14>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<15>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<16>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<17>{} ), 5 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<18>{} ), 5 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<19>{} ), 5 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<20>{} ), 5 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<21>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<22>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<23>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<24>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<25>{} ), 7 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<26>{} ), 7 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<27>{} ), 7 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<28>{} ), 7 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<29>{} ), 8 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<30>{} ), 8 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<31>{} ), 8 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<32>{} ), 8 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<33>{} ), 9 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<34>{} ), 9 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<35>{} ), 9 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<36>{} ), 9 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<37>{} ), 10 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<38>{} ), 10 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<39>{} ), 10 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<40>{} ), 10 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<41>{} ), 11 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<42>{} ), 11 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<43>{} ), 11 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<44>{} ), 11 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<45>{} ), 12 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<46>{} ), 12 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<47>{} ), 12 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<48>{} ), 12 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<49>{} ), 13 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<50>{} ), 13 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<51>{} ), 13 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<52>{} ), 13 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<53>{} ), 14 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<54>{} ), 14 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<55>{} ), 14 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<56>{} ), 14 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<57>{} ), 15 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<58>{} ), 15 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<59>{} ), 15 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<60>{} ), 15 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<61>{} ), 16 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<62>{} ), 16 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<63>{} ), 16 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<64>{} ), 16 )
            REQUIRE_EQUAL( get_word_size( fixed_bytes<65>{} ), 17 )

            // vector of shorts
            REQUIRE_EQUAL( get_word_size( std::vector<short>{ } ), 0 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<short>{ } )), 0 )
            REQUIRE_EQUAL( get_word_size( std::vector<short>{ 1 } ), 1 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<short>{ 1 } )), 1 )
            REQUIRE_EQUAL( get_word_size( std::vector<short>{ 1, 2 } ), 1 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<short>{ 1, 2 } )), 1 )
            REQUIRE_EQUAL( get_word_size( std::vector<short>{ 1, 2, 3 } ), 2 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<short>{ 1, 2, 3 } )), 2 )
            REQUIRE_EQUAL( get_word_size( std::vector<short>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 5 )
            REQUIRE_EQUAL( get_word_size( std::span(std::vector<short>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }) ), 5 )

            // vector of ints
            REQUIRE_EQUAL( get_word_size( std::vector<int>{ } ), 0 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int>{ } )), 0 )
            REQUIRE_EQUAL( get_word_size( std::vector<int>{ 1 } ), 1 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int>{ 1 } )), 1 )
            REQUIRE_EQUAL( get_word_size( std::vector<int>{ 1, 2 } ), 2 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int>{ 1, 2 } )), 2 )
            REQUIRE_EQUAL( get_word_size( std::vector<int>{ 1, 2, 3 } ), 3 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int>{ 1, 2, 3 } )), 3 )
            REQUIRE_EQUAL( get_word_size( std::vector<int>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 10 )

            // vector of words
            REQUIRE_EQUAL( get_word_size( std::vector<word_t>{  } ), 0 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<word_t>{  } )), 0 )
            REQUIRE_EQUAL( get_word_size( std::vector<word_t>{ 1 } ), 1 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<word_t>{ 1 } )), 1 )
            REQUIRE_EQUAL( get_word_size( std::vector<word_t>{ 1, 2 } ), 2 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<word_t>{ 1, 2 } )), 2 )
            REQUIRE_EQUAL( get_word_size( std::vector<word_t>{ 1, 2, 3 } ), 3 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<word_t>{ 1, 2, 3 } )), 3 )
            REQUIRE_EQUAL( get_word_size( std::vector<word_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 10 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<word_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } )), 10 )

            // vector of 64bit ints
            REQUIRE_EQUAL( get_word_size( std::vector<int64_t>{  } ), 0 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int64_t>{  } ) ), 0 )
            REQUIRE_EQUAL( get_word_size( std::vector<int64_t>{ 1 } ), 2 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int64_t>{ 1 } ) ), 2 )
            REQUIRE_EQUAL( get_word_size( std::vector<int64_t>{ 1, 2 } ), 4 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int64_t>{ 1, 2 } ) ), 4 )
            REQUIRE_EQUAL( get_word_size( std::vector<int64_t>{ 1, 2, 3 } ), 6 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int64_t>{ 1, 2, 3 } ) ), 6 )
            REQUIRE_EQUAL( get_word_size( std::vector<int64_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 20 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<int64_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ) ), 20 )

            // vector of unsigned 64bit ints
            REQUIRE_EQUAL( get_word_size( std::vector<uint64_t>{  } ), 0 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<uint64_t>{  } ) ), 0 )
            REQUIRE_EQUAL( get_word_size( std::vector<uint64_t>{ 1 } ), 2 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<uint64_t>{ 1 } ) ), 2 )
            REQUIRE_EQUAL( get_word_size( std::vector<uint64_t>{ 1, 2 } ), 4 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<uint64_t>{ 1, 2 } ) ), 4 )
            REQUIRE_EQUAL( get_word_size( std::vector<uint64_t>{ 1, 2, 3 } ), 6 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<uint64_t>{ 1, 2, 3 } ) ), 6 )
            REQUIRE_EQUAL( get_word_size( std::vector<uint64_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 20 )
            REQUIRE_EQUAL( get_word_size( std::span( std::vector<uint64_t>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ) ), 20 )

            // array of shorts
            REQUIRE_EQUAL( get_word_size( std::array<short, 0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( std::array<short, 1>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( std::array<short, 2>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( std::array<short, 3>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( std::array<short, 10>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 5 )

            // array of ints
            REQUIRE_EQUAL( get_word_size( std::array<int, 0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( std::array<int, 1>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( std::array<int, 2>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( std::array<int, 3>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( std::array<int, 10>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 10 )

            // array of words
            REQUIRE_EQUAL( get_word_size( std::array<word_t, 0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( std::array<word_t, 1>{} ), 1 )
            REQUIRE_EQUAL( get_word_size( std::array<word_t, 2>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( std::array<word_t, 3>{} ), 3 )
            REQUIRE_EQUAL( get_word_size( std::array<word_t, 10>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 10 )

            // array of 64-bit ints
            REQUIRE_EQUAL( get_word_size( std::array<uint64_t, 0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( std::array<uint64_t, 1>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( std::array<uint64_t, 2>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( std::array<uint64_t, 3>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( std::array<uint64_t, 10>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 20 )

            // array of unsigned 64-bit ints
            REQUIRE_EQUAL( get_word_size( std::array<int64_t, 0>{} ), 0 )
            REQUIRE_EQUAL( get_word_size( std::array<int64_t, 1>{} ), 2 )
            REQUIRE_EQUAL( get_word_size( std::array<int64_t, 2>{} ), 4 )
            REQUIRE_EQUAL( get_word_size( std::array<int64_t, 3>{} ), 6 )
            REQUIRE_EQUAL( get_word_size( std::array<int64_t, 10>{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } ), 20 )
        }

        // Test hex string to bytes conversion
        {
            using namespace std::string_view_literals;

            // Test empty string
            REQUIRE_EQUAL( from_hex( "" ), bytes() )
            REQUIRE_EQUAL( from_hex( std::string() ), bytes() )
            REQUIRE_EQUAL( from_hex( std::string("\0AABB1234") ), bytes() )
            REQUIRE_EQUAL( from_hex( std::string_view() ), bytes() )
            REQUIRE_EQUAL( from_hex( std::string_view("\0AABB1234") ), bytes() )

            REQUIRE_EQUAL( from_hex( ""      ), fixed_bytes<0>{} ) // hits string literal overload
            REQUIRE_EQUAL( from_hex<0>( ""   ), fixed_bytes<0>{} )
            REQUIRE_EQUAL( from_hex<0>( ""sv ), fixed_bytes<0>{} )
            REQUIRE_EQUAL( from_hex<1>( ""   ), fixed_bytes<0>{} ) // hits string literal overload
            REQUIRE_EQUAL( from_hex<1>( ""sv ), fixed_bytes<1>{} )
            REQUIRE_EQUAL( from_hex<2>( ""   ), fixed_bytes<2>{} )
            REQUIRE_EQUAL( from_hex<2>( ""sv ), fixed_bytes<2>{} )
            REQUIRE_EQUAL( from_hex<3>( ""   ), fixed_bytes<3>{} )
            REQUIRE_EQUAL( from_hex<3>( ""sv ), fixed_bytes<3>{} )
            REQUIRE_EQUAL( from_hex<4>( ""   ), fixed_bytes<4>{} )
            REQUIRE_EQUAL( from_hex<4>( ""sv ), fixed_bytes<4>{} )
            REQUIRE_EQUAL( ""_hex, bytes() )

            // Test returned required buffer size
            REQUIRE_EQUAL( from_hex( "00", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "00", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "00" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "00" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "01", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "01", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "01" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "01" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "01" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "01" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "02", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "02", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "02" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "02" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "02" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "02" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "03", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "03", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "03" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "03" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "03" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "03" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "07", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "07", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "07" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "07" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "07" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "07" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "0F", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "0F", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "0F" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "0F" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0F" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0F" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "0f", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "0f", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "0f" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "0f" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0f" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0f" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "10", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "10", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "10" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "10" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "20", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "20", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "20" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "20" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "20" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "20" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "30", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "30", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "30" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "30" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "30" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "30" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "70", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "70", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "70" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "70" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "70" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "70" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "F0", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "F0", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "F0" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "F0" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "F0" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "F0" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "f0", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "f0", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "f0" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "f0" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "f0" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "f0" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "12", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "12", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "12" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "12" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "12" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "12" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "21", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "21", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "21" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "21" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "21" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "21" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "32", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "32", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "32" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "32" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "32" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "32" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "75", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "75", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "75" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "75" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "75" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "75" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "FA", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "FA", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "FA" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "FA" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FA" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FA" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "fa", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "fa", 2, bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "fa" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string( "fa" ), bytes(1).data(), 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "fa" ), nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( std::string_view( "fa" ), bytes(1).data(), 0 ), 1 )

            REQUIRE_EQUAL( from_hex( "000", 3, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "000", 3, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "000" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "001", 3, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "001", 3, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "001" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "001" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "001" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "001" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "100", 3, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "100", 3, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "100" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "100" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "fff", 3, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "fff", 3, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "fff" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "fff" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "fff" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "fff" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "0000", 4, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "0000", 4, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "0000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "0000" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "0001", 4, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "0001", 4, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "0001" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "0001" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0001" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0001" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "1000", 4, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "1000", 4, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "1000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "1000" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "FFFF", 4, nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( "FFFF", 4, bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "FFFF" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string( "FFFF" ), bytes(1).data(), 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFFF" ), nullptr, 0 ), 2 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFFF" ), bytes(1).data(), 0 ), 2 )

            REQUIRE_EQUAL( from_hex( "00000", 5, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "00000", 5, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "00000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "00000" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "00001", 5, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "00001", 5, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "00001" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "00001" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00001" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00001" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "10000", 5, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "10000", 5, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "10000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "10000" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10000" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "aBfCe", 5, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "aBfCe", 5, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "aBfCe" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "aBfCe" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "aBfCe" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "aBfCe" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "000000", 6, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "000000", 6, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "000000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "000000" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "000001", 6, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "000001", 6, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "000001" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "000001" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000001" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000001" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "100000", 6, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "100000", 6, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "100000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "100000" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100000" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100000" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "ffffff", 6, nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( "ffffff", 6, bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "ffffff" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string( "ffffff" ), bytes(1).data(), 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "ffffff" ), nullptr, 0 ), 3 )
            REQUIRE_EQUAL( from_hex( std::string_view( "ffffff" ), bytes(1).data(), 0 ), 3 )

            REQUIRE_EQUAL( from_hex( "0000000", 7, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "0000000", 7, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "0000001", 7, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "0000001", 7, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "0000001" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "0000001" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000001" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000001" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "1000000", 7, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "1000000", 7, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "1000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "1000000" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000000" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "FFFFFFF", 7, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "FFFFFFF", 7, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "FFFFFFF" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "FFFFFFF" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFFFFFF" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFFFFFF" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "00000000", 8, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "00000000", 8, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "00000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "00000000" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000000" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "00000001", 8, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "00000001", 8, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "00000001" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "00000001" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000001" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "00000001" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "10000000", 8, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "10000000", 8, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "10000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "10000000" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10000000" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "10000000" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "ffFFffFF", 8, nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( "ffFFffFF", 8, bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "ffFFffFF" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string( "ffFFffFF" ), bytes(1).data(), 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "ffFFffFF" ), nullptr, 0 ), 4 )
            REQUIRE_EQUAL( from_hex( std::string_view( "ffFFffFF" ), bytes(1).data(), 0 ), 4 )

            REQUIRE_EQUAL( from_hex( "000000000", 9, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "000000000", 9, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "000000000" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000000" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "000000001", 9, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "000000001", 9, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "000000001" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "000000001" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000001" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "000000001" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "100000000", 9, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "100000000", 9, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "100000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "100000000" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "100000000" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "FFffFffFf", 9, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "FFffFffFf", 9, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "FFffFffFf" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "FFffFffFf" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFffFffFf" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFffFffFf" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "0000000000", 10, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "0000000000", 10, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000000" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000000" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "0000000001", 10, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "0000000001", 10, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000001" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "0000000001" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000001" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "0000000001" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "1000000000", 10, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "1000000000", 10, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "1000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "1000000000" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000000000" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "1000000000" ), bytes(1).data(), 0 ), 5 )

            REQUIRE_EQUAL( from_hex( "FFffFffFfF", 10, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "FFffFffFfF", 10, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "FFffFffFfF" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string( "FFffFffFfF" ), bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFffFffFfF" ), nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( std::string_view( "FFffFffFfF" ), bytes(1).data(), 0 ), 5 )

            // Edge case, hex sting with wrong length
            REQUIRE_EQUAL( from_hex( "000000000", 9, nullptr, 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "000000000", 9, bytes(1).data(), 0 ), 5 )
            REQUIRE_EQUAL( from_hex( "000000000", 2, nullptr, 0 ), 1 )
            REQUIRE_EQUAL( from_hex( "000000000", 2, bytes(1).data(), 0 ), 1 )

            // Test even length hex string
            REQUIRE_EQUAL( from_hex( "00" ), bytes( { 0x00 } ))
            REQUIRE_EQUAL( from_hex( "01" ), bytes({0x01}))
            REQUIRE_EQUAL( from_hex( "7f" ), bytes( { 0x7f } ))
            REQUIRE_EQUAL( from_hex( "80" ), bytes( { 0x80 } ))
            REQUIRE_EQUAL( from_hex( "a5" ), bytes( { 0xa5 }))
            REQUIRE_EQUAL( from_hex( "ff" ), bytes( { 0xff } ))
            REQUIRE_EQUAL( from_hex( "0011" ), bytes( { 0x00, 0x11 } ))
            REQUIRE_EQUAL( from_hex( "4b1d" ), bytes( { 0x4b, 0x1d } ))
            REQUIRE_EQUAL( from_hex( "4B1D" ), bytes( { 0x4b, 0x1d } ))
            REQUIRE_EQUAL( from_hex( "7f80" ), bytes( { 0x7f, 0x80 } ))
            REQUIRE_EQUAL( from_hex( "ffff" ), bytes( { 0xff, 0xff } ))
            REQUIRE_EQUAL( from_hex( "001122" ), bytes({0x00, 0x11, 0x22}))
            REQUIRE_EQUAL( from_hex( "7f80fe" ), bytes({0x7f, 0x80, 0xfe}))
            REQUIRE_EQUAL( from_hex( "7F80FE" ), bytes({0x7f, 0x80, 0xfe}))
            REQUIRE_EQUAL( from_hex( "a5b312" ), bytes({0xa5, 0xb3, 0x12}))
            REQUIRE_EQUAL( from_hex( "A5B312" ), bytes({0xa5, 0xb3, 0x12}))
            REQUIRE_EQUAL( from_hex( "b105f00d" ), bytes({0xb1, 0x05, 0xf0, 0x0d}))
            REQUIRE_EQUAL( from_hex( "B105F00D" ), bytes({0xb1, 0x05, 0xf0, 0x0d}))
            REQUIRE_EQUAL( from_hex( "fab1234c" ), bytes({0xfa, 0xb1, 0x23, 0x4c}))
            REQUIRE_EQUAL( from_hex( "FAB1234C" ), bytes({0xfa, 0xb1, 0x23, 0x4c}))
            REQUIRE_EQUAL( from_hex( "ffffffff" ), bytes({0xff, 0xff, 0xff, 0xff}))
            REQUIRE_EQUAL( from_hex( "FFFFFFFF" ), bytes({0xff, 0xff, 0xff, 0xff}))

            REQUIRE_EQUAL( from_hex<1>( "00"   ), fixed_bytes<1>({ 0x00 }) )
            REQUIRE_EQUAL( from_hex<1>( "00"sv ), fixed_bytes<1>({ 0x00 }) )
            REQUIRE_EQUAL( from_hex<1>( "01"   ), fixed_bytes<1>({ 0x01 }) )
            REQUIRE_EQUAL( from_hex<1>( "01"sv ), fixed_bytes<1>({ 0x01 }) )
            REQUIRE_EQUAL( from_hex<1>( "7f"   ), fixed_bytes<1>({ 0x7f }) )
            REQUIRE_EQUAL( from_hex<1>( "7f"sv ), fixed_bytes<1>({ 0x7f }) )
            REQUIRE_EQUAL( from_hex<1>( "80"   ), fixed_bytes<1>({ 0x80 }) )
            REQUIRE_EQUAL( from_hex<1>( "80"sv ), fixed_bytes<1>({ 0x80 }) )
            REQUIRE_EQUAL( from_hex<1>( "a5"   ), fixed_bytes<1>({ 0xa5 }) )
            REQUIRE_EQUAL( from_hex<1>( "a5"sv ), fixed_bytes<1>({ 0xa5 }) )
            REQUIRE_EQUAL( from_hex<1>( "ff"   ), fixed_bytes<1>({ 0xff }) )
            REQUIRE_EQUAL( from_hex<1>( "ff"sv ), fixed_bytes<1>({ 0xff }) )
            REQUIRE_EQUAL( from_hex<2>( "0011"   ), fixed_bytes<2>({ 0x00, 0x11 }) )
            REQUIRE_EQUAL( from_hex<2>( "0011"sv ), fixed_bytes<2>({ 0x00, 0x11 }) )
            REQUIRE_EQUAL( from_hex<2>( "4b1d"   ), fixed_bytes<2>({ 0x4b, 0x1d }) )
            REQUIRE_EQUAL( from_hex<2>( "4b1d"sv ), fixed_bytes<2>({ 0x4b, 0x1d }) )
            REQUIRE_EQUAL( from_hex<2>( "4B1D"   ), fixed_bytes<2>({ 0x4b, 0x1d }) )
            REQUIRE_EQUAL( from_hex<2>( "4B1D"sv ), fixed_bytes<2>({ 0x4b, 0x1d }) )
            REQUIRE_EQUAL( from_hex<2>( "7f80"   ), fixed_bytes<2>({ 0x7f, 0x80 }) )
            REQUIRE_EQUAL( from_hex<2>( "7f80"sv ), fixed_bytes<2>({ 0x7f, 0x80 }) )
            REQUIRE_EQUAL( from_hex<2>( "ffff"   ), fixed_bytes<2>({ 0xff, 0xff }) )
            REQUIRE_EQUAL( from_hex<2>( "ffff"sv ), fixed_bytes<2>({ 0xff, 0xff }) )
            REQUIRE_EQUAL( from_hex<3>( "001122"   ), fixed_bytes<3>({ 0x00, 0x11, 0x22 }) )
            REQUIRE_EQUAL( from_hex<3>( "001122"sv ), fixed_bytes<3>({ 0x00, 0x11, 0x22 }) )
            REQUIRE_EQUAL( from_hex<3>( "7f80fe"   ), fixed_bytes<3>({ 0x7f, 0x80, 0xfe }) )
            REQUIRE_EQUAL( from_hex<3>( "7f80fe"sv ), fixed_bytes<3>({ 0x7f, 0x80, 0xfe }) )
            REQUIRE_EQUAL( from_hex<3>( "7F80FE"   ), fixed_bytes<3>({ 0x7f, 0x80, 0xfe }) )
            REQUIRE_EQUAL( from_hex<3>( "7F80FE"sv ), fixed_bytes<3>({ 0x7f, 0x80, 0xfe }) )
            REQUIRE_EQUAL( from_hex<3>( "a5b312"   ), fixed_bytes<3>({ 0xa5, 0xb3, 0x12 }) )
            REQUIRE_EQUAL( from_hex<3>( "a5b312"sv ), fixed_bytes<3>({ 0xa5, 0xb3, 0x12 }) )
            REQUIRE_EQUAL( from_hex<3>( "A5B312"   ), fixed_bytes<3>({ 0xa5, 0xb3, 0x12 }) )
            REQUIRE_EQUAL( from_hex<3>( "A5B312"sv ), fixed_bytes<3>({ 0xa5, 0xb3, 0x12 }) )
            REQUIRE_EQUAL( from_hex<4>( "b105f00d"   ), fixed_bytes<4>({ 0xb1, 0x05, 0xf0, 0x0d }) )
            REQUIRE_EQUAL( from_hex<4>( "b105f00d"sv ), fixed_bytes<4>({ 0xb1, 0x05, 0xf0, 0x0d }) )
            REQUIRE_EQUAL( from_hex<4>( "B105F00D"   ), fixed_bytes<4>({ 0xb1, 0x05, 0xf0, 0x0d }) )
            REQUIRE_EQUAL( from_hex<4>( "B105F00D"sv ), fixed_bytes<4>({ 0xb1, 0x05, 0xf0, 0x0d }) )
            REQUIRE_EQUAL( from_hex<4>( "fab1234c"   ), fixed_bytes<4>({ 0xfa, 0xb1, 0x23, 0x4c }) )
            REQUIRE_EQUAL( from_hex<4>( "fab1234c"sv ), fixed_bytes<4>({ 0xfa, 0xb1, 0x23, 0x4c }) )
            REQUIRE_EQUAL( from_hex<4>( "FAB1234C"   ), fixed_bytes<4>({ 0xfa, 0xb1, 0x23, 0x4c }) )
            REQUIRE_EQUAL( from_hex<4>( "FAB1234C"sv ), fixed_bytes<4>({ 0xfa, 0xb1, 0x23, 0x4c }) )
            REQUIRE_EQUAL( from_hex<4>( "ffffffff"   ), fixed_bytes<4>({ 0xff, 0xff, 0xff, 0xff }) )
            REQUIRE_EQUAL( from_hex<4>( "ffffffff"sv ), fixed_bytes<4>({ 0xff, 0xff, 0xff, 0xff }) )
            REQUIRE_EQUAL( from_hex<4>( "FFFFFFFF"   ), fixed_bytes<4>({ 0xff, 0xff, 0xff, 0xff }) )
            REQUIRE_EQUAL( from_hex<4>( "FFFFFFFF"sv ), fixed_bytes<4>({ 0xff, 0xff, 0xff, 0xff }) )

            REQUIRE_EQUAL( "00"_hex, bytes( {0x00}));
            REQUIRE_EQUAL("01"_hex, bytes({0x01}));
            REQUIRE_EQUAL( "7f"_hex, bytes( {0x7f}));
            REQUIRE_EQUAL( "80"_hex, bytes( { 0x80 } ))
            REQUIRE_EQUAL( "a5"_hex, bytes( {0xa5}));
            REQUIRE_EQUAL( "ff"_hex, bytes( {0xff}));
            REQUIRE_EQUAL( "0011"_hex, bytes( { 0x00, 0x11 } ))
            REQUIRE_EQUAL( "4b1d"_hex, bytes( { 0x4b, 0x1d } ))
            REQUIRE_EQUAL( "4B1D"_hex, bytes( { 0x4b, 0x1d } ))
            REQUIRE_EQUAL( "7f80"_hex, bytes( { 0x7f, 0x80 } ))
            REQUIRE_EQUAL( "ffff"_hex, bytes( { 0xff, 0xff } ))
            REQUIRE_EQUAL("001122"_hex, bytes({0x00, 0x11, 0x22}));
            REQUIRE_EQUAL("7f80fe"_hex, bytes({0x7f, 0x80, 0xfe}));
            REQUIRE_EQUAL("7F80FE"_hex, bytes({0x7f, 0x80, 0xfe}));
            REQUIRE_EQUAL("a5b312"_hex, bytes({0xa5, 0xb3, 0x12}));
            REQUIRE_EQUAL("A5B312"_hex, bytes({0xa5, 0xb3, 0x12}));
            REQUIRE_EQUAL( "b105f00d"_hex, bytes({0xb1, 0x05, 0xf0, 0x0d}))
            REQUIRE_EQUAL( "B105F00D"_hex, bytes({0xb1, 0x05, 0xf0, 0x0d}))
            REQUIRE_EQUAL( "fab1234c"_hex, bytes({0xfa, 0xb1, 0x23, 0x4c}))
            REQUIRE_EQUAL( "FAB1234C"_hex, bytes({0xfa, 0xb1, 0x23, 0x4c}))
            REQUIRE_EQUAL("ffffffff"_hex, bytes({0xff, 0xff, 0xff, 0xff}))
            REQUIRE_EQUAL("FFFFFFFF"_hex, bytes({0xff, 0xff, 0xff, 0xff}))

            // Test odd length hex string
            REQUIRE_EQUAL( from_hex( "0" ), bytes( { 0x00 } ))
            REQUIRE_EQUAL( from_hex( "1" ), bytes( { 0x01 } ))
            REQUIRE_EQUAL( from_hex( "2" ), bytes( { 0x02 } ))
            REQUIRE_EQUAL( from_hex( "3" ), bytes( { 0x03 } ))
            REQUIRE_EQUAL( from_hex( "4" ), bytes( { 0x04 } ))
            REQUIRE_EQUAL( from_hex( "5" ), bytes( { 0x05 } ))
            REQUIRE_EQUAL( from_hex( "6" ), bytes( { 0x06 } ))
            REQUIRE_EQUAL( from_hex( "7" ), bytes( { 0x07 } ))
            REQUIRE_EQUAL( from_hex( "8" ), bytes( { 0x08 } ))
            REQUIRE_EQUAL( from_hex( "9" ), bytes( { 0x09 } ))
            REQUIRE_EQUAL( from_hex( "a" ), bytes( { 0x0a } ))
            REQUIRE_EQUAL( from_hex( "A" ), bytes( { 0x0a } ))
            REQUIRE_EQUAL( from_hex( "b" ), bytes( { 0x0b } ))
            REQUIRE_EQUAL( from_hex( "B" ), bytes( { 0x0b } ))
            REQUIRE_EQUAL( from_hex( "c" ), bytes( { 0x0c } ))
            REQUIRE_EQUAL( from_hex( "C" ), bytes( { 0x0c } ))
            REQUIRE_EQUAL( from_hex( "d" ), bytes( { 0x0d } ))
            REQUIRE_EQUAL( from_hex( "D" ), bytes( { 0x0d } ))
            REQUIRE_EQUAL( from_hex( "e" ), bytes( { 0x0e } ))
            REQUIRE_EQUAL( from_hex( "E" ), bytes( { 0x0e } ))
            REQUIRE_EQUAL( from_hex( "f" ), bytes( { 0x0f } ))
            REQUIRE_EQUAL( from_hex( "F" ), bytes( { 0x0f } ))
            REQUIRE_EQUAL( from_hex( "011" ), bytes( { 0x00, 0x11 } ))
            REQUIRE_EQUAL( from_hex( "122" ), bytes( { 0x01, 0x22 } ))
            REQUIRE_EQUAL( from_hex( "233" ), bytes( { 0x02, 0x33 } ))
            REQUIRE_EQUAL( from_hex( "344" ), bytes( { 0x03, 0x44 } ))
            REQUIRE_EQUAL( from_hex( "455" ), bytes( { 0x04, 0x55 } ))
            REQUIRE_EQUAL( from_hex( "566" ), bytes( { 0x05, 0x66 } ))
            REQUIRE_EQUAL( from_hex( "677" ), bytes( { 0x06, 0x77 } ))
            REQUIRE_EQUAL( from_hex( "788" ), bytes( { 0x07, 0x88 } ))
            REQUIRE_EQUAL( from_hex( "7f8" ), bytes( { 0x07, 0xf8 } ))
            REQUIRE_EQUAL( from_hex( "7F8" ), bytes( { 0x07, 0xf8 } ))
            REQUIRE_EQUAL( from_hex( "a5b" ), bytes( { 0x0a, 0x5b }))
            REQUIRE_EQUAL( from_hex( "A5B" ), bytes( { 0x0a, 0x5b }))
            REQUIRE_EQUAL( from_hex( "fff" ), bytes( { 0x0f, 0xff } ))
            REQUIRE_EQUAL( from_hex( "FFF" ), bytes( { 0x0f, 0xff } ))
            REQUIRE_EQUAL( from_hex( "12345" ), bytes( { 0x01, 0x23, 0x45 } ))
            REQUIRE_EQUAL( from_hex( "54321" ), bytes( { 0x05, 0x43, 0x21 } ))
            REQUIRE_EQUAL( from_hex( "a4b2c" ), bytes( { 0x0a, 0x4b, 0x2c } ))
            REQUIRE_EQUAL( from_hex( "A4b2C" ), bytes( { 0x0a, 0x4b, 0x2c } ))
            REQUIRE_EQUAL( from_hex( "1234567" ), bytes( { 0x01, 0x23, 0x45, 0x67 } ))
            REQUIRE_EQUAL( from_hex( "7654321" ), bytes( { 0x07, 0x65, 0x43, 0x21 } ))
            REQUIRE_EQUAL( from_hex( "a4b2c3d" ), bytes( { 0x0a, 0x4b, 0x2c, 0x3d } ))
            REQUIRE_EQUAL( from_hex( "A4b2C3D" ), bytes( { 0x0a, 0x4b, 0x2c, 0x3d } ))

            REQUIRE_EQUAL( from_hex<1>( "0"   ), fixed_bytes<1>({ 0x00 }) )
            REQUIRE_EQUAL( from_hex<1>( "0"sv ), fixed_bytes<1>({ 0x00 }) )
            REQUIRE_EQUAL( from_hex<1>( "1"   ), fixed_bytes<1>({ 0x01 }) )
            REQUIRE_EQUAL( from_hex<1>( "1"sv ), fixed_bytes<1>({ 0x01 }) )
            REQUIRE_EQUAL( from_hex<1>( "2"   ), fixed_bytes<1>({ 0x02 }) )
            REQUIRE_EQUAL( from_hex<1>( "2"sv ), fixed_bytes<1>({ 0x02 }) )
            REQUIRE_EQUAL( from_hex<1>( "3"   ), fixed_bytes<1>({ 0x03 }) )
            REQUIRE_EQUAL( from_hex<1>( "3"sv ), fixed_bytes<1>({ 0x03 }) )
            REQUIRE_EQUAL( from_hex<1>( "4"   ), fixed_bytes<1>({ 0x04 }) )
            REQUIRE_EQUAL( from_hex<1>( "4"sv ), fixed_bytes<1>({ 0x04 }) )
            REQUIRE_EQUAL( from_hex<1>( "5"   ), fixed_bytes<1>({ 0x05 }) )
            REQUIRE_EQUAL( from_hex<1>( "5"sv ), fixed_bytes<1>({ 0x05 }) )
            REQUIRE_EQUAL( from_hex<1>( "6"   ), fixed_bytes<1>({ 0x06 }) )
            REQUIRE_EQUAL( from_hex<1>( "6"sv ), fixed_bytes<1>({ 0x06 }) )
            REQUIRE_EQUAL( from_hex<1>( "7"   ), fixed_bytes<1>({ 0x07 }) )
            REQUIRE_EQUAL( from_hex<1>( "7"sv ), fixed_bytes<1>({ 0x07 }) )
            REQUIRE_EQUAL( from_hex<1>( "8"   ), fixed_bytes<1>({ 0x08 }) )
            REQUIRE_EQUAL( from_hex<1>( "8"sv ), fixed_bytes<1>({ 0x08 }) )
            REQUIRE_EQUAL( from_hex<1>( "9"   ), fixed_bytes<1>({ 0x09 }) )
            REQUIRE_EQUAL( from_hex<1>( "9"sv ), fixed_bytes<1>({ 0x09 }) )
            REQUIRE_EQUAL( from_hex<1>( "a"   ), fixed_bytes<1>({ 0x0a }) )
            REQUIRE_EQUAL( from_hex<1>( "a"sv ), fixed_bytes<1>({ 0x0a }) )
            REQUIRE_EQUAL( from_hex<1>( "A"   ), fixed_bytes<1>({ 0x0a }) )
            REQUIRE_EQUAL( from_hex<1>( "A"sv ), fixed_bytes<1>({ 0x0a }) )
            REQUIRE_EQUAL( from_hex<1>( "b"   ), fixed_bytes<1>({ 0x0b }) )
            REQUIRE_EQUAL( from_hex<1>( "b"sv ), fixed_bytes<1>({ 0x0b }) )
            REQUIRE_EQUAL( from_hex<1>( "B"   ), fixed_bytes<1>({ 0x0b }) )
            REQUIRE_EQUAL( from_hex<1>( "B"sv ), fixed_bytes<1>({ 0x0b }) )
            REQUIRE_EQUAL( from_hex<1>( "c"   ), fixed_bytes<1>({ 0x0c }) )
            REQUIRE_EQUAL( from_hex<1>( "c"sv ), fixed_bytes<1>({ 0x0c }) )
            REQUIRE_EQUAL( from_hex<1>( "C"   ), fixed_bytes<1>({ 0x0c }) )
            REQUIRE_EQUAL( from_hex<1>( "C"sv ), fixed_bytes<1>({ 0x0c }) )
            REQUIRE_EQUAL( from_hex<1>( "d"   ), fixed_bytes<1>({ 0x0d }) )
            REQUIRE_EQUAL( from_hex<1>( "d"sv ), fixed_bytes<1>({ 0x0d }) )
            REQUIRE_EQUAL( from_hex<1>( "D"   ), fixed_bytes<1>({ 0x0d }) )
            REQUIRE_EQUAL( from_hex<1>( "D"sv ), fixed_bytes<1>({ 0x0d }) )
            REQUIRE_EQUAL( from_hex<1>( "e"   ), fixed_bytes<1>({ 0x0e }) )
            REQUIRE_EQUAL( from_hex<1>( "e"sv ), fixed_bytes<1>({ 0x0e }) )
            REQUIRE_EQUAL( from_hex<1>( "E"   ), fixed_bytes<1>({ 0x0e }) )
            REQUIRE_EQUAL( from_hex<1>( "E"sv ), fixed_bytes<1>({ 0x0e }) )
            REQUIRE_EQUAL( from_hex<1>( "f"   ), fixed_bytes<1>({ 0x0f }) )
            REQUIRE_EQUAL( from_hex<1>( "f"sv ), fixed_bytes<1>({ 0x0f }) )
            REQUIRE_EQUAL( from_hex<1>( "F"   ), fixed_bytes<1>({ 0x0f }) )
            REQUIRE_EQUAL( from_hex<1>( "F"sv ), fixed_bytes<1>({ 0x0f }) )
            REQUIRE_EQUAL( from_hex<2>( "011"   ), fixed_bytes<2>({ 0x00, 0x11 }) )
            REQUIRE_EQUAL( from_hex<2>( "011"sv ), fixed_bytes<2>({ 0x00, 0x11 }) )
            REQUIRE_EQUAL( from_hex<2>( "122"   ), fixed_bytes<2>({ 0x01, 0x22 }) )
            REQUIRE_EQUAL( from_hex<2>( "122"sv ), fixed_bytes<2>({ 0x01, 0x22 }) )
            REQUIRE_EQUAL( from_hex<2>( "233"   ), fixed_bytes<2>({ 0x02, 0x33 }) )
            REQUIRE_EQUAL( from_hex<2>( "233"sv ), fixed_bytes<2>({ 0x02, 0x33 }) )
            REQUIRE_EQUAL( from_hex<2>( "344"   ), fixed_bytes<2>({ 0x03, 0x44 }) )
            REQUIRE_EQUAL( from_hex<2>( "344"sv ), fixed_bytes<2>({ 0x03, 0x44 }) )
            REQUIRE_EQUAL( from_hex<2>( "455"   ), fixed_bytes<2>({ 0x04, 0x55 }) )
            REQUIRE_EQUAL( from_hex<2>( "455"sv ), fixed_bytes<2>({ 0x04, 0x55 }) )
            REQUIRE_EQUAL( from_hex<2>( "566"   ), fixed_bytes<2>({ 0x05, 0x66 }) )
            REQUIRE_EQUAL( from_hex<2>( "566"sv ), fixed_bytes<2>({ 0x05, 0x66 }) )
            REQUIRE_EQUAL( from_hex<2>( "677"   ), fixed_bytes<2>({ 0x06, 0x77 }) )
            REQUIRE_EQUAL( from_hex<2>( "677"sv ), fixed_bytes<2>({ 0x06, 0x77 }) )
            REQUIRE_EQUAL( from_hex<2>( "788"   ), fixed_bytes<2>({ 0x07, 0x88 }) )
            REQUIRE_EQUAL( from_hex<2>( "788"sv ), fixed_bytes<2>({ 0x07, 0x88 }) )
            REQUIRE_EQUAL( from_hex<2>( "7f8"   ), fixed_bytes<2>({ 0x07, 0xf8 }) )
            REQUIRE_EQUAL( from_hex<2>( "7f8"sv ), fixed_bytes<2>({ 0x07, 0xf8 }) )
            REQUIRE_EQUAL( from_hex<2>( "7F8"   ), fixed_bytes<2>({ 0x07, 0xf8 }) )
            REQUIRE_EQUAL( from_hex<2>( "7F8"sv ), fixed_bytes<2>({ 0x07, 0xf8 }) )
            REQUIRE_EQUAL( from_hex<2>( "a5b"   ), fixed_bytes<2>({ 0x0a, 0x5b }) )
            REQUIRE_EQUAL( from_hex<2>( "a5b"sv ), fixed_bytes<2>({ 0x0a, 0x5b }) )
            REQUIRE_EQUAL( from_hex<2>( "A5B"   ), fixed_bytes<2>({ 0x0a, 0x5b }) )
            REQUIRE_EQUAL( from_hex<2>( "A5B"sv ), fixed_bytes<2>({ 0x0a, 0x5b }) )
            REQUIRE_EQUAL( from_hex<2>( "fff"   ), fixed_bytes<2>({ 0x0f, 0xff }) )
            REQUIRE_EQUAL( from_hex<2>( "fff"sv ), fixed_bytes<2>({ 0x0f, 0xff }) )
            REQUIRE_EQUAL( from_hex<2>( "FFF"   ), fixed_bytes<2>({ 0x0f, 0xff }) )
            REQUIRE_EQUAL( from_hex<2>( "FFF"sv ), fixed_bytes<2>({ 0x0f, 0xff }) )
            REQUIRE_EQUAL( from_hex<3>( "12345"   ), fixed_bytes<3>({ 0x01, 0x23, 0x45 }) )
            REQUIRE_EQUAL( from_hex<3>( "12345"sv ), fixed_bytes<3>({ 0x01, 0x23, 0x45 }) )
            REQUIRE_EQUAL( from_hex<3>( "54321"   ), fixed_bytes<3>({ 0x05, 0x43, 0x21 }) )
            REQUIRE_EQUAL( from_hex<3>( "54321"sv ), fixed_bytes<3>({ 0x05, 0x43, 0x21 }) )
            REQUIRE_EQUAL( from_hex<3>( "a4b2c"   ), fixed_bytes<3>({ 0x0a, 0x4b, 0x2c }) )
            REQUIRE_EQUAL( from_hex<3>( "a4b2c"sv ), fixed_bytes<3>({ 0x0a, 0x4b, 0x2c }) )
            REQUIRE_EQUAL( from_hex<3>( "A4b2C"   ), fixed_bytes<3>({ 0x0a, 0x4b, 0x2c }) )
            REQUIRE_EQUAL( from_hex<3>( "A4b2C"sv ), fixed_bytes<3>({ 0x0a, 0x4b, 0x2c }) )
            REQUIRE_EQUAL( from_hex<4>( "1234567"   ), fixed_bytes<4>({ 0x01, 0x23, 0x45, 0x67 }) )
            REQUIRE_EQUAL( from_hex<4>( "1234567"sv ), fixed_bytes<4>({ 0x01, 0x23, 0x45, 0x67 }) )
            REQUIRE_EQUAL( from_hex<4>( "7654321"   ), fixed_bytes<4>({ 0x07, 0x65, 0x43, 0x21 }) )
            REQUIRE_EQUAL( from_hex<4>( "7654321"sv ), fixed_bytes<4>({ 0x07, 0x65, 0x43, 0x21 }) )
            REQUIRE_EQUAL( from_hex<4>( "a4b2c3d"   ), fixed_bytes<4>({ 0x0a, 0x4b, 0x2c, 0x3d }) )
            REQUIRE_EQUAL( from_hex<4>( "a4b2c3d"sv ), fixed_bytes<4>({ 0x0a, 0x4b, 0x2c, 0x3d }) )
            REQUIRE_EQUAL( from_hex<4>( "A4b2C3D"   ), fixed_bytes<4>({ 0x0a, 0x4b, 0x2c, 0x3d }) )
            REQUIRE_EQUAL( from_hex<4>( "A4b2C3D"sv ), fixed_bytes<4>({ 0x0a, 0x4b, 0x2c, 0x3d }) )

            REQUIRE_EQUAL("0"_hex, bytes({0x00}))
            REQUIRE_EQUAL("1"_hex, bytes({0x01}))
            REQUIRE_EQUAL("2"_hex, bytes({0x02}))
            REQUIRE_EQUAL("3"_hex, bytes({0x03}))
            REQUIRE_EQUAL("4"_hex, bytes({0x04}))
            REQUIRE_EQUAL("5"_hex, bytes({0x05}))
            REQUIRE_EQUAL("6"_hex, bytes({0x06}))
            REQUIRE_EQUAL("7"_hex, bytes({0x07}))
            REQUIRE_EQUAL("8"_hex, bytes({0x08}))
            REQUIRE_EQUAL("9"_hex, bytes({0x09}))
            REQUIRE_EQUAL("a"_hex, bytes({0x0a}))
            REQUIRE_EQUAL("A"_hex, bytes({0x0a}))
            REQUIRE_EQUAL("b"_hex, bytes({0x0b}))
            REQUIRE_EQUAL("B"_hex, bytes({0x0b}))
            REQUIRE_EQUAL("c"_hex, bytes({0x0c}))
            REQUIRE_EQUAL("C"_hex, bytes({0x0c}))
            REQUIRE_EQUAL("d"_hex, bytes({0x0d}))
            REQUIRE_EQUAL("e"_hex, bytes({0x0e}))
            REQUIRE_EQUAL("E"_hex, bytes({0x0e}))
            REQUIRE_EQUAL("f"_hex, bytes({0x0f}))
            REQUIRE_EQUAL("F"_hex, bytes({0x0f}))
            REQUIRE_EQUAL("011"_hex, bytes( { 0x00, 0x11 } ))
            REQUIRE_EQUAL("122"_hex, bytes( { 0x01, 0x22 } ))
            REQUIRE_EQUAL("233"_hex, bytes( { 0x02, 0x33 } ))
            REQUIRE_EQUAL("344"_hex, bytes( { 0x03, 0x44 } ))
            REQUIRE_EQUAL("455"_hex, bytes( { 0x04, 0x55 } ))
            REQUIRE_EQUAL("566"_hex, bytes( { 0x05, 0x66 } ))
            REQUIRE_EQUAL("677"_hex, bytes( { 0x06, 0x77 } ))
            REQUIRE_EQUAL("788"_hex, bytes( { 0x07, 0x88 } ))
            REQUIRE_EQUAL("7f8"_hex, bytes( { 0x07, 0xf8 } ))
            REQUIRE_EQUAL("7F8"_hex, bytes( { 0x07, 0xf8 } ))
            REQUIRE_EQUAL("a5b"_hex, bytes( { 0x0a, 0x5b}))
            REQUIRE_EQUAL("A5B"_hex, bytes( { 0x0a, 0x5b}))
            REQUIRE_EQUAL("fff"_hex, bytes( { 0x0f, 0xff } ))
            REQUIRE_EQUAL("FFF"_hex, bytes( { 0x0f, 0xff } ))
            REQUIRE_EQUAL("12345"_hex, bytes( { 0x01, 0x23, 0x45 } ))
            REQUIRE_EQUAL("54321"_hex, bytes( { 0x05, 0x43, 0x21 } ))
            REQUIRE_EQUAL("a4b2c"_hex, bytes( { 0x0a, 0x4b, 0x2c } ))
            REQUIRE_EQUAL("A4b2C"_hex, bytes( { 0x0a, 0x4b, 0x2c } ))
            REQUIRE_EQUAL("1234567"_hex, bytes( { 0x01, 0x23, 0x45, 0x67 } ))
            REQUIRE_EQUAL("7654321"_hex, bytes( { 0x07, 0x65, 0x43, 0x21 } ))
            REQUIRE_EQUAL("a4b2c3d"_hex, bytes( { 0x0a, 0x4b, 0x2c, 0x3d } ))
            REQUIRE_EQUAL("A4b2C3D"_hex, bytes( { 0x0a, 0x4b, 0x2c, 0x3d } ))

            // Test mixed case
            REQUIRE_EQUAL( from_hex( "aB" )               , bytes( { 0xab } ))
            REQUIRE_EQUAL( from_hex( "Ab" )               , bytes( { 0xab } ))
            REQUIRE_EQUAL( from_hex( "aBc" )             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( from_hex( "AbC" )             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( from_hex( "ABc" )             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( from_hex( "aBC" )             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( from_hex( "aBcD" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "AbCd" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "ABcd" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "aBCd" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "abCD" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "AbcD" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "aBcD" )            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( from_hex( "Ab0d6Cf" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "Ab0d6CF" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "Ab0D6CF" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "ab0d6CF" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "AB0d6Cf" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "AB0D6cF" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "AB0D6cf" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "aB0d6Cf" )         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( from_hex( "0123456789AbcDef" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789aBcDeF" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789ABcDeF" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789AbCdEf" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789aBCdEf" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789AbcDeF" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789aBcDEF" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789AbCDEF" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( from_hex( "0123456789ABCDEf" ), bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))

            REQUIRE_EQUAL( from_hex<1>( "aB"   ), fixed_bytes<1>({ 0xab }) )
            REQUIRE_EQUAL( from_hex<1>( "aB"sv ), fixed_bytes<1>({ 0xab }) )
            REQUIRE_EQUAL( from_hex<1>( "Ab"   ), fixed_bytes<1>({ 0xab }) )
            REQUIRE_EQUAL( from_hex<1>( "Ab"sv ), fixed_bytes<1>({ 0xab }) )
            REQUIRE_EQUAL( from_hex<2>( "aBc"   ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "aBc"sv ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "AbC"   ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "AbC"sv ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "ABc"   ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "ABc"sv ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "aBC"   ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "aBC"sv ), fixed_bytes<2>({ 0x0a, 0xbc }) )
            REQUIRE_EQUAL( from_hex<2>( "aBcD"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "aBcD"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "AbCd"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "AbCd"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "ABcd"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "ABcd"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "aBCd"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "aBCd"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "abCD"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "abCD"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "AbcD"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "AbcD"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "aBcD"   ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<2>( "aBcD"sv ), fixed_bytes<2>({ 0xab, 0xcd }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0d6Cf"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0d6Cf"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0d6CF"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0d6CF"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0D6CF"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "Ab0D6CF"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "ab0d6CF"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "ab0d6CF"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0d6Cf"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0d6Cf"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0D6cF"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0D6cF"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0D6cf"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "AB0D6cf"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "aB0d6Cf"   ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<4>( "aB0d6Cf"sv ), fixed_bytes<4>({ 0x0a, 0xb0, 0xd6, 0xcf }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbcDef"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbcDef"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBcDeF"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBcDeF"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789ABcDeF"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789ABcDeF"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbCdEf"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbCdEf"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBCdEf"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBCdEf"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbcDeF"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbcDeF"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBcDEF"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789aBcDEF"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbCDEF"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789AbCDEF"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789ABCDEf"   ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )
            REQUIRE_EQUAL( from_hex<8>( "0123456789ABCDEf"sv ), fixed_bytes<8>({ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }) )

            REQUIRE_EQUAL( "aB"_hex              , bytes( { 0xab } ))
            REQUIRE_EQUAL( "Ab"_hex              , bytes( { 0xab } ))
            REQUIRE_EQUAL( "aBc"_hex             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( "AbC"_hex             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( "ABc"_hex             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( "aBC"_hex             , bytes( { 0x0a, 0xbc } ))
            REQUIRE_EQUAL( "aBcD"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "AbCd"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "ABcd"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "aBCd"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "abCD"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "AbcD"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "aBcD"_hex            , bytes( { 0xab, 0xcd } ))
            REQUIRE_EQUAL( "Ab0d6Cf"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "Ab0d6CF"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "Ab0D6CF"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "ab0d6CF"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "AB0d6Cf"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "AB0D6cF"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "AB0D6cf"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "aB0d6Cf"_hex         , bytes( { 0x0a, 0xb0, 0xd6, 0xcf }))
            REQUIRE_EQUAL( "0123456789AbcDef"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789aBcDeF"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789ABcDeF"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789AbCdEf"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789aBCdEf"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789AbcDeF"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789aBcDEF"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789AbCDEF"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))
            REQUIRE_EQUAL( "0123456789ABCDEf"_hex, bytes( { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ))

            // Leading zeros
            REQUIRE_EQUAL( from_hex( "00" ), bytes( { 0x00 } ))
            REQUIRE_EQUAL( from_hex( "000" ), bytes( { 0x00, 0x00 } ))
            REQUIRE_EQUAL( from_hex( "0000" ), bytes( { 0x00, 0x00 } ))
            REQUIRE_EQUAL( from_hex( "00000" ), bytes( { 0x00, 0x00, 0x00 } ))
            REQUIRE_EQUAL( from_hex( "000000" ), bytes( { 0x00, 0x00, 0x00 } ))
            REQUIRE_EQUAL( from_hex( "0000000" ), bytes( { 0x00, 0x00, 0x00, 0x00} ))
            REQUIRE_EQUAL( from_hex( "00112233" ), bytes( { 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( from_hex( "0000112233" ), bytes( { 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( from_hex( "000000112233" ), bytes( { 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( from_hex( "00000000112233" ), bytes( { 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( from_hex( "0000000000112233" ), bytes( { 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( from_hex( "000000000000112233" ), bytes( { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))

            REQUIRE_EQUAL( from_hex<1>( "00"   ), fixed_bytes<1>({0x00 }) )
            REQUIRE_EQUAL( from_hex<1>( "00"sv ), fixed_bytes<1>({0x00 }) )
            REQUIRE_EQUAL( from_hex<2>( "000"   ), fixed_bytes<2>({0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<2>( "000"sv ), fixed_bytes<2>({0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<2>( "0000"   ), fixed_bytes<2>({0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<2>( "0000"sv ), fixed_bytes<2>({0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<3>( "00000"   ), fixed_bytes<3>({0x00, 0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<3>( "00000"sv ), fixed_bytes<3>({0x00, 0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<3>( "000000"   ), fixed_bytes<3>({0x00, 0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<3>( "000000"sv ), fixed_bytes<3>({0x00, 0x00, 0x00 }) )
            REQUIRE_EQUAL( from_hex<4>( "0000000"   ), fixed_bytes<4>({0x00, 0x00, 0x00, 0x00}) )
            REQUIRE_EQUAL( from_hex<4>( "0000000"sv ), fixed_bytes<4>({0x00, 0x00, 0x00, 0x00}) )
            REQUIRE_EQUAL( from_hex<4>( "00112233"   ), fixed_bytes<4>({0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<4>( "00112233"sv ), fixed_bytes<4>({0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<5>( "0000112233"   ), fixed_bytes<5>({0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<5>( "0000112233"sv ), fixed_bytes<5>({0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<6>( "000000112233"   ), fixed_bytes<6>({0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<6>( "000000112233"sv ), fixed_bytes<6>({0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<7>( "00000000112233"   ), fixed_bytes<7>({0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<7>( "00000000112233"sv ), fixed_bytes<7>({0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<8>( "0000000000112233"   ), fixed_bytes<8>({0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<8>( "0000000000112233"sv ), fixed_bytes<8>({0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<9>( "000000000000112233"   ), fixed_bytes<9>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )
            REQUIRE_EQUAL( from_hex<9>( "000000000000112233"sv ), fixed_bytes<9>({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }) )

            REQUIRE_EQUAL( "00"_hex, bytes( { 0x00 } ))
            REQUIRE_EQUAL( "000"_hex, bytes( { 0x00, 0x00 } ))
            REQUIRE_EQUAL( "0000"_hex, bytes( { 0x00, 0x00 } ))
            REQUIRE_EQUAL( "00000"_hex, bytes( { 0x00, 0x00, 0x00 } ))
            REQUIRE_EQUAL( "000000"_hex, bytes( { 0x00, 0x00, 0x00 } ))
            REQUIRE_EQUAL( "0000000"_hex, bytes( { 0x00, 0x00, 0x00, 0x00} ))
            REQUIRE_EQUAL( "00112233"_hex, bytes( { 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( "0000112233"_hex, bytes( { 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( "000000112233"_hex, bytes( { 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( "00000000112233"_hex, bytes( { 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( "0000000000112233"_hex, bytes( { 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))
            REQUIRE_EQUAL( "000000000000112233"_hex, bytes( { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 }))

            // Failure cases
            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( 'x');
            })

            REQUIRE_ASSERT( "Invalid hex string", [&]() {
                from_hex( nullptr, 5, nullptr, 0 );
            })

             REQUIRE_ASSERT( "Invalid hex string", [&]() {
                bytes out(5);
                from_hex( nullptr, 5, out.data(), out.size() );
            })

            REQUIRE_ASSERT( "Invalid hex string", [&]() { // bytes case
                from_hex( nullptr, 5 );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() {
                bytes out(1);
                from_hex( "000101", 6, out.data(), out.size() );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // std::string case
                bytes out(1);
                from_hex( std::string( "000101" ), out.data(), out.size() );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // std::string_view case
                bytes out(1);
                from_hex( std::string_view( "000101" ), out.data(), out.size() );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<0>( std::string_view( "000101" ) );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<0>( "000101" );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<1>( std::string_view( "000101" ) );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<1>( "000101" );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<2>( std::string_view( "000101" ) );
            })

            REQUIRE_ASSERT( "Invalid out data size", [&]() { // fixed bytes case
                from_hex<2>( "000101" );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "0x1234", 6 );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "0x1234" );
            })

             REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "0x1234"sv );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                "0x1234"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character 'X'", [&]() {
                from_hex( "0X1234", 6 );
            })

            REQUIRE_ASSERT( "Invalid hex character 'X'", [&]() {
                from_hex( "0X1234" );
            })

            REQUIRE_ASSERT( "Invalid hex character 'X'", [&]() {
                from_hex( "0X1234"sv );
            })

            REQUIRE_ASSERT( "Invalid hex character 'X'", [&]() {
                "0X1234"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( " 1234", 5 );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() { // hex literal case
                " 000101"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( " 1234" );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( "1234 ", 5 );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( "1234 " );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( "1234 "sv );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() { // hex literal case
                "000101 "_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( " 1234 ", 6 );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() {
                from_hex( " 1234 " );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "12x34", 5 );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "12x34" );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() { // hex literal case
                "0001x01"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "12x34u", 6 );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "12x34u" );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                from_hex( "12x34u"sv );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() {
                "12x34u"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character 'n'", [&]() {
                from_hex( "an12x34u", 8 );
            })

            REQUIRE_ASSERT( "Invalid hex character 'n'", [&]() {
                from_hex( "an12x34u" );
            })

            REQUIRE_ASSERT( "Invalid hex character 'n'", [&]() {
                from_hex( "an12x34u"sv );
            })

            REQUIRE_ASSERT( "Invalid hex character 'n'", [&]() {
                "an12x34u"_hex;
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "\0""1234", 5 ); // 0 has to be escaped otherwise the string sequence
                                           // is treated as 012 aka oct number representing number 10 ('\n') and "34"
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "\0""1234" );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "1234\0", 5 );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "1234\0" );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "1234\0aX", 5 );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "1234\0aX" );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "\0""1234 ", 6 );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "\0""1234 " );
            })

            REQUIRE_ASSERT( "Invalid hex character '<null>'", [&]() {
                from_hex( "\0 1234 " );
            })

            REQUIRE_ASSERT( "Invalid hex character 'x'", [&]() { // fixed bytes case
                from_hex<8>( "0001x01" );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() { // fixed bytes case
                from_hex<8>( " 000101" );
            })

            REQUIRE_ASSERT( "Invalid hex character ' '", [&]() { // fixed bytes case
                from_hex<8>( "000101 " );
            })
        }

        // memxor tests
        // note: test cases generated with python
        {
            bytes a = ""_hex;
            memxor( a, ""_hex, 0 );
            REQUIRE_EQUAL( a, ""_hex );

            a = ""_hex;
            memxor( a, ""_hex, 1 );
            REQUIRE_EQUAL( a, ""_hex );

            a = ""_hex;
            memxor( a, ""_hex, 32 );
            REQUIRE_EQUAL( a, ""_hex );

            a = ""_hex;
            memxor( a, "AABBCCDD"_hex, 32 );
            REQUIRE_EQUAL( a, ""_hex );

            a = "AABBCCDD"_hex;
            memxor( a, ""_hex, 32 );
            REQUIRE_EQUAL( a, "AABBCCDD"_hex );

            a = "AA"_hex;
            memxor( a, "BB"_hex, 32 );
            REQUIRE_EQUAL( a, "11"_hex );

            a = "AABB"_hex;
            memxor( a, "BB"_hex, 32 );
            REQUIRE_EQUAL( a, "11BB"_hex );

            a = "AABB"_hex;
            memxor( a, "BBAA"_hex, 32 );
            REQUIRE_EQUAL( a, "1111"_hex );

            a = "AABBCC"_hex;
            memxor( a, "BBAA"_hex, 32 );
            REQUIRE_EQUAL( a, "1111CC"_hex );

            a = "AABBCC"_hex;
            memxor( a, "BBAAFF"_hex, 32 );
            REQUIRE_EQUAL( a, "111133"_hex );

            a = "AABBCC"_hex;
            memxor( a, "BBAAFF12"_hex, 32 );
            REQUIRE_EQUAL( a, "111133"_hex );

            a = "AABBCC34"_hex;
            memxor( a, "BBAAFF12"_hex, 32 );
            REQUIRE_EQUAL( a, "11113326"_hex );

            a = "AABBCC3400"_hex;
            memxor( a, "BBAAFF12"_hex, 32 );
            REQUIRE_EQUAL( a, "1111332600"_hex );

            a = "AABBCC3400"_hex;
            memxor( a, "BBAAFF12AA"_hex, 32 );
            REQUIRE_EQUAL( a, "11113326AA"_hex );

            a = "AABBCC3400AA"_hex;
            memxor( a, "BBAAFF12AA55"_hex, 32 );
            REQUIRE_EQUAL( a, "11113326AAFF"_hex );

            // test memxor a with same size b
            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 0 );
            REQUIRE_EQUAL( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 1 );
            REQUIRE_EQUAL( a, "0855AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 2 );
            REQUIRE_EQUAL( a, "08CCAB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 3 );
            REQUIRE_EQUAL( a, "08CCF380D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 4 );
            REQUIRE_EQUAL( a, "08CCF315D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 5 );
            REQUIRE_EQUAL( a, "08CCF3155FDB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 6 );
            REQUIRE_EQUAL( a, "08CCF3155F1492E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 7 );
            REQUIRE_EQUAL( a, "08CCF3155F1495E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 8 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A89F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 9 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A73F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 10 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E45D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 11 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E40D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 12 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400C6CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 13 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBAA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 14 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C0A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 15 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C343EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 16 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C3493DF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 17 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 18 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B433DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 19 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A2D6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 20 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23CF41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 21 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C791591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 22 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 23 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 24 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 25 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC29A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 26 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 27 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31287073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 28 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F73CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 29 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F95CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 30 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F95A35C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 31 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F95A32A53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 32 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F95A32A8E"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "069958958DCF0782FACB05DFD6893EADF4329FEA8DF095393F188B7FE66F76DD"_hex, 33 );
            REQUIRE_EQUAL( a, "08CCF3155F14956A733E400CBA2C34932B43A23C79E504E0EC31280F95A32A8E"_hex );

            // memxor a with itself
            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 0 );
            REQUIRE_EQUAL( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 1 );
            REQUIRE_EQUAL( a, "0055AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 2 );
            REQUIRE_EQUAL( a, "0000AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 3 );
            REQUIRE_EQUAL( a, "00000080D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 4 );
            REQUIRE_EQUAL( a, "00000000D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 5 );
            REQUIRE_EQUAL( a, "0000000000DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 6 );
            REQUIRE_EQUAL( a, "00000000000092E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 7 );
            REQUIRE_EQUAL( a, "00000000000000E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 8 );
            REQUIRE_EQUAL( a, "000000000000000089F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 9 );
            REQUIRE_EQUAL( a, "000000000000000000F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 10 );
            REQUIRE_EQUAL( a, "0000000000000000000045D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 11 );
            REQUIRE_EQUAL( a, "0000000000000000000000D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 12 );
            REQUIRE_EQUAL( a, "0000000000000000000000006CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 13 );
            REQUIRE_EQUAL( a, "00000000000000000000000000A50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 14 );
            REQUIRE_EQUAL( a, "00000000000000000000000000000A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 15 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000003EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 16 );
            REQUIRE_EQUAL( a, "00000000000000000000000000000000DF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 17 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 18 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000003DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 19 );
            REQUIRE_EQUAL( a, "00000000000000000000000000000000000000D6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 20 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 21 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000001591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 22 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000091D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 23 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 24 );
            REQUIRE_EQUAL( a, "000000000000000000000000000000000000000000000000D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 25 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000029A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 26 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 27 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000007073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 28 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 29 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000000CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 30 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000000005C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 31 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000000000053"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 32 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000000000000"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex, 33 );
            REQUIRE_EQUAL( a, "0000000000000000000000000000000000000000000000000000000000000000"_hex );

            // test memxor a with smaller b
            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 0 );
            REQUIRE_EQUAL( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 1 );
            REQUIRE_EQUAL( a, "0355AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 2 );
            REQUIRE_EQUAL( a, "030AAB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 3 );
            REQUIRE_EQUAL( a, "030A8480D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 4 );
            REQUIRE_EQUAL( a, "030A84B6D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 5 );
            REQUIRE_EQUAL( a, "030A84B63FDB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 6 );
            REQUIRE_EQUAL( a, "030A84B63F0A92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 7 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 8 );
            REQUIRE_EQUAL( a, "030A84B63F0AA94689F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 9 );
            REQUIRE_EQUAL( a, "030A84B63F0AA94634F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 10 );
            REQUIRE_EQUAL( a, "030A84B63F0AA946342845D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 11 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFD36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 12 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC16CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 13 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 14 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 15 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 16 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B92DF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 17 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 18 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 19 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 20 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 21 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 22 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 23 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 24 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 25 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 26 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 27 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 28 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 29 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 30 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 31 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 32 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC9551"_hex, 33 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            // test memxor a with larger b
            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 0 );
            REQUIRE_EQUAL( a, "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 1 );
            REQUIRE_EQUAL( a, "0355AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 2 );
            REQUIRE_EQUAL( a, "030AAB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 3 );
            REQUIRE_EQUAL( a, "030A8480D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 4 );
            REQUIRE_EQUAL( a, "030A84B6D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 5 );
            REQUIRE_EQUAL( a, "030A84B63FDB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 6 );
            REQUIRE_EQUAL( a, "030A84B63F0A92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 7 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 8 );
            REQUIRE_EQUAL( a, "030A84B63F0AA94689F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 9 );
            REQUIRE_EQUAL( a, "030A84B63F0AA94634F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 10 );
            REQUIRE_EQUAL( a, "030A84B63F0AA946342845D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 11 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFD36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 12 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC16CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 13 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 14 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0A3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 15 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B3EDF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 16 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B92DF713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 17 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A713DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 18 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A203DD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 19 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202CD6F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 20 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C67F41591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 21 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E1591D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 22 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E3291D9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 23 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323AD9D329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 24 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0ED329A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 25 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB829A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 26 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB808A37073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 27 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB808287073CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 28 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C373CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 29 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D6CC5C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 30 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D6195C53"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 31 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D6191153"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 32 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 33 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 34 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 35 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 36 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 37 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 38 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 39 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 40 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 41 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 42 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 43 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 44 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 45 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 46 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 47 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 48 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 49 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 50 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );

            a = "0E55AB80D2DB92E889F545D36CA50A3EDF713DD6F41591D9D329A37073CC5C53"_hex;
            memxor( a, "0D5F2F36EDD13BAEBDDDFA12530F01AC955111b1ca27abd76b218bb3a5d54d3cc1b3f2ee16e20b2200df05032dcc945dc205"_hex, 51 );
            REQUIRE_EQUAL( a, "030A84B63F0AA9463428BFC13FAA0B924A202C673E323A0EB80828C3D619116F"_hex );
        }
    EOSIO_TEST_END
}