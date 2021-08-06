// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <array>
#include <cstdint>
#include <vector>

#include <eosio/fixed_bytes.hpp>

#include "types.hpp"

namespace eosiock {

    namespace internal_do_not_use {
        // Implementation in this scope was taken from:
        // https://github.com/XKCP/XKCP/blob/8f447eb59d43fef72297f5f1560e2cefea093b32/Standalone/CompactFIPS202/C/TweetableFIPS202.c

        typedef unsigned long long U;
        typedef byte_t C;

        inline constexpr U rot( U a, U n ) {
            return a << n ^ a >> ( 64 - n );
        }

        constexpr void F(U *s)
        {
            C R = 1;
            U t = 0;
            U B[5] = { 0 };

            for( U n = 0; n < 24; n++ ) {
                for( U i = 0; i < 5; i++ ) {
                    B[i] = 0;
                    for( U j = 0; j < 5; j++ ) {
                        B[i] ^= s[ i + 5 * j ];
                    }
                }

                for( U i = 0; i < 5; i++ ) {
                    t = B[ (i + 4) % 5 ] ^ rot( B[ (i + 1) % 5 ], 1 );

                    for( U j = 0; j < 5; j++ ) {
                        s[ i + 5 * j ] ^= t;
                    }
                }

                t = s[1];
                C x = 1;
                C y = 0;
                C r = 0;
                U Y = 0;

                for( U j = 0; j < 24; j++ ) {
                    r += j + 1;
                    Y = 2 * x + 3 * y;
                    x = y;
                    y = Y % 5;
                    Y = s[ x + 5 * y ];
                    s[ x + 5 * y ] = rot( t, r % 64 );
                    t = Y;
                }

                for( U j = 0; j < 5; j++ ) {
                    for( U i = 0; i < 5; i++ ) {
                        B[i] = s[ i + 5 * j ];
                    }

                    for( U i = 0; i < 5; i++ ) {
                        s[ i + 5 * j ] = B[i] ^ ( ~B[ (i + 1) % 5 ] & B[ (i + 2) % 5 ] );
                    }
                }

                for( U j = 0; j < 7; j++ ) {
                    if( ( R = (R << 1) ^ ( 113 * (R >> 7) ) ) & 2 ) {
                        *s ^= 1ULL << ( (1 << j) - 1 );
                    }
                }
            }
        }

        template<C r, C p>
        constexpr void keccak(const C* m, U n, C* h, U d)
        {
            U s[25]  = { 0 };
            C t[200] = { 0 };

            while ( n >= r ) {
                for( U i = 0; i < r; i++ ) {
                    s[ i/8 ] ^= static_cast<U>( m[i] ) << i % 8 * 8;
                }

                F(s);
                n -= r;
                m += r;
            }

            for( U i = 0; i < n; i++ ) {
                t[i] = m[i];
            }

            t[n]   =  p;
            t[r-1] |= 128;

            for( U i = 0; i < r; i++ ) {
                s[i/8] ^= static_cast<U>( t[i] ) << i % 8 * 8;
            }

            for( U i = 0; i < d; i++ ) {
                if(0 == i % r) {
                    F(s);
                }

                h[i] = s[ i % r/8 ] >> 8 * (i % 8);
            }
        }
    } // internal_use_do_not_use


    inline eosio::checksum256 sha3_256(const bytes_view& data)
    {
        std::array<byte_t, 32> h;
        internal_do_not_use::keccak<17 * 8, 6>(
            reinterpret_cast<const internal_do_not_use::C*>( data.data() ),
            data.size(),
            h.data(),
            h.size()
        );
        return h;
    }

    inline eosio::checksum512 sha3_512(const bytes_view& data)
    {
        std::array<byte_t, 64> h;
        internal_do_not_use::keccak<9 * 8, 6>(
            reinterpret_cast<const internal_do_not_use::C*>(data.size()),
            data.size(),
            h.data(),
            h.size()
        );
        return h;
    }

    template<std::size_t Size>
    inline eosio::fixed_bytes<Size> shake128_fixed(const bytes_view& data)
    {
        using hash = eosio::fixed_bytes<Size>;
        using word_t = typename hash::word_t;
        static_assert( Size % sizeof(word_t) == 0,
            "the size of digest is not divisible by the size of word"
        );

        eosio::fixed_bytes<Size> h;
        internal_do_not_use::keccak<21 * 8, 31>(
            reinterpret_cast<const internal_do_not_use::C*>(data.data()),
            data.size(),
            h.data(),
            Size
        );
        return h;
    }

    inline bytes shake128(const bytes_view& data, std::size_t out_len)
    {
        bytes h( out_len );
        internal_do_not_use::keccak<21 * 8, 31>(
            reinterpret_cast<const internal_do_not_use::C*>(data.data()),
            data.size(),
            h.data(),
            h.size()
        );
        return h;
    }

    template<std::size_t Size>
    inline eosio::fixed_bytes<Size> shake256_fixed(const bytes_view& data)
    {
        using hash = eosio::fixed_bytes<Size>;
        using word_t = typename hash::word_t;
        static_assert( Size % sizeof(word_t) == 0,
            "the size of digest is not divisible by the size of word"
        );

        std::array<uint8_t, Size> h;
        internal_do_not_use::keccak<17 * 8, 31>(
            reinterpret_cast<const internal_do_not_use::C*>(data.data()),
            data.size(),
            h.data(),
            h.size()
        );

        return h;
    }

    inline bytes shake256(const bytes_view& data, std::size_t out_len)
    {
        bytes h( out_len );
        internal_do_not_use::keccak<17 * 8, 31>(
            data.data(),
            data.size(),
            h.data(),
            h.size()
        );
        return h;
    }
}