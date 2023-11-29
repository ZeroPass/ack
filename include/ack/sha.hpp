// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <cstdint>
#include <vector>

#include <ack/types.hpp>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

namespace ack {
     namespace internal_do_not_use {
        static_assert( sizeof( uint32_t ) == 4, "uint32_t must be 4 bytes" );
        static_assert( sizeof( uint64_t ) == 8, "uint64_t must be 8 bytes" );

        constexpr inline size_t sha384_hash_size = 48;
        using sha384_hash = fixed_bytes<sha384_hash_size>;

        constexpr inline size_t sha512_block_size    = 128;
        constexpr inline size_t sha512_hash_size     = 64;
        constexpr inline size_t sha512_padblock_size = 16;
        constexpr inline size_t sha512_rounds        = 80;

        using sha512_word_t    = uint64_t;
        using sha512_hash      = fixed_bytes<sha512_hash_size>;
        using sha512_word_hash = std::array<sha512_word_t, 8>;

        // NIST FIPS 180-4 Section 5.3.4 SHA-384
        constexpr inline sha512_word_hash sha384_initial_hash_values = {
            0xcbbb9d5dc1059ed8ULL,
            0x629a292a367cd507ULL,
            0x9159015a3070dd17ULL,
            0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL,
            0x8eb44a8768581511ULL,
            0xdb0c2e0d64f98fa7ULL,
            0x47b5481dbefa4fa4ULL
        };

        constexpr sha512_word_t K_512[80] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        constexpr inline void write_u64le(byte_t* dest, uint64_t x)
        {
            *dest++ = ( x >> 56 ) & 0xff;
            *dest++ = ( x >> 48 ) & 0xff;
            *dest++ = ( x >> 40 ) & 0xff;
            *dest++ = ( x >> 32 ) & 0xff;
            *dest++ = ( x >> 24 ) & 0xff;
            *dest++ = ( x >> 16 ) & 0xff;
            *dest++ = ( x >>  8 ) & 0xff;
            *dest++ = ( x >>  0 ) & 0xff;
        }

        constexpr inline uint32_t read_u32be(const byte_t* src)
        {
            return static_cast<uint32_t>(
                ( src[0] << 24 ) |
                ( src[1] << 16 ) |
                ( src[2] << 8  ) |
                ( src[3] << 0  )
            );
        }

        constexpr inline uint64_t read_u64be(const byte_t* src)
        {
            uint64_t upper = read_u32be( src );
            uint64_t lower = read_u32be( src + 4 );
            return ( ( upper & 0xffffffff ) << 32 ) | ( lower & 0xffffffff );
        }

        constexpr inline uint64_t ROTR(uint64_t x, uint64_t n)
        {
            // A compiler-recognised implementation of rotate right that avoids the
            // undefined behaviour caused by shifting by the number of bits of the left-hand
            // type. See John Regehr's article https://blog.regehr.org/archives/1063
            return ( x >> n ) | ( x << ( -n & 63 ));
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        constexpr inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
            return ( x & y ) ^ ( ~x & z );
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        constexpr inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
            return ( x & y ) ^ ( x & z ) ^ ( y & z );
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        // Defined as uppercase sigma (Σ) 0
        constexpr inline uint64_t SIG0_512(uint64_t x) {
            return ROTR( x, 28 ) ^ ROTR( x, 34 ) ^ ROTR( x, 39 );
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        // Defined as uppercase sigma (Σ) 1
        constexpr inline uint64_t SIG1_512(uint64_t x) {
            return ROTR( x, 14 ) ^ ROTR( x, 18 ) ^ ROTR( x, 41 );
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        // Defined as lowercase sigma (σ) 0
        constexpr inline uint64_t sig0_512(uint64_t x) {
            return ROTR( x, 1 ) ^ ROTR( x, 8 ) ^ ( x >> 7 );
        }

        // NIST FIPS 180-4 Section 4.1.3 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions"
        // Defined as lowercase sigma (σ) 1
        constexpr inline uint64_t sig1_512(uint64_t x) {
            return ROTR( x, 19 ) ^ ROTR( x, 61 ) ^ ( x >> 6 );
        }

        constexpr inline void sha512_prepare(sha512_word_t* W, size_t t) {
            // Note: Don't change order of addition (cache miss optimization)
            W[t] = W[t - 7] + W[t - 16] + sig0_512( W[t - 15] ) + sig1_512( W[t - 2] ) ;
        }

        template <size_t R, size_t N>
        [[nodiscard]] constexpr inline fixed_bytes<R> truncate(const fixed_bytes<N>& hash)
        {
            static_assert( R <= N );
            fixed_bytes<R> thash;
            memcpy( thash.data(), hash.data(), R );
            return thash;
        }

        constexpr inline void sha512_compress(const byte_t* data, sha512_word_hash& H)
        {
            sha512_word_t W[sha512_rounds] = {0};
            for ( int t = 0; t < 16; t++ ) {
                W[t] = read_u64be(&data[t * sizeof( sha512_word_t )]);
            }

            // partial loop unroll
            for ( size_t t = 16; t < sha512_rounds; t += 16 ) {
                sha512_prepare( W, t      ); sha512_prepare( W, t +  1 );
                sha512_prepare( W, t +  2 ); sha512_prepare( W, t +  3 );
                sha512_prepare( W, t +  4 ); sha512_prepare( W, t +  5 );
                sha512_prepare( W, t +  6 ); sha512_prepare( W, t +  7 );
                sha512_prepare( W, t +  8 ); sha512_prepare( W, t +  9 );
                sha512_prepare( W, t + 10 ); sha512_prepare( W, t + 11 );
                sha512_prepare( W, t + 12 ); sha512_prepare( W, t + 13 );
                sha512_prepare( W, t + 14 ); sha512_prepare( W, t + 15 );
            }

            auto a = H[0];
            auto b = H[1];
            auto c = H[2];
            auto d = H[3];
            auto e = H[4];
            auto f = H[5];
            auto g = H[6];
            auto h = H[7];

            const auto round = [&](size_t t) {
                // Note: Don't change order of addition (cache miss optimization)
                const auto T1 = Ch( e, f, g ) + W[t] + K_512[t] + h  + SIG1_512( e );
                const auto T2 = Maj( a, b, c ) + SIG0_512( a );
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            };

            // partial loop unroll
            for ( size_t t = 0; t < sha512_rounds; t += 16 ) {
                round( t      ); round( t +  1 );
                round( t +  2 ); round( t +  3 );
                round( t +  4 ); round( t +  5 );
                round( t +  6 ); round( t +  7 );
                round( t +  8 ); round( t +  9 );
                round( t + 10 ); round( t + 11 );
                round( t + 12 ); round( t + 13 );
                round( t + 14 ); round( t + 15 );
            }

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        };

        // NIST FIPS 180-4 Section 6.4.2 "SHA-512 Hash Computation"
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
        [[nodiscard]] constexpr inline sha512_hash sha512_compute(const sha512_word_hash& s, const byte_t* data, uint64_t size)
        {
            const uint64_t bit_length_low  = size << 3;
            const uint64_t bit_length_high = size >> (64 - 3);
            sha512_word_hash H = s;

            while ( size >= sha512_block_size ) {
                sha512_compress( data, H );
                data += sha512_block_size;
                size -= sha512_block_size;
            }

            // Add padding
            // NIST FIPS 180-4 Section 5.1.2 "SHA-384, SHA-512, SHA-512/224 and SHA-512/256"
            {
                std::array<byte_t, sha512_block_size> block;
                memcpy( block.data(), data, size );

                auto i = size;
                block[i++] = 0x80;
                if ( i > sha512_block_size - sha512_padblock_size ) {
                    while (i < sha512_block_size) {
                        block[i++] = 0;
                    }
                    sha512_compress( block.data(), H );
                    i = 0;
                }

                while ( i < sha512_block_size - sha512_padblock_size ) {
                    block[i++] = 0;
                }

                write_u64le( &block[i], bit_length_high );
                write_u64le( &block[i + sizeof( sha512_word_t )], bit_length_low );
                sha512_compress( block.data(), H );
            }

            // Convert to little-endian bytes
            sha512_hash hash;
            for ( byte_t i = 0; i < sizeof( sha512_word_t ); i++ ) {
                write_u64le( &hash[i * sizeof( sha512_word_t )], H[i] );
            }

            return hash;
        }
    }

    /**
     * SHA-384 hash function.
     * @note Implementation follows NIST FIPS-180 standard.
     *       https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
     *
     * @param data - data to hash
     * @return 384-bit hash
    */
    [[nodiscard]] inline hash384 sha384(const bytes_view& data)
    {
        using namespace internal_do_not_use;
        return truncate<sha384_hash_size>(
            sha512_compute(sha384_initial_hash_values, data.data(), data.size())
        );
    }
}