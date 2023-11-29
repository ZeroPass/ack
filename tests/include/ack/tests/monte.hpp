// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <algorithm>

#include <ack/keccak.hpp>
#include <ack/sha.hpp>
#include <ack/tests/utils.hpp>
#include <ack/types.hpp>
#include <ack/utils.hpp>

namespace ack::tests {
    namespace detail {
        template<std::size_t HLen>
        inline bytes to_bytes(const hash_t<HLen>& h) {
            auto bh = h.extract_as_byte_array();
            return bytes{ (byte_t*)bh.data(), (byte_t*)bh.data() + HLen };
        }
    }

    template<std::size_t HLen>
    using monte_carlo_array =  std::array<fixed_bytes<HLen>, 100>;

    /*
     * Generator function for NIST SHA3VS Monte Carlo PRNG test case array.
     *
     * Implementation follows SHA3VS - 6.3.3 The Pseudorandomly Generated Messages (Monte Carlo) Test
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
    */
    template<std::size_t HLen, typename Lambda>
    static monte_carlo_array<HLen> sha3vs_monte_carlo_prng(Lambda&& hash_func, bytes seed) {
        auto md = std::move( seed );
        monte_carlo_array<HLen> mca;
        for ( std::size_t i = 0; i < 100; i++ ){
            for( std::size_t j = 1; j < 1001; j++ ) {
                md = detail::to_bytes( hash_func( md ) );
            }
            std::copy_n( md.begin(), HLen, mca[i].begin() );
        }
        return mca;
    };

    /*
     * Generator function for NIST SHAVS Monte Carlo PRNG test case array.
     *
     * Implementation follows NIST SHAVS - Section 6.4 The Pseudorandomly Generated Messages (Monte Carlo) Test
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
    */
    template<std::size_t HLen, typename Lambda>
    static monte_carlo_array<HLen> shavs_monte_carlo_prng(Lambda&& hash_func, bytes seed) {
        monte_carlo_array<HLen> mca;
        for ( std::size_t j = 0; j < 100; j++ ){
            std::array<bytes, 3> mdx = {  seed, seed, seed  };
            bytes mdi;
            for( std::size_t i = 3; i < 1003; i++ ) {
                bytes mi;
                mi.reserve( mdx[0].size() + mdx[1].size() + mdx[2].size() );
                for ( const auto& md : mdx ) {
                    mi.insert( mi.end(), md.begin(), md.end() );
                }
                mdi = detail::to_bytes( hash_func( mi ) );
                std::copy( mdx.begin() + 1, mdx.end(), mdx.begin() );
                mdx.back() = mdi;
            }
            std::copy_n( mdi.begin(), HLen, mca[j].begin() );
            seed = std::move( mdi );
        }
        return mca;
    };

    inline monte_carlo_array<48> sha384_monte_carlo_prng(bytes seed) {
        return shavs_monte_carlo_prng<48>( sha384, std::move( seed ) );
    };

    inline monte_carlo_array<32> sha3_256_monte_carlo_prng(bytes seed) {
        return sha3vs_monte_carlo_prng<32>( sha3_256, std::move( seed ));
    };

    inline monte_carlo_array<48> sha3_384_monte_carlo_prng(bytes seed) {
        return sha3vs_monte_carlo_prng<48>( sha3_384, std::move( seed ));
    };

    inline monte_carlo_array<64> sha3_512_monte_carlo_prng(bytes seed) {
        return sha3vs_monte_carlo_prng<64>( sha3_512, std::move( seed ));
    };
}