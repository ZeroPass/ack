// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <iterator>
#include <span>

#include <eosiock/type_traits.hpp>
#include <eosiock/types.hpp>
#include <eosiock/utils.hpp>

namespace eosiock {
    template <typename T>
    constexpr inline bool operator == (const std::span<T>& lhs, const std::span<T>& rhs) {
        if ( lhs.data() == rhs.data() ) {
            return lhs.size() == rhs.size();
        }
        return std::equal(
            std::begin(lhs), std::end(lhs),
            std::begin(rhs), std::end(rhs)
        );
    }

    template <typename T, typename U>
    constexpr inline bool operator == (const std::span<T>& lhs, const U& rhs) {
        return lhs == std::span<T>{ rhs };
    }

    template <typename T, typename U>
    constexpr inline bool operator == (const U& lhs, const std::span<T>& rhs) {
        return std::span<T>{ lhs } == rhs;
    }

    template <typename T>
    constexpr inline bool operator != (const std::span<T>& lhs, const std::span<T>& rhs) {
        return !( lhs == rhs );
    }

    template <typename T, typename U>
    constexpr inline bool operator != (const std::span<T>& lhs, const U& rhs) {
        return lhs != std::span<T>{ rhs };
    }

    template <typename T, typename U>
    inline bool operator != (const U& lhs, const std::span<T>& rhs) {
        return !( lhs == rhs );
    }

    constexpr inline void operator ^= (std::span<byte_t> lhs, const bytes_view rhs)
    {
        //eosio::check( rhs.size() < lhs.size(), "rhs.size() < lhs.size()" );
        using block_t = std::array<uint32_t, 4>;
        constexpr auto block_size = sizeof( block_t::value_type ) * block_t{}.size();
        const size_t num_blocks   = lhs.size() - ( lhs.size() % block_size );

        for ( size_t i = 0; i != num_blocks; i += block_size ) {
            block_t x;
            block_t y;
            array_memcpy( x, lhs.subspan(i, block_size) );
            array_memcpy( y, rhs.subspan(i, block_size) );

            x[0] ^= y[0];
            x[1] ^= y[1];
            x[2] ^= y[2];
            x[3] ^= y[3];

            array_memcpy( lhs.subspan( i, block_size ), x );
        }

        // XOR remaining data
        for ( size_t i = num_blocks; i != lhs.size(); i++ ) {
            lhs[i] ^= rhs[i];
        }
    }
}