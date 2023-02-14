// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include <eosio/eosio.hpp>
#include <eosio/rope.hpp>
#include <eosio/string.hpp>

#include <ack/types.hpp>

#if defined(ACK_ENABLE_DEBUG_LOG) && ACK_ENABLE_DEBUG_LOG == 1
#  define ACK_LOG_DEBUG(...) eosio::print_f( __VA_ARGS__ )
#else
#  define ACK_LOG_DEBUG(...)
#endif

namespace ack {

    inline byte_t from_hex( char c ) {
        if( c >= '0' && c <= '9' )
        return byte_t(c - '0');
        if( c >= 'a' && c <= 'f' )
            return byte_t(c - 'a' + 10);
        if( c >= 'A' && c <= 'F' )
            return byte_t(c - 'A' + 10);
        eosio::check( false, eosio::rope("Invalid hex character '" + eosio::rope(std::string_view(&c, 1)) + "'").c_str() );
        return 0;
    }

    [[maybe_unused]] static size_t from_hex( const char* hex_str, size_t hex_str_len, byte_t* out_data, size_t out_data_len ) {
        if( hex_str_len == 0 ) {
            return 0;
        }

        eosio::check( hex_str != nullptr && hex_str_len % 2 == 0, "Invalid hex string" );
        if ( out_data == nullptr || out_data_len == 0) {
            return hex_str_len / 2; // return required out data size
        }

        // from eosio/fc
        auto i = hex_str;
        auto i_end = hex_str + hex_str_len;
        byte_t* out_pos = (byte_t*)out_data;
        byte_t* out_end = out_pos + out_data_len;
        while ( i != i_end && out_end != out_pos ) {
            *out_pos = byte_t( from_hex( *i ) << 4 );
            ++i;
            if( i != i_end )  {
                *out_pos |= from_hex( *i );
                ++i;
            }
            ++out_pos;
        }
        return size_t(out_pos - (byte_t*)out_data);
    }

    inline size_t from_hex( const eosio::string& hex_str, byte_t* out_data, size_t out_data_len ) {
        eosio::check( hex_str.size() % 2 == 0, "invalid hex string length" );
        return from_hex( hex_str.data(), hex_str.size(), out_data, out_data_len );
    }

    inline size_t from_hex( const std::string_view& hex_str, byte_t* out_data, size_t out_data_len ) {
        eosio::check( hex_str.size() % 2 == 0, "invalid hex string length" );
        return from_hex( hex_str.data(), hex_str.size(), out_data, out_data_len );
    }

    inline bytes from_hex( const char* hex_str, size_t hex_str_len ) {
        bytes r( from_hex( hex_str, hex_str_len, nullptr, 0 ));
        eosio::check( from_hex( hex_str, hex_str_len, r.data(), r.size() ) == r.size(), "failed to parse hex string");
        return r;
    }

    inline bytes from_hex( const eosio::string& hex_str ) {
        return from_hex( hex_str.data(), hex_str.size() );
    }

    inline bytes from_hex( const std::string_view& hex_str ) {
        return from_hex( hex_str.data(), hex_str.size() );
    }

    inline bytes operator""_hex( const char* hex_str, std::size_t len ) {
        return from_hex( std::string_view{ hex_str, len });
    }

    template<typename T, std::size_t S>
    inline void typecastcpy_bytes(std::array<T, S>& dst, const bytes_view src)
    {
       static_assert( std::is_trivial<T>::value );
       memcpy( dst.data(), src.data(), sizeof(T) * S );
    }

    template<typename T, std::size_t S>
    inline void typecastcpy_bytes(std::span<byte_t> dst, const std::array<T, S>& src)
    {
       static_assert( std::is_trivial<T>::value );
       memcpy( dst.data(), src.data(), sizeof(T) * S );
    }

    constexpr inline void memxor(std::span<byte_t> dst, const bytes_view src, size_t num)
    {
        //eosio::check( rhs.size() < lhs.size(), "rhs.size() < lhs.size()" );
        num = std::min( std::min( num, dst.size() ), src.size() );

        using block_t = std::array<uint32_t, 4>;
        constexpr auto block_size = sizeof( block_t::value_type ) * block_t{}.size();
        const size_t num_blocks   = num - ( num % block_size );

        for ( size_t i = 0; i != num_blocks; i += block_size ) {
            block_t x;
            block_t y;
            typecastcpy_bytes( x, dst.subspan(i, block_size) );
            typecastcpy_bytes( y, src.subspan(i, block_size) );

            x[0] ^= y[0];
            x[1] ^= y[1];
            x[2] ^= y[2];
            x[3] ^= y[3];

            typecastcpy_bytes( dst.subspan( i, block_size ), x );
        }

        // XOR remaining data
        for ( size_t i = num_blocks; i != num; i++ ) {
            dst[i] ^= src[i];
        }
    }
}