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
    namespace detail {
        void cx_assert_failed(){} // Dummy function to cause compilation failure in constant evaluated context
    }

    /** constexpr eosio::check */
    inline constexpr void check(const bool expr, const char* msg)
    {
        if (std::is_constant_evaluated()) {
            if (!expr) detail::cx_assert_failed();
        }
        else {
            eosio::check(expr, msg);
        }
    }

    /**
     * Returns the number of words needed to store the given number of elements of the given type.
     * @tparam T the type of the elements
     *
     * @param size the number of elements
     * @return the number of words needed to store the given number of elements of the given type.
    */
    template <typename T, typename = std::enable_if_t<std::is_trivial_v<T> && !std::is_pointer_v<T>>>
    inline constexpr std::size_t get_word_size(std::size_t size) {
        return (size * sizeof(T) + (sizeof(word_t) - 1)) / sizeof(word_t);
    }

    /**
     * Returns the number of words needed to store the given span.
     * @tparam T the type of the span
     *
     * @param span the span
     * @return the number of words needed to store the given span
    */
    template <typename T>
    inline constexpr std::size_t get_word_size(const std::span<T>& span) {
        return get_word_size<T>( span.size() );
    }

    /**
     * Returns the number of words needed to store the given vector.
     * @tparam T element type of the vector
     *
     * @param vec the vector
     * @return the number of words needed to store the given vector
    */
    template <typename T>
    inline constexpr std::size_t get_word_size(const std::vector<T>& vec) {
        return get_word_size<T>( vec.size() );
    }

    /**
     * Returns the number of words needed to store the given array.
     * @tparam T element type of the array
     * @tparam N size of the array
     *
     * @param a the array
     * @return the number of words needed to store the given array
    */
    template <typename T, size_t N>
    inline constexpr std::size_t get_word_size(const std::array<T, N>& a) {
        return get_word_size<T>( a.size() );
    }

    /**
     * Returns the number of words needed to store the given number of bits.
     * @param bitsize - the number of bits
     * @return the number of words needed to store the given number of bits
    */
    inline constexpr std::size_t get_word_size_from_bitsize(std::size_t bitsize) {
        return (bitsize + word_bit_size - 1) / word_bit_size;
    }

    inline constexpr byte_t from_hex( char c ) {
        if( c >= '0' && c <= '9' )
            return byte_t(c - '0');
        if( c >= 'a' && c <= 'f' )
            return byte_t(c - 'a' + 10);
        if( c >= 'A' && c <= 'F' )
            return byte_t(c - 'A' + 10);
        check( false, eosio::rope( "Invalid hex character '" + ( c ? eosio::rope(std::string_view(&c, 1)) : "<null>" ) + "'" ).c_str() );
        return 0;
    }

    [[maybe_unused]] static constexpr std::size_t from_hex( const char* hex_str, size_t hex_str_len, byte_t* out_data, size_t out_data_len ) {
        if( hex_str_len == 0 ) {
            return 0;
        }

        check( hex_str != nullptr, "Invalid hex string" );
        if ( out_data == nullptr || out_data_len == 0) {
            return ( hex_str_len + 1 ) / 2; // return required out data size
        }

        check( out_data_len >= (( hex_str_len + 1) / 2 ), "Invalid out data size" );

        auto i                = hex_str;
        const auto i_end      = hex_str + hex_str_len;
        byte_t* out_pos       = out_data;
        const byte_t* out_end = out_pos + out_data_len;

        if ( ( hex_str_len % 2 ) != 0 ) {
            *out_data = from_hex( *i );
            i++;
            out_pos++;
        }

        // from eosio/fc
        while ( i != i_end && out_end != out_pos ) {
            *out_pos = byte_t( from_hex( *i ) << 4 );
            ++i;
            if( i != i_end )  {
                *out_pos |= from_hex( *i );
                ++i;
            }
            ++out_pos;
        }

        return std::distance( out_data, out_pos );
    }

    inline size_t from_hex( const eosio::string& hex_str, byte_t* out_data, size_t out_data_len ) {
        return from_hex( hex_str.data(), hex_str.size(), out_data, out_data_len );
    }

    inline constexpr size_t from_hex( const std::string_view hex_str, byte_t* out_data, size_t out_data_len ) {
        return from_hex( hex_str.data(), hex_str.size(), out_data, out_data_len );
    }

    inline bytes from_hex( const char* hex_str, size_t hex_str_len ) {
        bytes data( from_hex( hex_str, hex_str_len, nullptr, 0 ));
        eosio::check( from_hex( hex_str, hex_str_len, data.data(), data.size() ) == data.size(), "Failed to parse hex string");
        return data;
    }

    inline bytes from_hex( const eosio::string& hex_str ) {
        return from_hex( hex_str.data(), hex_str.size() );
    }

    inline bytes from_hex( const std::string_view& hex_str ) {
        return from_hex( hex_str.data(), hex_str.size() );
    }

    template<std::size_t N>
    inline constexpr fixed_bytes<N> from_hex( const std::string_view& hex_str ) {
        fixed_bytes<N> data{};
        if ( hex_str.size() == 0 ) {
            return data;
        }

        std::size_t dsize = (hex_str.size() + 1) / 2;
        check( N >= dsize, "Invalid out data size" );
        check( from_hex( hex_str, data.data(), data.size() ) == dsize, "Failed to parse hex string");
        return data;
    }

    template<std::size_t N, std::size_t dsize = N / 2>
    constexpr fixed_bytes<dsize> from_hex(const char (&hex_str)[N] ) {
        return from_hex<dsize>( std::string_view{ hex_str, N - 1 } );
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

    inline constexpr void memxor(std::span<byte_t> dst, const bytes_view src, size_t num)
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