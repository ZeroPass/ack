// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <cstdint>
#include <string_view>

#include <eosio/eosio.hpp>
#include <eosio/rope.hpp>
#include <eosio/string.hpp>

#include "types.hpp"


namespace eosiock {
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

    inline bytes operator""_hex(const char* hex_str, std::size_t len) {
        return from_hex( std::string_view{ hex_str, len });
    }
}