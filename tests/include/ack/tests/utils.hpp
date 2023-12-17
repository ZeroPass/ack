// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/fixed_bytes.hpp>
#include <eosio/tester.hpp>

#include <ack/span_ext.hpp>
#include <ack/tests/sha1.hpp>
#include <ack/tests/sha2.hpp>
#include <ack/types.hpp>

namespace ack::tests {
    static void init_test_intrinsics() {
        using namespace eosio::native;

        intrinsics::set_intrinsic<intrinsics::sha1>(
        [](const char* data, uint32_t length, capi_checksum160* hash) {
            sha_1::calc( data, length, hash->hash );
        });

        intrinsics::set_intrinsic<intrinsics::sha256>(
        [](const char* data, uint32_t length, capi_checksum256* hash) {
            auto d =  sha256( (const uint8_t*)data, length );
            memcpy( hash->hash, d.data(), d.size() );
        });

        intrinsics::set_intrinsic<intrinsics::sha512>(
        [](const char* data, uint32_t length, capi_checksum512* hash) {
            auto d =  sha512( (const uint8_t*)data, length );
            memcpy( hash->hash, d.data(), d.size() );
        });
    }

    using ack::operator ==;
    template<size_t N>
    bool operator == (const eosio::fixed_bytes<N>& l, const bytes_view r)
    {
        return l.extract_as_byte_array() == r;
    }

    template<size_t N>
    bool operator == (const fixed_bytes<N>& l, const bytes_view r)
    {
        return bytes_view( l ) == r;
    }

    bytes inline make_bytes(std::string_view str)
    {
        return bytes( str.begin(), str.end() );
    }
}