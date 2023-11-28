// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <eosio/datastream.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/varint.hpp>

namespace ack {
    using byte_t     = uint8_t;
    using word_t     = uint32_t;
    using bytes      = std::vector<byte_t>;
    using bytes_view = std::span<const byte_t>;

    template<std::size_t N>
    using fixed_bytes = std::array<byte_t, N>;

    template<std::size_t N>
    using hash_t  = eosio::fixed_bytes<N>;
    using hash160 = eosio::checksum160;
    using hash256 = eosio::checksum256;
    using hash384 = eosio::fixed_bytes<48>;
    using hash512 = eosio::checksum512;

    static constexpr size_t word_bit_size = sizeof(word_t) * 8;

    inline bytes make_bytes(const bytes_view& data) {
        return bytes{ data.begin(), data.end() };
    }

    // bytes_view serializer specialization
    template<typename DataStream>
    inline DataStream& operator<<(DataStream& ds, const bytes_view& data) {
        ds << eosio::unsigned_int( data.size() );
        ds.write( data.data(), data.size() );
        return ds;
    }

    template<typename DataStream>
    inline DataStream& operator>>(DataStream& ds, bytes_view& data) {
        eosio::unsigned_int s;
        ds >> s;
        if constexpr ( !std::is_same_v<eosio::datastream<size_t>, DataStream> ) {
            data = bytes_view{ (const byte_t*)ds.pos(), s.value };
        }
        ds.skip( s );
        return ds;
    }
}