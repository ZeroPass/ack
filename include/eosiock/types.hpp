// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "span.hpp"

namespace eosiock {
    using byte_t      = uint8_t;
    using bytes       = std::vector<byte_t>;
    using bytes_view  = span<const byte_t>;

    // helper type for the std::visit
    template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
    // explicit deduction guide (not needed as of C++20)
    template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

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
            data = bytes_view{ (const byte_t*)ds.pos(), s };
        }
        ds.skip( s );
        return ds;
    }
}