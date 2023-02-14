// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/fixed_bytes.hpp>
#include <ack/span_ext.hpp>

namespace ack::tests {
    using ack::operator ==;
    template<size_t N>
    bool operator == (const eosio::fixed_bytes<N>& l, const bytes_view& r)
    {
        return l.extract_as_byte_array() == r;
    }
}