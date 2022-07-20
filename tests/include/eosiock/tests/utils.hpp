// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/fixed_bytes.hpp>
#include <eosiock/span_ext.hpp>

namespace eosiock::tests {
    using eosiock::operator ==;
    template<size_t N>
    bool operator == (const eosio::fixed_bytes<N>& l, const bytes_view& r)
    {
        return l.extract_as_byte_array() == r;
    }
}