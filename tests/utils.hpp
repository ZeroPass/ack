#pragma once
#include <eosio/fixed_bytes.hpp>

namespace eosiock::test {
    template<size_t N>
    bool operator == (const eosio::fixed_bytes<N>& l, const bytes_view& r)
    {
        return l.extract_as_byte_array() == r;
    }
}