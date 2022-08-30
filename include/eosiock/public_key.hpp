// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <optional>
#include <eosio/serialize.hpp>

#include <eosiock/types.hpp>
#include <eosiock/span_ext.hpp>

namespace eosiock {
    struct rsa_public_key {
        bytes modulus;
        bytes exponent;
        std::optional<uint8_t> pss_salt_len; // TODO: Max 256 for custom salt length was selected because cdt tester fw was broken for optional<unsigned_int> and unsigned_int was not compile constructible at the time.
    };

    struct rsa_public_key_view {
        bytes_view modulus;
        bytes_view exponent;
        std::optional<uint8_t> pss_salt_len; // TODO: Max 256 for custom salt length was selected because cdt tester fw was broken for optional<unsigned_int> and unsigned_int was not compile constructible at the time.

        constexpr rsa_public_key_view() {}
        constexpr rsa_public_key_view( const bytes_view& mod, const bytes_view& exp ) :
            modulus(mod),
            exponent(exp)
        {}

        constexpr rsa_public_key_view( const bytes_view& mod, const bytes_view& exp, std::optional<uint8_t> salt_len ) :
            modulus(mod),
            exponent(exp),
            pss_salt_len(std::move(salt_len))
        {}

        constexpr rsa_public_key_view( const rsa_public_key& rsa_pub_key ) :
            modulus(rsa_pub_key.modulus),
            exponent(rsa_pub_key.exponent),
            pss_salt_len(rsa_pub_key.pss_salt_len)
        {}

        EOSLIB_SERIALIZE( rsa_public_key_view, (modulus)(exponent)(pss_salt_len) )
    };

    constexpr inline bool operator == (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
        return lkey.exponent == rkey.exponent && lkey.modulus == rkey.modulus && lkey.pss_salt_len == rkey.pss_salt_len;
    }

    constexpr inline bool operator != (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
        return !( lkey == rkey );
    }
}