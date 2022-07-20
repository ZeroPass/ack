// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/serialize.hpp>
#include <eosiock/types.hpp>
#include <eosiock/span_ext.hpp>

namespace eosiock {
    struct rsa_public_key {
        bytes modulus;
        bytes exponent;
    };

    struct rsa_public_key_view {
        bytes_view modulus;
        bytes_view exponent;

        rsa_public_key_view() {}
        constexpr rsa_public_key_view( const bytes_view& mod, const bytes_view& exp ) :
            modulus(mod),
            exponent(exp)
        {}

        constexpr rsa_public_key_view( const rsa_public_key& rsa_pub_key ) :
            modulus(rsa_pub_key.modulus),
            exponent(rsa_pub_key.exponent)
        {}

        EOSLIB_SERIALIZE( rsa_public_key_view, (modulus)(exponent) )
    };

    constexpr inline bool operator == (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
        return lkey.exponent == rkey.exponent && lkey.modulus == rkey.modulus;
    }

    constexpr inline bool operator != (const rsa_public_key_view & lkey, const rsa_public_key_view& rkey) {
        return !( lkey == rkey );
    }
}