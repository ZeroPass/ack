// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <optional>
#include <eosio/serialize.hpp>
#include <eosio/varint.hpp>

#include <ack/types.hpp>
#include <ack/span_ext.hpp>

namespace ack {
    struct rsa_public_key {
        bytes modulus;
        bytes exponent;
    };

    struct rsa_pss_public_key : rsa_public_key {
        std::optional<eosio::unsigned_int> pss_salt_len;

        rsa_pss_public_key() = default;
        rsa_pss_public_key( const rsa_pss_public_key& ) = default;
        rsa_pss_public_key( rsa_pss_public_key&& ) = default;
        rsa_pss_public_key& operator=( const rsa_pss_public_key& ) = default;
        rsa_pss_public_key& operator=( rsa_pss_public_key&& ) = default;

        rsa_pss_public_key( bytes mod, bytes exp ) :
            rsa_public_key{ std::move(mod), std::move(exp) }
        {}

        rsa_pss_public_key( bytes mod, bytes exp, std::optional<eosio::unsigned_int> salt_len ) :
            rsa_public_key{ (std::move(mod)), std::move(exp) },
            pss_salt_len( std::move(salt_len) )
        {}

        rsa_pss_public_key( bytes mod, bytes exp, std::optional<uint32_t> salt_len ) :
            rsa_public_key{ (std::move(mod)), std::move(exp) },
            pss_salt_len( salt_len.has_value()
                ? std::optional<eosio::unsigned_int>{ salt_len.value() }
                : std::nullopt
            )
        {}

        rsa_pss_public_key(  bytes mod, bytes exp, uint32_t salt_len ) :
            rsa_public_key{ (std::move(mod)), std::move(exp) },
            pss_salt_len( salt_len )
        {}

        explicit rsa_pss_public_key(rsa_public_key pub_key) :
            rsa_public_key( std::move(pub_key) )
        {}

        EOSLIB_SERIALIZE( rsa_pss_public_key, (modulus)(exponent)(pss_salt_len) )
    };

    struct rsa_public_key_view {
        bytes_view modulus;
        bytes_view exponent;

        constexpr rsa_public_key_view() {}
        constexpr rsa_public_key_view( const bytes_view& mod, const bytes_view& exp ) :
            modulus( mod ),
            exponent( exp )
        {}

        constexpr rsa_public_key_view( const rsa_public_key& pub_key ) :
            modulus( pub_key.modulus ),
            exponent( pub_key.exponent )
        {}

        EOSLIB_SERIALIZE( rsa_public_key_view, (modulus)(exponent) )
    };

    struct rsa_pss_public_key_view : rsa_public_key_view {
        std::optional<eosio::unsigned_int> pss_salt_len;

        constexpr rsa_pss_public_key_view() {}
        constexpr rsa_pss_public_key_view( const bytes_view& mod, const bytes_view& exp ) :
            rsa_public_key_view{ mod, exp }
        {}

        constexpr rsa_pss_public_key_view( const bytes_view& mod, const bytes_view& exp, std::optional<eosio::unsigned_int> salt_len ) :
            rsa_public_key_view{ mod, exp },
            pss_salt_len( std::move(salt_len) )
        {}

        constexpr rsa_pss_public_key_view( const bytes_view& mod, const bytes_view& exp, std::optional<uint32_t> salt_len ) :
            rsa_public_key_view{ mod, exp },
            pss_salt_len( salt_len.has_value()
                ? std::optional<eosio::unsigned_int>{ salt_len.value() }
                : std::nullopt
            )
        {}

        constexpr rsa_pss_public_key_view( const bytes_view& mod, const bytes_view& exp, uint32_t salt_len ) :
            rsa_public_key_view{ mod, exp },
            pss_salt_len( salt_len )
        {}

        constexpr rsa_pss_public_key_view( const rsa_pss_public_key& pub_key ) :
            rsa_public_key_view{ pub_key.modulus, pub_key.exponent },
            pss_salt_len( pub_key.pss_salt_len )
        {}

        explicit constexpr rsa_pss_public_key_view( const rsa_public_key& pub_key ) :
            rsa_public_key_view{ pub_key.modulus, pub_key.exponent }
        {}

        explicit constexpr rsa_pss_public_key_view( const rsa_public_key_view pub_key_view ) :
            rsa_public_key_view{ pub_key_view.modulus, pub_key_view.exponent }
        {}

        EOSLIB_SERIALIZE( rsa_pss_public_key_view, (modulus)(exponent)(pss_salt_len) )
    };

    constexpr inline bool operator == ( const rsa_public_key_view & lkey, const rsa_public_key_view& rkey ) {
        return lkey.exponent == rkey.exponent && lkey.modulus == rkey.modulus;
    }

    constexpr inline bool operator == ( const rsa_pss_public_key_view & lkey, const rsa_pss_public_key_view& rkey ) {
        return lkey.exponent == rkey.exponent && lkey.modulus == rkey.modulus && lkey.pss_salt_len == rkey.pss_salt_len;
    }

    constexpr inline bool operator != ( const rsa_public_key_view & lkey, const rsa_public_key_view& rkey ) {
        return !( lkey == rkey );
    }

    constexpr inline bool operator != ( const rsa_pss_public_key_view & lkey, const rsa_pss_public_key_view& rkey ) {
        return !( lkey == rkey );
    }
}