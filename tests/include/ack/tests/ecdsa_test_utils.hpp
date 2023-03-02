// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/ecdsa.hpp>
#include <ack/tests/utils.hpp>

#include <eosio/fixed_bytes.hpp>
#include <eosio/tester.hpp>

namespace ack::tests {

    template<typename BigNumT, std::size_t HLen, typename CurveTag>
    inline void test_ecdsa_verification(bool sig_valid, const ec_point_fp_t<BigNumT, CurveTag>& q, const eosio::fixed_bytes<HLen>& digest, const BigNumT& r, const BigNumT& s, const ec_curve_fp<BigNumT, CurveTag>& curve)
    {
        const auto hb = digest.extract_as_byte_array();
        REQUIRE_EQUAL( ecdsa_verify( q, bytes_view( (const byte_t*)hb.data(), HLen ), r, s, curve ), sig_valid )
        REQUIRE_EQUAL( ecdsa_verify( q, digest, r, s, curve ), sig_valid )

        if (sig_valid) {
            // Test verification is invalid if data is changed
            auto dbad = digest;
            dbad.data()[0] ^= ( dbad.data()[0] << 0x10 ) >> 0x01;
            auto dbadb = dbad.extract_as_byte_array();

            REQUIRE_EQUAL( ecdsa_verify( q, bytes_view( (const byte_t*)dbadb.data(), HLen ), r, s, curve ), false )
            REQUIRE_EQUAL( ecdsa_verify( q, dbad, r, s, curve ), false )
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, bytes_view( (const byte_t*)dbadb.data(), HLen ), r, s, curve,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, dbad, r, s, curve,
                    "ECDSA signature verification failed"
                );
            })
        }
        else {
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, bytes_view( (const byte_t*)hb.data(), HLen ), r, s, curve,
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, digest, r, s, curve,
                    "ECDSA signature verification failed"
                );
            })
        }
    }
}
