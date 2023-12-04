// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/ecdsa.hpp>
#include <ack/tests/utils.hpp>

#include <eosio/tester.hpp>

namespace ack::tests {

    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    inline void test_ecdsa_verification(bool sig_valid, const ec_point_fp<CurveT>& q, const eosio::fixed_bytes<HLen>& digest, const IntT& r, const IntT& s, [[maybe_unused]] const CurveT& curve)
    {
        const auto hb = digest.extract_as_byte_array();
        REQUIRE_EQUAL( ecdsa_verify( q, bytes_view( (const byte_t*)hb.data(), HLen ), r, s ), sig_valid )
        REQUIRE_EQUAL( ecdsa_verify( q, digest, r, s ), sig_valid )

        if (sig_valid) {
            // Test verification is invalid if data is changed
            auto dbad = digest;
            dbad.data()[0] ^= ( dbad.data()[0] << 0x10 ) >> 0x01;
            REQUIRE_EQUAL( ecdsa_verify( q, dbad, r, s ), false )

            const auto dbadb = dbad.extract_as_byte_array();
            REQUIRE_EQUAL( ecdsa_verify( q, bytes_view( (const byte_t*)dbadb.data(), HLen ), r, s ), false )

            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, bytes_view( (const byte_t*)dbadb.data(), HLen ), r, s,
                    "ECDSA signature verification failed"
                );
            })
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, dbad, r, s,
                    "ECDSA signature verification failed"
                );
            })
        }
        else {
            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, bytes_view( (const byte_t*)hb.data(), HLen ), r, s,
                    "ECDSA signature verification failed"
                );
            })

            REQUIRE_ASSERT( "ECDSA signature verification failed", [&]() {
                assert_ecdsa( q, digest, r, s,
                    "ECDSA signature verification failed"
                );
            })
        }
    }
}
