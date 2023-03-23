// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/tests/ecdsa_secp256k1_test.hpp>
#include <ack/tests/ecdsa_secp256r1_test.hpp>

#include <eosio/tester.hpp>

namespace ack::tests {
    EOSIO_TEST_BEGIN( ecdsa_test )
        EOSIO_TEST( ecdsa_secp256k1_test )
        EOSIO_TEST( ecdsa_secp256r1_test )
    EOSIO_TEST_END
}
