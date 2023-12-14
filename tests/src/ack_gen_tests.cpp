// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#include <eosio/tester.hpp>

#include <ack/tests/bigint_test.hpp>
#include <ack/tests/keccak_test.hpp>
#include <ack/tests/public_key_test.hpp>
#include <ack/tests/sha_test.hpp>
#include <ack/tests/utils_test.hpp>

#include <ack/tests/utils.hpp>

using namespace ack::tests;

int main(int argc, char** argv)
{
    silence_output( true );
    init_test_intrinsics();

    EOSIO_TEST( utils_test      )
    EOSIO_TEST( bigint_test     )
    EOSIO_TEST( sha_test        )
    EOSIO_TEST( keccak_test     )
    EOSIO_TEST( public_key_test )

    return has_failed();
}