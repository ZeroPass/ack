// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#include <eosio/tester.hpp>

#include <ack/tests/ec_test.hpp>
#include <ack/tests/ecdsa_test.hpp>
#include <ack/tests/fp_test.hpp>

#include <ack/tests/utils.hpp>

using namespace ack::tests;

int main(int argc, char** argv)
{
    silence_output( true );
    init_test_intrinsics();

    EOSIO_TEST( fp_test    )
    EOSIO_TEST( ec_test    )
    EOSIO_TEST( ecdsa_test )

    return has_failed();
}