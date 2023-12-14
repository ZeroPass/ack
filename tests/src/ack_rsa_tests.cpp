// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#include <eosio/tester.hpp>

#include <ack/tests/mgf_test.hpp>
#include <ack/tests/rsa_test.hpp>

#include <ack/tests/utils.hpp>

using namespace ack::tests;

int main(int argc, char** argv)
{
    silence_output( true );
    init_test_intrinsics();

    EOSIO_TEST( mgf1_test )
    EOSIO_TEST( rsa_test  )

    return has_failed();
}