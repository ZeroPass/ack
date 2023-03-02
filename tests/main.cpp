// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#include <eosio/tester.hpp>

#include <ack/tests/bigint_test.hpp>
#include <ack/tests/ec_test.hpp>
#include <ack/tests/ecdsa_test.hpp>
#include <ack/tests/keccak_test.hpp>
#include <ack/tests/mgf_test.hpp>
#include <ack/tests/public_key_test.hpp>
#include <ack/tests/rsa_test.hpp>
#include <ack/tests/utils_test.hpp>
#include <ack/tests/sha1.hpp>
#include <ack/tests/sha2.hpp>

using namespace ack::tests;

void init_test_intrinsics() {
    using namespace eosio::native;

    intrinsics::set_intrinsic<intrinsics::sha1>(
    [](const char* data, uint32_t length, capi_checksum160* hash) {
        sha_1::calc( data, length, hash->hash );
    });

    intrinsics::set_intrinsic<intrinsics::sha256>(
    [](const char* data, uint32_t length, capi_checksum256* hash) {
        auto d =  sha256( (const uint8_t*)data, length );
        memcpy( hash->hash, d.data(), d.size() );
    });

    intrinsics::set_intrinsic<intrinsics::sha512>(
    [](const char* data, uint32_t length, capi_checksum512* hash) {
        auto d =  sha512( (const uint8_t*)data, length );
        memcpy( hash->hash, d.data(), d.size() );
    });
}

int main(int argc, char** argv)
{
    silence_output( true );
    init_test_intrinsics();

    EOSIO_TEST( utils_test      )
    EOSIO_TEST( bigint_test     )
    EOSIO_TEST( keccak_test     )
    EOSIO_TEST( public_key_test )
    EOSIO_TEST( mgf1_test       )
    EOSIO_TEST( rsa_test        )
    EOSIO_TEST( ec_test         )
    EOSIO_TEST( ecdsa_test      )

    return has_failed();
}