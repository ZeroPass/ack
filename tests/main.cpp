// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#include <eosio/tester.hpp>

#include "keccak_test.hpp"
#include "public_key_test.hpp"
#include "rsa_test.hpp"
#include "sha1.hpp"
#include "sha2.hpp"

using namespace eosiock::test;

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
    silence_output(true);
    init_test_intrinsics();

    EOSIO_TEST( keccak_test )
    EOSIO_TEST( public_key_test )
    EOSIO_TEST( rsa_pkcs_1_5_test )
    return has_failed();
}