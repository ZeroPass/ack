#include <eosio/tester.hpp>

#include "keccak_test.hpp"
#include "public_key_test.hpp"
#include "sha2.hpp"

using namespace ck::test;

void init_test_intrinsics() {
    using namespace eosio::native;
    intrinsics::set_intrinsic<intrinsics::sha256>(
    [](const char* data, uint32_t length, capi_checksum256* hash) {
        auto d =  sha256( (const uint8_t*)data, length );
        memcpy( hash->hash, d.data(), d.size() );
    });
}

int main(int argc, char** argv)
{
    silence_output(false);
    init_test_intrinsics();

    EOSIO_TEST( keccak_test )
    EOSIO_TEST( public_key_test )
    return has_failed();
}