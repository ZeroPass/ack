#include <ck/types.hpp>
#include "keccak_test.hpp"
#include "public_key_test.hpp"

using namespace ck::test;

int main(int argc, char** argv)
{
    silence_output(false);

    EOSIO_TEST( keccak_test )
    EOSIO_TEST( public_key_test )
    return has_failed();
}