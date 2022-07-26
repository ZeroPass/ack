// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <eosio/crypto.hpp>
#include <eosio/tester.hpp>

#include <eosiock/mgf.hpp>
#include <eosiock/utils.hpp>
#include <eosiock/tests/utils.hpp>

namespace eosiock::tests {
    EOSIO_TEST_BEGIN( mgf1_test )
        // Test vector taken from bc-java
        // Note: the tv_mgf_mask vas modified to contain full SHA-256 hash
        auto tv_mgf_seed = "d6e168c5f256a2dcff7ef12facd390f393c7a88d"_hex;
        auto tv_mgf_mask = "0742ba966813af75536bb6149cc44fc256fd64064f0f352bafb940fda7b5e44bdf79665bc31dc5a62f70535e52c53015b9d37d41736de6808d10576cb636a9912ff3c1193439599e1b628774c50d9ccb78d82c42d1ea38aa0c449704071e92a05e4521ee47b8c36a4bcffe"_hex;
        auto mgf_mask    = bytes( tv_mgf_mask.size() );
        mgf1( eosio::sha256, tv_mgf_seed, mgf_mask );
        REQUIRE_EQUAL( mgf_mask, tv_mgf_mask );

        // Test vector taken from bc-java
        tv_mgf_seed = "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4"_hex;
        tv_mgf_mask = "5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04"_hex;
        mgf_mask    = bytes( tv_mgf_mask.size() );
        mgf1( eosio::sha1, tv_mgf_seed, mgf_mask );
        REQUIRE_EQUAL( mgf_mask, tv_mgf_mask );

        // Test vector taken from bc-java
        // Note: the tv_mgf_mask vas modified to contain full SHA-256 hash
        tv_mgf_seed = "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4"_hex;
        tv_mgf_mask = "09e2decf2a6e1666c2f6071ff4298305e2643fd5f2c0a97b55ad3334fa2bdf3410a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac179f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24"_hex;
        mgf_mask = bytes( tv_mgf_mask.size() );
        mgf1( eosio::sha256, tv_mgf_seed, mgf_mask );
        REQUIRE_EQUAL( mgf_mask, tv_mgf_mask );

        // Test vector taken fromftp://ftp.rsa.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2-vec.zip
        tv_mgf_seed = "df1a896f9d8bc816d97cd7a2c43bad546fbe8cfe"_hex;
        tv_mgf_mask = "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc89739a96643136e8b0f465e87a4535cd4c59b10028d"_hex;
        mgf_mask = bytes( tv_mgf_mask.size() );
        mgf1( eosio::sha1, tv_mgf_seed, mgf_mask );
        REQUIRE_EQUAL( mgf_mask, tv_mgf_mask );
    EOSIO_TEST_END
}