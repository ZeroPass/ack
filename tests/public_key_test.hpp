#pragma once
#include "eosiock/public_key.hpp"
#include "eosiock/utils.hpp"

#include <eosio/datastream.hpp>

namespace eosiock::test {
    EOSIO_TEST_BEGIN(public_key_test)
        const auto tv_mod = "008052A201E37AD87DD9A14E917C40F5555788D5EF8AEE7454FCB6F686E4A391450691C6AD18A33A0DD23D105C5C20B8E7DEB00FE80FEAA6F1D8B53C46CF60DF17AE9191E297349D0866375A583540167AADFE1DAE1265DF275D9E5D040A7F78DD30BF78B187CDF180527F7915D745B1882210BDF2F8908DB1871970909DA84E55"_hex;
        const auto tv_exp = "010001"_hex;
        auto pubkey = rsa_public_key { tv_mod, tv_exp };

        REQUIRE_EQUAL( tv_mod, pubkey.modulus  )
        REQUIRE_EQUAL( tv_exp, pubkey.exponent )

        auto pub_key_view = rsa_public_key_view( pubkey );
        REQUIRE_EQUAL( tv_mod      , pub_key_view.modulus                           )
        REQUIRE_EQUAL( tv_exp      , pub_key_view.exponent                          )
        REQUIRE_EQUAL( pub_key_view, pubkey                                         )
        REQUIRE_EQUAL( pub_key_view, rsa_public_key_view( tv_mod, tv_exp )          )
        REQUIRE_EQUAL( false, (pub_key_view == rsa_public_key_view( tv_exp,tv_mod )))

        // Test serializing public_key
        eosio::datastream<size_t> sizer;
        sizer << pubkey;

        bytes raw_pubkey(sizer.tellp());
        eosio::datastream<bytes::value_type*> ser(raw_pubkey.data(), raw_pubkey.size());
        ser << pubkey;

        rsa_public_key pubkey2;
        ser.seekp(0);
        ser >> pubkey2;
        REQUIRE_EQUAL( pubkey2, pubkey )

        // Test serializing public_key_view
        sizer.seekp(0);
        sizer << pub_key_view;
        bytes raw_pubkey_view( sizer.tellp() );
        REQUIRE_EQUAL( raw_pubkey_view.size(), raw_pubkey.size() );

        ser = eosio::datastream<bytes::value_type*>( raw_pubkey_view.data(), raw_pubkey_view.size() );
        ser << pub_key_view;
        REQUIRE_EQUAL( raw_pubkey_view, raw_pubkey );

        rsa_public_key_view pub_key_view2;
        ser.seekp(0);
        ser >> pub_key_view2;
        REQUIRE_EQUAL( pub_key_view, pub_key_view2 );
    EOSIO_TEST_END
}