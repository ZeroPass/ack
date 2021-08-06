// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#include <helloeosiock.hpp>
#include <bt.hpp>
#include <eosio/crypto.hpp>

[[eosio::action("rsasha1"), eosio::read_only]]
void helloeosiock::check_rsa_sha1(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha1( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha1_signature( rsa_pubkey, md, sig,
        "verification of RSA PKCS v1.5 SHA-1 signature failed"
    );
}

[[eosio::action("rsasha2")]]
void helloeosiock::check_rsa_sha256(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha256_signature( rsa_pubkey, md, sig,
        "verification of RSA PKCS v1.5 SHA-256 signature failed"
    );
}

[[eosio::action("rsasha512"), eosio::read_only]]
void helloeosiock::check_rsa_sha512(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha512_signature( rsa_pubkey, md, sig,
        "verification of RSA PKCS v1.5 SHA-512 signature failed"
    );
}

[[eosio::action("btrsa1ksha1"), eosio::read_only]]
void helloeosiock::bt_rsa_1024_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha1::mod, rsa_1024_sha1::exp );
    assert_rsa_sha1_signature( pubkey, rsa_1024_sha1::md, rsa_1024_sha1::sig,
        "verification of RSA 1024 PKCS v1.5 SHA-1 signature failed"
    );
}

[[eosio::action("btrsa2ksha1"), eosio::read_only]]
void helloeosiock::bt_rsa_2048_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha1::mod, rsa_2048_sha1::exp );
    assert_rsa_sha1_signature( pubkey, rsa_2048_sha1::md, rsa_2048_sha1::sig,
        "verification of RSA 2048 PKCS v1.5 SHA-1 signature failed"
    );
}

[[eosio::action("btrsa1ksha2"), eosio::read_only]]
void helloeosiock::bt_rsa_1024_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha256::mod, rsa_1024_sha256::exp );
    assert_rsa_sha256_signature( pubkey, rsa_1024_sha256::md, rsa_1024_sha256::sig,
        "verification of RSA 1024 PKCS v1.5 SHA-256 signature failed"
    );
}

[[eosio::action("btrsa2ksha2"), eosio::read_only]]
void helloeosiock::bt_rsa_2048_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha256::mod, rsa_2048_sha256::exp );
    assert_rsa_sha256_signature( pubkey, rsa_2048_sha256::md, rsa_2048_sha256::sig,
        "verification of RSA 2048 PKCS v1.5 SHA-256 signature failed"
    );
}

[[eosio::action("btrsa4ksha2"), eosio::read_only]]
void helloeosiock::bt_rsa_4096_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_4096_sha256::mod, rsa_4096_sha256::exp );
    assert_rsa_sha256_signature( pubkey, rsa_4096_sha256::md, rsa_4096_sha256::sig,
        "verification of RSA 4096 PKCS v1.5 SHA-256 signature failed"
    );
}

[[eosio::action("btrsa1ksha512"), eosio::read_only]]
void helloeosiock::bt_rsa_1024_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha512::mod, rsa_1024_sha512::exp );
    assert_rsa_sha512_signature( pubkey, rsa_1024_sha512::md, rsa_1024_sha512::sig,
        "verification of RSA 1024 PKCS v1.5 SHA-512 signature failed"
    );
}

[[eosio::action("btrsa2ksha512"), eosio::read_only]]
void helloeosiock::bt_rsa_2048_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha512::mod, rsa_2048_sha512::exp );
    assert_rsa_sha512_signature( pubkey, rsa_2048_sha512::md, rsa_2048_sha512::sig,
        "verification of RSA 2048 PKCS v1.5 SHA-512 signature failed"
    );
}
