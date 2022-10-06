// Copyright © 2022 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#include <helloack.hpp>
#include <bt.hpp>
#include <eosio/crypto.hpp>

[[eosio::action("rsasha1"), eosio::read_only]]
void helloack::check_rsa_sha1(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha1( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha1_assert( rsa_pubkey, md, sig,
        "RSA PKCS v1.5 SHA-1 signature verification failed"
    );
}

[[eosio::action("rsapsssha1"), eosio::read_only]]
void helloack::check_rsa_pss_sha1(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha1( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha1( rsa_pubkey, md, sig,
        "RSA PSS SHA-1 signature verification failed"
    );
}

[[eosio::action("rsasha2")]]
void helloack::check_rsa_sha256(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha256( rsa_pubkey, md, sig,
        "RSA PKCS v1.5 SHA-256 signature verification failed"
    );
}

[[eosio::action("rsapsssha2")]]
void helloack::check_rsa_pss_sha256(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha256( rsa_pubkey, md, sig,
        "RSA PSS SHA-256 signature verification failed"
    );
}

[[eosio::action("rsasha512"), eosio::read_only]]
void helloack::check_rsa_sha512(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha512( rsa_pubkey, md, sig,
        "RSA PKCS v1.5 SHA-512 signature verification failed"
    );
}

[[eosio::action("rsapsssha512"), eosio::read_only]]
void helloack::check_rsa_pss_sha512(rsa_public_key_view rsa_pubkey, bytes_view msg, bytes_view sig)
{
    auto md = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha512( rsa_pubkey, md, sig,
        "RSA PSS SHA-512 signature verification failed"
    );
}

[[eosio::action("btrsa1ksha1"), eosio::read_only]]
void helloack::bt_rsa_1024_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha1::mod, rsa_1024_sha1::exp );
    assert_rsa_sha1_assert( pubkey, rsa_1024_sha1::md, rsa_1024_sha1::sig,
        "RSA 1024 PKCS v1.5 SHA-1 signature verification failed"
    );
}

[[eosio::action("btrsa2ksha1"), eosio::read_only]]
void helloack::bt_rsa_2048_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha1::mod, rsa_2048_sha1::exp );
    assert_rsa_sha1_assert( pubkey, rsa_2048_sha1::md, rsa_2048_sha1::sig,
        "RSA 2048 PKCS v1.5 SHA-1 signature verification failed"
    );
}

[[eosio::action("btrsa1ksha2"), eosio::read_only]]
void helloack::bt_rsa_1024_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha256::mod, rsa_1024_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_1024_sha256::md, rsa_1024_sha256::sig,
        "RSA 1024 PKCS v1.5 SHA-256 signature verification failed"
    );
}

[[eosio::action("btrsa2ksha2"), eosio::read_only]]
void helloack::bt_rsa_2048_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha256::mod, rsa_2048_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_2048_sha256::md, rsa_2048_sha256::sig,
        "RSA 2048 PKCS v1.5 SHA-256 signature verification failed"
    );
}

[[eosio::action("btrsapss2sha2"), eosio::read_only]]
void helloack::bt_rsa_pss_2048_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_pss_mgf1_sha256_2048::mod, rsa_pss_mgf1_sha256_2048::exp, rsa_pss_mgf1_sha256_2048::salt_len );
    assert_rsa_pss_sha256( pubkey, rsa_pss_mgf1_sha256_2048::md, rsa_pss_mgf1_sha256_2048::sig,
        "RSA PSS 2048 SHA-256 signature verification failed"
    );
}

[[eosio::action("btrsa4ksha2"), eosio::read_only]]
void helloack::bt_rsa_4096_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_4096_sha256::mod, rsa_4096_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_4096_sha256::md, rsa_4096_sha256::sig,
        "RSA 4096 PKCS v1.5 SHA-256 signature verification failed"
    );
}

[[eosio::action("btrsapss4sha2"), eosio::read_only]]
void helloack::bt_rsa_pss_4096_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_pss_mgf1_sha256_4096::mod, rsa_pss_mgf1_sha256_4096::exp, rsa_pss_mgf1_sha256_4096::salt_len );
    assert_rsa_pss_sha256( pubkey, rsa_pss_mgf1_sha256_4096::md, rsa_pss_mgf1_sha256_4096::sig,
        "RSA PSS 4096 SHA-256 signature verification failed"
    );
}

[[eosio::action("btrsa1ksha512"), eosio::read_only]]
void helloack::bt_rsa_1024_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha512::mod, rsa_1024_sha512::exp );
    assert_rsa_sha512( pubkey, rsa_1024_sha512::md, rsa_1024_sha512::sig,
        "RSA 1024 PKCS v1.5 SHA-512 signature verification failed"
    );
}

[[eosio::action("btrsa2ksha512"), eosio::read_only]]
void helloack::bt_rsa_2048_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha512::mod, rsa_2048_sha512::exp );
    assert_rsa_sha512( pubkey, rsa_2048_sha512::md, rsa_2048_sha512::sig,
        "RSA 2048 PKCS v1.5 SHA-512 signature verification failed"
    );
}
