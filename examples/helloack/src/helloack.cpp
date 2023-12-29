// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#include <ack/bigint.hpp>
#include <ack/ec.hpp>
#include <ack/ec_curve.hpp>
#include <ack/ecdsa.hpp>
#include <ack/sha.hpp>

#include <helloack.hpp>
#include <bt.hpp>
#include <eosio/crypto.hpp>

using namespace ack::ec_curve;

void helloack::check_ecdsa_brainpoolP256_sha256(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(brainpoolP256r1)::int_type;
    const auto pub_point = brainpoolP256r1.make_point( qx, qy );
    const auto h = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA brainpoolP256r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_brainpoolP320_sha384(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(brainpoolP320r1)::int_type;
    const auto pub_point = brainpoolP320r1.make_point( qx, qy );
    const auto h = sha384( msg );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA brainpoolP320r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_brainpoolP384_sha384(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(brainpoolP384r1)::int_type;
    const auto pub_point = brainpoolP384r1.make_point( qx, qy );
    const auto h = sha384( msg );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA brainpoolP384r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_brainpoolP512_sha512(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(brainpoolP512r1)::int_type;
    const auto pub_point = brainpoolP512r1.make_point( qx, qy );
    const auto h = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA brainpoolP512r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_secp256k1_sha256(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(secp256k1)::int_type;
    const auto pub_point = secp256k1.make_point( qx, qy );
    const auto h = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA secp256k1 signature verification failed!"
    );
}

void helloack::check_ecdsa_secp256r1_sha256(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(secp256r1)::int_type;
    const auto pub_point = secp256r1.make_point( qx, qy );
    const auto h = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA secp256r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_secp384r1_sha384(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(secp384r1)::int_type;
    const auto pub_point = secp384r1.make_point( qx, qy );
    const auto h = sha384( msg );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA secp384r1 signature verification failed!"
    );
}

void helloack::check_ecdsa_secp521r1_sha512(bytes_view qx, bytes_view qy, bytes_view msg, bytes_view r, bytes_view s)
{
    using int_type = typename decltype(secp521r1)::int_type;
    const auto pub_point = secp521r1.make_point( qx, qy );
    const auto h = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_ecdsa( pub_point, h, int_type( r ), int_type( s ),
      "ECDSA secp521r1 signature verification failed!"
    );
}

void helloack::check_rsa_sha1(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha1( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha1( pubkey, md, sig,
        "RSA PKCS v1.5 SHA-1 signature verification failed"
    );
}

void helloack::check_rsa_pss_sha1(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha1( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha1( pubkey, md, sig,
        "RSA PSS SHA-1 signature verification failed"
    );
}

void helloack::check_rsa_sha256(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha256( pubkey, md, sig,
        "RSA PKCS v1.5 SHA-256 signature verification failed"
    );
}

void helloack::check_rsa_pss_sha256(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha256( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha256( pubkey, md, sig,
        "RSA PSS SHA-256 signature verification failed"
    );
}

void helloack::check_rsa_sha384(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = sha384( msg );
    assert_rsa_sha384( pubkey, md, sig,
        "RSA PKCS v1.5 SHA-384 signature verification failed"
    );
}

void helloack::check_rsa_pss_sha384(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = sha384( msg );
    assert_rsa_pss_sha384( pubkey, md, sig,
        "RSA PSS SHA-384 signature verification failed"
    );
}

void helloack::check_rsa_sha512(rsa_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_sha512( pubkey, md, sig,
        "RSA PKCS v1.5 SHA-512 signature verification failed"
    );
}

void helloack::check_rsa_pss_sha512(rsa_pss_public_key_view pubkey, bytes_view msg, bytes_view sig)
{
    const auto md = eosio::sha512( reinterpret_cast<const char*>( msg.data() ), msg.size() );
    assert_rsa_pss_sha512( pubkey, md, sig,
        "RSA PSS SHA-512 signature verification failed"
    );
}

void helloack::bt_rsa_1024_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha1::mod, rsa_1024_sha1::exp );
    assert_rsa_sha1( pubkey, rsa_1024_sha1::md, rsa_1024_sha1::sig,
        "RSA 1024 PKCS v1.5 SHA-1 signature verification failed"
    );
}

void helloack::bt_rsa_2048_sha1()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha1::mod, rsa_2048_sha1::exp );
    assert_rsa_sha1( pubkey, rsa_2048_sha1::md, rsa_2048_sha1::sig,
        "RSA 2048 PKCS v1.5 SHA-1 signature verification failed"
    );
}

void helloack::bt_rsa_1024_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha256::mod, rsa_1024_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_1024_sha256::md, rsa_1024_sha256::sig,
        "RSA 1024 PKCS v1.5 SHA-256 signature verification failed"
    );
}

void helloack::bt_rsa_2048_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha256::mod, rsa_2048_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_2048_sha256::md, rsa_2048_sha256::sig,
        "RSA 2048 PKCS v1.5 SHA-256 signature verification failed"
    );
}

void helloack::bt_rsa_pss_2048_sha256()
{
    constexpr auto pubkey = rsa_pss_public_key_view( rsa_pss_mgf1_sha256_2048::mod, rsa_pss_mgf1_sha256_2048::exp, rsa_pss_mgf1_sha256_2048::salt_len );
    assert_rsa_pss_sha256( pubkey, rsa_pss_mgf1_sha256_2048::md, rsa_pss_mgf1_sha256_2048::sig,
        "RSA PSS 2048 SHA-256 signature verification failed"
    );
}

void helloack::bt_rsa_4096_sha256()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_4096_sha256::mod, rsa_4096_sha256::exp );
    assert_rsa_sha256( pubkey, rsa_4096_sha256::md, rsa_4096_sha256::sig,
        "RSA 4096 PKCS v1.5 SHA-256 signature verification failed"
    );
}

void helloack::bt_rsa_pss_4096_sha256()
{
    constexpr auto pubkey = rsa_pss_public_key_view( rsa_pss_mgf1_sha256_4096::mod, rsa_pss_mgf1_sha256_4096::exp, rsa_pss_mgf1_sha256_4096::salt_len );
    assert_rsa_pss_sha256( pubkey, rsa_pss_mgf1_sha256_4096::md, rsa_pss_mgf1_sha256_4096::sig,
        "RSA PSS 4096 SHA-256 signature verification failed"
    );
}

void helloack::bt_rsa_1024_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_1024_sha512::mod, rsa_1024_sha512::exp );
    assert_rsa_sha512( pubkey, rsa_1024_sha512::md, rsa_1024_sha512::sig,
        "RSA 1024 PKCS v1.5 SHA-512 signature verification failed"
    );
}

void helloack::bt_rsa_2048_sha512()
{
    constexpr auto pubkey = rsa_public_key_view( rsa_2048_sha512::mod, rsa_2048_sha512::exp );
    assert_rsa_sha512( pubkey, rsa_2048_sha512::md, rsa_2048_sha512::sig,
        "RSA 2048 PKCS v1.5 SHA-512 signature verification failed"
    );
}

void helloack::bt_ecdsa_brainpoolP256r1_sha256()
{
   using tv = brainpoolP256r1_sha256_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA brainpoolP256r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_brainpoolP256r1_sha256()
{
    using tv = brainpoolP256r1_sha256_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA brainpoolP256r1 key recovery failed!" );
}

void helloack::bt_ecdsa_brainpoolP320r1_sha384()
{
   using tv = brainpoolP320r1_sha384_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA brainpoolP320r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_brainpoolP320r1_sha384()
{
    using tv = brainpoolP320r1_sha384_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA brainpoolP320r1 key recovery failed!" );
}

void helloack::bt_ecdsa_brainpoolP384r1_sha384()
{
   using tv = brainpoolP384r1_sha384_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA brainpoolP384r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_brainpoolP384r1_sha384()
{
    using tv = brainpoolP384r1_sha384_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA brainpoolP384r1 key recovery failed!" );
}

void helloack::bt_ecdsa_brainpoolP512r1_sha512()
{
   using tv = brainpoolP512r1_sha512_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA brainpool512r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_brainpoolP512r1_sha512()
{
    using tv = brainpoolP512r1_sha512_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA brainpoolP512r1 key recovery failed!" );
}

void helloack::bt_ecdsa_secp256k1_sha256()
{
   using tv = secp256k1_sha256_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA secp256k1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_secp256k1_sha256()
{
    using tv = secp256k1_sha256_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA secp256k1 key recovery failed!" );
}

void helloack::bt_ecdsa_secp256r1_sha256()
{
   using tv = secp256r1_sha256_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA secp256r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_secp256r1_sha256()
{
    using tv = secp256r1_sha256_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA secp256r1 key recovery failed!" );
}

void helloack::bt_ecdsa_secp384r1_sha384()
{
   using tv = secp384r1_sha384_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA secp384r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_secp384r1_sha384()
{
    using tv = secp384r1_sha384_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA secp384r1 key recovery failed!" );
}

void helloack::bt_ecdsa_secp521r1_sha512()
{
   using tv = secp521r1_sha512_tv;
   assert_ecdsa( tv::pub_point, tv::h, tv::r, tv::s,
      "ECDSA secp521r1 signature verification failed!"
   );
}

void helloack::bt_ecdsa_recover_secp521r1_sha512()
{
    using tv = secp521r1_sha512_tv;
    const auto rkey = ecdsa_recover( tv::curve, tv::h, tv::r, tv::s, tv::recid );
    check( rkey == tv::pub_point, "ECDSA secp521r1 key recovery failed!" );
}
