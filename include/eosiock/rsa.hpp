// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <array>
#include <eosio/fixed_bytes.hpp>

#include "public_key.hpp"
#include "types.hpp"

namespace eosiock {
    namespace detail {
        extern "C" {
            #include "c/powm.h"
        }

        // PKCS1 v1.5 - T constants of EMSA struct
        constexpr auto sha1_digest_info_prefix = std::array<byte_t, 15> {
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
        };
        constexpr size_t pkcs1_v1_5_t_sha1_size = sha1_digest_info_prefix.size() + /*sha1_digest_len=*/20;
        static_assert( pkcs1_v1_5_t_sha1_size == 35 );

        constexpr auto sha256_digest_info_prefix = std::array<byte_t, 19> {
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        };
        constexpr size_t pkcs1_v1_5_t_sha256_size = sha256_digest_info_prefix.size() + sizeof(eosio::checksum256);
        static_assert( pkcs1_v1_5_t_sha256_size == 51 );

        constexpr auto sha512_digest_info_prefix = std::array<byte_t, 19> {
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
        };
        constexpr size_t pkcs1_v1_5_t_sha512_size = sha512_digest_info_prefix.size() + sizeof(eosio::checksum512);
        static_assert( pkcs1_v1_5_t_sha512_size == 83 );
    }

    /**
    * Returns result of modular exponentiation.
    * @param base         - base byte array
    * @param base_len     - size in bytes of the array pointed by base param
    * @param exponent     - exponent byte array
    * @param exponent_len - size in bytes of the array pointed by exponent param
    * @param modulus      - modulus byte array
    * @param modulus_len  - size in bytes of the array pointed by modulus param
    * @param out          - pointer to the buffer to which the result will be written
    * @param out_len      - the size of out buffer
    *
    * @return zero on error, otherwise base_len.
    */
    static int powm(const char* base, uint32_t base_len,
                    const char* exponent,  uint32_t exponent_len,
                    const char* modulus,   uint32_t modulus_len,
                    char* out,  uint32_t out_len)
    {
        eosio::check( base_len && modulus_len && exponent_len && modulus_len,
            "powm error, at least 1 param has an invalid length"
        );

        eosio::check( base_len == modulus_len,
            "powm error, base_len and modulus_len are not the same size"
        );

        if ( out_len == 0 ) return base_len;
        eosio::check( out_len >= base_len, "powm error, out_len too small" );

        detail::key_prop* prop;
        eosio::check(
            rsa_gen_key_prop( (const uint8_t*)modulus, modulus_len, (const uint8_t*)exponent, exponent_len, &prop ) == 0,
            "powm error, rsa_gen_key_prop failed"
        );

        auto res = rsa_mod_exp_sw( (const uint8_t*)base, base_len, prop, (uint8_t *)out );
        rsa_free_key_prop( prop );
        return res == 0 ? modulus_len : 0;
    }

    /**
    * Returns result of modular exponentiation.
    * @param base     - base
    * @param exponent - exponent
    * @param modulus  - modulus
    *
    * @return result, the size of vector is the same as modulus
    */
    [[nodiscard]] inline bytes powm( const bytes_view& base, const bytes_view& exponent, const bytes_view& modulus ) {
        bytes result( modulus.size() );
        [[maybe_unused]]auto res_size = powm(
            (const char*)base.data(), base.size(),
            (const char*)exponent.data(), exponent.size(),
            (const char*)modulus.data(), modulus.size(),
            (char*)result.data(), result.size()
        );
        //TODO: res_size zero meaning error, verify there is no error
        return result;
    }

    [[nodiscard]] inline bytes rsavp1(const rsa_public_key_view& rsa_pub_key, const bytes_view& signature) {
        // Note: Missing check for signature representative, an integer between 0 and n - 1
        return powm( signature, rsa_pub_key.exponent, rsa_pub_key.modulus );
    }

    template<size_t t_len, typename Lambda>
    [[nodiscard]] bool rsassa_pkcs1_v1_5_verify(const rsa_public_key_view& rsa_pub_key, const bytes_view& signature, Lambda&& gen_t)
    {
        if ( signature.size() != rsa_pub_key.modulus.size() ) {
            eosio::print( "[ERROR] rsassa_pkcs1_v1_5_verify: invalid signature" );
            return false;
        }

        const auto em = rsavp1( rsa_pub_key, signature );
        if ( em.size() < t_len + 11 ) {
            eosio::print( "[ERROR] rsassa_pkcs1_v1_5_verify: intended encoded message length too short" );
            return false;
        }

        // Construct EM' = 0x00 || 0x01 || PS || 0x00 || T
        // https://tools.ietf.org/html/rfc3447#section-9.2
        byte_t em_[em.size()];
        em_[0] = 0x00;
        em_[1] = 0x01;

        const auto ps_len = em.size() - t_len - 3;
        memset( &em_[2], 0xff, ps_len );

        em_[2 + ps_len] = 0x00;
        gen_t( span<byte_t>{ &em_[ 3 + ps_len ], t_len });

        return memcmp( em_, em.data(), em.size() ) == 0;
    }

    // T generator - https://tools.ietf.org/html/rfc3447#section-9.2
    // @param put_hash - function should calculate hash and put the calculated digest to the buffer pointed to by it's argument
    template<std::size_t S, typename std::size_t HS>
    inline void rsa_1_5_t_generator(span<byte_t>& t, const std::array<byte_t, S> digest_info_prefix, const eosio::fixed_bytes<HS>& digest)
    {
        memcpy( t.data(), digest_info_prefix.data(), digest_info_prefix.size() );
        auto hash = digest.extract_as_byte_array();
        memcpy( &t[digest_info_prefix.size()], hash.data(), hash.size() );
    }

    /**
    * Verifies a RSA PKCS1 v1.5 signed sha-1 digest
    * @note function uses intrinsic __powm to decrypt signature.
    *       The decrypted signature is verified in contract following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param rsa_pub_key - RSA public
    * @param digest      - SHA-1 digest to verify
    * @param signature   - signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] bool verify_rsa_sha1(const rsa_public_key_view& rsa_pub_key, const eosio::checksum160& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha1_size>( rsa_pub_key, signature, [&](span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha1_digest_info_prefix, digest );
        });
    }

    inline void assert_rsa_sha1_signature(const rsa_public_key_view& rsa_pub_key, const eosio::checksum160& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha1( rsa_pub_key, digest, signature ), error );
    }

    /**
    * Verifies a RSA PKCS1 v1.5 signed SHA-256 digest
    * @note function uses intrinsic __powm to decrypt signature.
    *       The decrypted signature is verified in contract following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param rsa_pub_key - RSA public
    * @param digest      - SHA-256 digest to verify
    * @param signature   - signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] bool verify_rsa_sha256(const rsa_public_key_view& rsa_pub_key, const eosio::checksum256& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha256_size>( rsa_pub_key, signature, [&](span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha256_digest_info_prefix, digest );
        });
    }

    inline void assert_rsa_sha256_signature(const rsa_public_key_view& rsa_pub_key, const eosio::checksum256& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha256( rsa_pub_key, digest, signature ), error );
    }

    /**
    * Verifies a RSA PKCS1 v1.5 signed SHA-512 digest
    * @note function uses intrinsic __powm to decrypt signature.
    *       The decrypted signature is verified in contract following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param rsa_pub_key - RSA public
    * @param digest      - SHA-512 digest to verify
    * @param signature   - signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] bool verify_rsa_sha512(const rsa_public_key_view& rsa_pub_key, const eosio::checksum512& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha512_size>( rsa_pub_key, signature, [&](span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha512_digest_info_prefix, digest );
        });
    }

    inline void assert_rsa_sha512_signature(const rsa_public_key_view& rsa_pub_key, const eosio::checksum512& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha512( rsa_pub_key, digest, signature ), error );
    }
}