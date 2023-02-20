// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <span>
#include <type_traits>

#include <eosio/crypto.hpp>
#include <eosio/fixed_bytes.hpp>

#include <ack/mgf.hpp>
#include <ack/public_key.hpp>
#include <ack/utils.hpp>

#if ACK_NO_INTRINSICS == 0
#  include <eosio/crypto_ext.hpp>
#endif

namespace ack {
    namespace detail {
    #if defined(ACK_NO_INTRINSICS) && ACK_NO_INTRINSICS == 1
        extern "C" {
            #include "c/powm.h"
        }
    #endif

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

    #if ACK_NO_INTRINSICS == 0
        auto res = eosio::mod_exp( base, base_len, exponent, exponent_len, modulus, modulus_len, out, out_len );
    #else
        detail::key_prop* prop;
        eosio::check(
            rsa_gen_key_prop( (const uint8_t*)modulus, modulus_len, (const uint8_t*)exponent, exponent_len, &prop ) == 0,
            "powm error, rsa_gen_key_prop failed"
        );

        auto res = rsa_mod_exp_sw( (const uint8_t*)base, base_len, prop, (uint8_t *)out );
        rsa_free_key_prop( prop );
    #endif
        return res == 0 ? base_len : 0;
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
        if ( exponent.size() > sizeof(uint64_t) ) {
            for (size_t i = 0; i < exponent.size()  - sizeof(uint64_t); i++) {
                eosio::check( exponent[i] == 0x00, "exponent too big" );
            }
        }

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

    [[nodiscard]] inline bytes rsavp1(const rsa_public_key_view pub_key, const bytes_view& signature) {
        // Note: Missing check for signature representative (integer between 0 and n - 1)
        return powm( signature, pub_key.exponent, pub_key.modulus );
    }

    template<size_t t_len, typename Lambda>
    [[nodiscard]] bool rsassa_pkcs1_v1_5_verify(const rsa_public_key_view& pub_key, const bytes_view& signature, Lambda&& gen_t)
    {
        if ( signature.size() != pub_key.modulus.size() ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pkcs1_v1_5_verify: invalid signature" );
            return false;
        }

        const auto em = rsavp1( pub_key, signature );
        if ( em.size() < t_len + 11 ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pkcs1_v1_5_verify: inconsistent" );
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
        gen_t( std::span<byte_t>{ &em_[ 3 + ps_len ], t_len } );

        return memcmp( em_, em.data(), em.size() ) == 0;
    }

    // T generator - https://tools.ietf.org/html/rfc3447#section-9.2
    // @param put_hash - function should calculate hash and put the calculated digest to the buffer pointed to by it's argument
    template<std::size_t S, typename std::size_t HS>
    inline void rsa_1_5_t_generator(std::span<byte_t>& t, const std::array<byte_t, S> digest_info_prefix, const eosio::fixed_bytes<HS>& digest)
    {
        memcpy( t.data(), digest_info_prefix.data(), digest_info_prefix.size() );
        auto hash = digest.extract_as_byte_array();
        memcpy( &t[digest_info_prefix.size()], hash.data(), hash.size() );
    }

    /**
    * RSASSA-PSS signature verification function.
    * Implementation based on RFC 8017 sec. 8.1.2: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    *
    * @note The DB mask is generated by using MGF1 function.
    *       The same hash function - `HashT` is used to generate digest H' and MGF1 mask.
    *
    * @param pub_key   - RSA-PSS public key
    *                       Note: If salt length is not provided through key the hash length is used.
    * @param digest    - Digest to verify
    * @param signature - RSASSA-PSS signature
    * @param hash      - Hash function which was used to produce `digest`.
    *
    * @return true if signature is valid, else false.
    */
    template<size_t HLen, typename HashT>
    [[nodiscard]] static bool rsassa_pss_mgf1_verify(const rsa_pss_public_key_view& pub_key, const eosio::fixed_bytes<HLen>& digest, const bytes_view& signature, HashT&& hash)
    {
        using HDT = typename std::invoke_result_t<HashT, const char*, size_t>;
        static_assert( std::is_same_v<eosio::fixed_bytes<HLen>, HDT> );

        // 1. Length check
        if ( signature.size() != pub_key.modulus.size() ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: invalid signature" );
            return false;
        }

        // 2. RSA verification
        auto em = rsavp1( pub_key, signature );

        // 3. EMSA-PSS-VERIFY

        // Check the correctness of EM
        size_t slen = pub_key.pss_salt_len.value_or( HLen ); // If salt length is not provided the HLen is used
        if ( em.size() < HLen + slen + 2 ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: inconsistent" );
            return false;
        }

        if ( em.back() != 0xbc ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: inconsistent" );
            return false;
        }

        const size_t embits = pub_key.modulus.size() * 8 - 1;
        const unsigned int top_bitmask = 0xff >> ( (em.size() * 8) - embits );
        if ((em[0] & 0xff) != (em[0] & top_bitmask)) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: inconsistent" );
            return false;
        }

        // Extract masked DB & H from EM
        const std::size_t dblen = em.size() - HLen - 1;
        auto db = std::span<byte_t>( em.data(), dblen );
        auto h  = bytes_view( &em[dblen], HLen );

        // Unmask DB
        mgf1( hash, h, db, [](auto dst, auto src, auto len){
            memxor( dst, src, len );
        });

        // Verify DB
        db[0] &= top_bitmask;
        for ( size_t i = 0; i != em.size() - HLen - slen - 2; i++ ) {
            if ( em[i] != 0 ) {
                ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: inconsistent" );
                return false;
            }
        }

        if ( em[em.size() - HLen - slen - 2] != 0x01 ) {
            ACK_LOG_DEBUG( "[ERROR] rsassa_pss_mgf1_verify: inconsistent" );
            return false;
        }

        // Construct M' from digest & salt
        bytes m = bytes( 8 + HLen + slen, 0 );
        const auto salt = db.subspan(db.size() - slen);
        memcpy( &m[8], digest.extract_as_byte_array().data(), HLen );
        memcpy( &m[8 + HLen], salt.data(), slen );

        // Calculate H' and compare H' to H
        const auto h2 = hash( reinterpret_cast<const char*>( m.data() ), m.size() )
            .extract_as_byte_array();
        return memcmp( h.data(), h2.data(), HLen ) == 0;
    }

    /**
    * Verifies RSA PKCS1 v1.5 SHA-1 signature.
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-1 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_sha1(const rsa_public_key_view& pub_key, const eosio::checksum160& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha1_size>( pub_key, signature, [&](std::span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha1_digest_info_prefix, digest );
        });
    }

    /**
    * Asserts if verification of RSA PKCS1 v1.5 SHA-1 signature fails.
    * @note For implementation details see verify_rsa_sha1.
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-1 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_sha1_assert(const rsa_public_key_view& pub_key, const eosio::checksum160& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha1( pub_key, digest, signature ), error );
    }

    /**
    * Verifies RSA PKCS1 v1.5 SHA-256 signature.
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-256 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_sha256(const rsa_public_key_view& pub_key, const eosio::checksum256& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha256_size>( pub_key, signature, [&](std::span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha256_digest_info_prefix, digest );
        });
    }

    /**
    * Asserts if verification of RSA PKCS1 v1.5 SHA-256 signature fails.
    * @note For implementation details see verify_rsa_sha256.
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-256 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_sha256(const rsa_public_key_view& pub_key, const eosio::checksum256& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha256( pub_key, digest, signature ), error );
    }

    /**
    * Verifies a RSA PKCS1 v1.5 SHA-512 signature.
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://tools.ietf.org/html/rfc8017#section-8.2.2
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-512 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_sha512(const rsa_public_key_view& pub_key, const eosio::checksum512& digest, const bytes_view& signature) {
        return rsassa_pkcs1_v1_5_verify<detail::pkcs1_v1_5_t_sha512_size>( pub_key, signature, [&](std::span<byte_t>&& t) {
            rsa_1_5_t_generator( t, detail::sha512_digest_info_prefix, digest );
        });
    }

    /**
    * Asserts if verification of RSA PKCS1 v1.5 SHA-512 signature fails.
    * @note For implementation details see verify_rsa_sha512.
    *
    * @param pub_key   - RSA public key
    * @param digest    - SHA-512 digest to verify
    * @param signature - RSA PKCS1 v1.5 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_sha512(const rsa_public_key_view& pub_key, const eosio::checksum512& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_sha512( pub_key, digest, signature ), error );
    }

    /**
    * Verifies RSASSA-PSS MGF1 SHA-1 signature
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-1 digest to verify
    * @param signature - RSASSA-PSS MGF1 SHA-1 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_pss_sha1(const rsa_pss_public_key_view& pub_key, const eosio::checksum160& digest, const bytes_view& signature) {
        return rsassa_pss_mgf1_verify( pub_key, digest, signature, eosio::sha1 );
    }

    /**
    * Asserts if verification of RSASSA-PSS MGF1 SHA-1 signature fails.
    * @note For implementation details see verify_rsa_pss_sha1.
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-1 digest to verify
    * @param signature - RSASSA-PSS MGF1 SHA-1 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_pss_sha1(const rsa_pss_public_key_view& pub_key, const eosio::checksum160& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_pss_sha1( pub_key, digest, signature ), error );
    }

    /**
    * Verifies RSASSA-PSS MGF1 SHA-256 signature
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-256 digest to verify
    * @param signature - RSASSA-PSS MGF1 SHA-256 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_pss_sha256(const rsa_pss_public_key_view& pub_key, const eosio::checksum256& digest, const bytes_view& signature) {
        return rsassa_pss_mgf1_verify( pub_key, digest, signature, eosio::sha256 );
    }

    /**
    * Asserts if verification of RSASSA-PSS MGF1 SHA-256 signature fails.
    * @note For implementation details see verify_rsa_pss_sha256.
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-256 digest to verify
    * @param signature - RSASSA-PSS MGF1 SHA-256 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_pss_sha256(const rsa_pss_public_key_view& pub_key, const eosio::checksum256& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_pss_sha256( pub_key, digest, signature ), error );
    }

    /**
    * Verifies RSASSA-PSS MGF1 SHA-512 signature
    * @note The decrypted signature is verified following the RFC8017 spec.
    *       https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-512 digest to verify
    * @param signature - SASSA-PSS MGF1 SHA-512 signature
    *
    * @return false if verification has failed, true if succeeds
    */
    [[nodiscard]] inline bool verify_rsa_pss_sha512(const rsa_pss_public_key_view& pub_key, const eosio::checksum512& digest, const bytes_view& signature) {
        return rsassa_pss_mgf1_verify( pub_key, digest, signature, eosio::sha512 );
    }

    /**
    * Asserts if verification of RSASSA-PSS MGF1 SHA-512 signature fails.
    * @note For implementation details see verify_rsa_pss_sha512.
    *
    * @param pub_key   - RSA-PSS public key
    * @param digest    - SHA-512 digest to verify
    * @param signature - RSASSA-PSS MGF1 SHA-512 signature
    * @param error     - error message to use when verification fails
    */
    inline void assert_rsa_pss_sha512(const rsa_pss_public_key_view& pub_key, const eosio::checksum512& digest, const bytes_view& signature, const char* error) {
        eosio::check( verify_rsa_pss_sha512( pub_key, digest, signature ), error );
    }
}