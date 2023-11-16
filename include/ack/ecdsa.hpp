// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/utils.hpp>

namespace ack{
    /**
     * Function verifies ECDSA signature.
     *
     * The implementation follows the NIST FIPS 186-5, section 6.4.2: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
     * and cross-checked against:
     *  - SECG SEC1 v2.0, section 4.1.4: https://www.secg.org/sec1-v2.pdf#page=52
     *  - BSI TR-03111 v2.10, section 4.2.1.2.: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03111/BSI-TR-03111_pdf.pdf
     *
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param q     - public key point. Note: point validity should be checked before calling this function.
     * @param msg   - message to verify. Note: msg is truncated to curve.n byte length.
     * @param r     - signature r value
     * @param s     - signature s value
     * @return true if signature is valid, false otherwise.
    */
    template<typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]] static bool ecdsa_verify(const ec_point_fp<CurveT>& q, const bytes_view msg, const IntT& r, const IntT& s)
    {
        if ( q.is_identity() ) {
            return false;
        }

        const auto& curve = q.curve();
        if ( r < 1 || r >= curve.n || s < 1 || s >= curve.n ) {
            return false;
        }

        auto e = IntT( msg.subspan( 0, std::min( curve.n.byte_length(), msg.size() )));
        if ( e > curve.n ) {
            e -= curve.n;
        }

        IntT w  = s.modinv( curve.n );
        auto u1 = ( e * w ) % curve.n;
        auto u2 = ( r * w ) % curve.n;
        auto rr = ec_mul_add_fast( u1, ec_point_fp_proj( curve.g ), u2, ec_point_fp_proj( q ) )
            .to_affine();

        if ( rr.is_identity() ) {
            return false;
        }

        if ( rr.x >= curve.n ) {
            rr.x -= curve.n;
        }

        return rr.x == r;
    }

    /**
     * Function verifies ECDSA signature.
     *
     * @tparam HLen   - digest length
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param digest - message digest to verify. Note: digest is truncated to curve.n byte length.
     * @param r      - signature r value
     * @param s      - signature s value
     * @return true if signature is valid, false otherwise.
    */
    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]] inline bool ecdsa_verify(const ec_point_fp<CurveT>& q, const eosio::fixed_bytes<HLen>& digest,
                                           const IntT& r, const IntT& s)
    {
        const auto bd = digest.extract_as_byte_array();
        const auto m  = bytes_view( reinterpret_cast<const byte_t*>( bd.data() ), HLen );
        return ecdsa_verify( q, m, r, s );
    }

    /**
     * Asserts that ECDSA signature is valid.
     *
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param msg    - message to verify. Note: msg is truncated to curve.n byte length.
     * @param r      - signature r value
     * @param s      - signature s value
     * @param error  - error message when verification fails
    */
    template<typename CurveT, typename IntT = typename CurveT::int_type>
    inline void assert_ecdsa(const ec_point_fp<CurveT>& q, const bytes_view msg,
                             const IntT& r, const IntT& s, const char* error)
    {
        check( ecdsa_verify( q, msg, r, s ), error );
    }

    /**
     * Asserts that ECDSA signature is valid.
     *
     * @tparam HLen   - digest length
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param digest - message digest to verify. Note: digest is truncated to curve.n byte length.
     * @param r      - signature r value
     * @param s      - signature s value
     * @param error  - error message when verification fails
    */
    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    inline void assert_ecdsa(const ec_point_fp<CurveT>& q, const eosio::fixed_bytes<HLen>& digest,
                             const IntT& r, const IntT& s, const char* error)
    {
        check( ecdsa_verify( q, digest, r, s ), error );
    }
}
