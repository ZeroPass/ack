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
     * @param q   - public key point. Note: point validity should be checked before calling this function.
     * @param msg - message to verify. Note: msg is truncated to curve.n byte length.
     * @param r   - signature r value
     * @param s   - signature s value
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

        const IntT w  = s.modinv( curve.n );
        const auto u1 = ( e * w ) % curve.n;
        const auto u2 = ( r * w ) % curve.n;
        auto R = ec_mul_add_fast( u1, ec_point_fp_jacobi( curve.g ), u2, ec_point_fp_jacobi( q ) )
            .to_affine();

        if ( R.is_identity() ) {
            return false;
        }

        if ( R.x >= curve.n ) {
            R.x -= curve.n;
        }

        return R.x == r;
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
    [[nodiscard]] inline bool ecdsa_verify(const ec_point_fp<CurveT>& q, const hash_t<HLen>& digest,
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
    inline void assert_ecdsa(const ec_point_fp<CurveT>& q, const hash_t<HLen>& digest,
                             const IntT& r, const IntT& s, const char* error)
    {
        check( ecdsa_verify( q, digest, r, s ), error );
    }

    /**
     * Function recovers public key from given message and ECDSA signature.
     * Implementation is modified version of SEC 1 v2.0, section 4.1.6 'Public Key Recovery Operation':
     * https://www.secg.org/sec1-v2.pdf#page=53
     *
     * @note This function currently works only for curve.h == 1.
     *
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param curve  - Elliptic curve
     * @param msg    - message
     * @param r      - signature r value
     * @param s      - signature s value
     * @param recid  - recovery id of the public key Q. (recid  <= 3)
     * @param verify - Performs additional verifications
     *
     * @return recovered EC public key point Q, or point at infinity if Q can't be calculated.
    */
    template<typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]]
    static ec_point_fp<CurveT> ecdsa_recover(const CurveT& curve, const bytes_view msg, const IntT& r, const IntT& s,
                                             const std::size_t recid, const bool verify = false)
    {
        if ( r < 1 || r >= curve.n || s < 1 || s >= curve.n || ( recid & 3 ) != recid ) {
            return ec_point_fp<CurveT>();
        }

        const auto yodd       = recid  & 1;
        const auto second_key = recid >> 1;

        // Sanity check, the second key is expected to be negative
        if ( second_key && r >= curve.p_minus_n ) {
            return ec_point_fp<CurveT>();
        }

        auto e = IntT( msg.subspan( 0, std::min( curve.n.byte_length(), msg.size() )));
        if ( e > curve.n ) {
            e -= curve.n;
        }

        // Calculate R, 1.1 - 1.3
        // 1.1. Let x = r + jn.
        const auto R = (second_key)
            ? curve.decompress_point( r + curve.n, yodd )
            : curve.decompress_point( r, yodd );

        if ( R.is_identity() ) {
            return R;
        }

        if ( verify ) {
            // 1.4 nR == O
            if ( !( R * curve.n ).is_identity() ) {
                return ec_point_fp<CurveT>();
            }
        }

        // 1.6.1 Compute Q = r^-1 (sR -  eG)
        //               Q = r^-1 (sR + -eG)
        //
        // We precompute w = r^-1, ew = -ew and sw = sw
        // so that we can then efficiently compute: Q = ew * G + sw * R
        const IntT w  = r.modinv( curve.n );
        const auto ew = (( curve.n - e ) * w ) % curve.n;
        const auto sw = ( s * w ) % curve.n;
        return ec_mul_add_fast( ew, ec_point_fp_jacobi( curve.g ), sw, ec_point_fp_jacobi( R ) )
            .to_affine();
    }

    /**
     * Function recovers public key from given message and ECDSA signature.
     * Implementation is modified version of SEC 1 v2.0, section 4.1.6 'Public Key Recovery Operation':
     * https://www.secg.org/sec1-v2.pdf#page=53
     *
     * @note function works currently only for curve.h = 1
     *
     * @tparam HLen   - digest length
     * @tparam CurveT - elliptic curve type. Required to be a curve over prime field.
     * @tparam IntT   - integer type, default is curve integer type
     *
     * @param curve  - Elliptic curve
     * @param digest - message digest. Note: digest is truncated to curve.n byte length.
     * @param r      - signature r value
     * @param s      - signature s value
     * @param recid  - recovery id of the public key Q. (recid  <= 3)
     * @param verify - Performs additional verifications
     *
     * @return recovered EC public key point Q, or point at infinity if Q can't be calculated.
    */
    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]]
    static ec_point_fp<CurveT> ecdsa_recover(const CurveT& curve, const hash_t<HLen>& digest,
                                             const IntT& r, const IntT& s,
                                             const std::size_t recid, const bool verify = false)
    {
        const auto bd = digest.extract_as_byte_array();
        const auto m  = bytes_view( reinterpret_cast<const byte_t*>( bd.data() ), HLen );
        return ecdsa_recover( curve, m, r, s, recid, verify );
    }
}
