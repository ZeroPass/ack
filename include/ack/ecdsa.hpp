// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/ec.hpp>
#include <ack/utils.hpp>

namespace ack{
    /**
     * Function verifies ECDSA signature.
     * @note msg is truncated to curve.n byte length.
     *
     * @param q     - public key point. Note: point validity should be checked before calling this function.
     * @param msg   - message to verify
     * @param r     - signature r value
     * @param s     - signature s value
     * @param curve - elliptic curve
     * @return true if signature is valid, false otherwise.
    */
    template<typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]] static bool ecdsa_verify(const ec_point_fp<CurveT>& q, const bytes_view msg, const IntT& r, const IntT& s,
                             const CurveT& curve)
    {
        if ( r < 1 || r >= curve.n || s < 1 || s >= curve.n ) {
            return false;
        }

        auto e = IntT( msg.subspan( 0, std::min( curve.n.byte_length(), msg.size() )));
        if ( e > curve.n ) {
            e -= curve.n;
        }

        IntT w = s.modinv( curve.n );
        auto u1 = ( e * w ) % curve.n;
        auto u2 = ( r * w ) % curve.n;

        //auto rr = ( u1*ec_point_fp_proj(curve.g) + u2*ec_point_fp_proj(q) ).to_affine();
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
     * @note digest is truncated to curve.n byte length.
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param digest - message digest to verify
     * @param r      - signature r value
     * @param s      - signature s value
     * @param curve  - elliptic curve
     * @return true if signature is valid, false otherwise.
    */
    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    [[nodiscard]] inline bool ecdsa_verify(const ec_point_fp<CurveT>& q, const eosio::fixed_bytes<HLen>& digest,
                                           const IntT& r, const IntT& s, const CurveT& curve)
    {
        const auto bd = digest.extract_as_byte_array();
        const auto m  = bytes_view( reinterpret_cast<const byte_t*>( bd.data() ), HLen );
        return ecdsa_verify( q, m, r, s, curve );
    }

    /**
     * Asserts that ECDSA signature is valid.
     * @note msg is truncated to curve.n byte length.
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param msg    - message to verify
     * @param r      - signature r value
     * @param s      - signature s value
     * @param curve  - elliptic curve
     * @param error  - error message when verification fails
    */
    template<typename CurveT, typename IntT = typename CurveT::int_type>
    inline void assert_ecdsa(const ec_point_fp<CurveT>& q, const bytes_view msg, const IntT& r, const IntT& s, const CurveT& curve, const char* error)
    {
        check( ecdsa_verify( q, msg, r, s, curve ), error );
    }

    /**
     * Asserts that ECDSA signature is valid.
     * @note digest is truncated to curve.n byte length.
     *
     * @param q      - public key point. Note: point validity should be checked before calling this function.
     * @param digest - message digest to verify
     * @param r      - signature r value
     * @param s      - signature s value
     * @param curve  - elliptic curve
     * @param error  - error message when verification fails
    */
    template<std::size_t HLen, typename CurveT, typename IntT = typename CurveT::int_type>
    inline void assert_ecdsa(const ec_point_fp<CurveT>& q, const eosio::fixed_bytes<HLen>& digest,
                             const IntT& r, const IntT& s, const CurveT& curve, const char* error)
    {
        check( ecdsa_verify( q, digest, r, s, curve ), error );
    }
}
