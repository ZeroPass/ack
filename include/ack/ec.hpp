// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <cstdint>
#include <span>

#include <ack/bigint.hpp>
#include <ack/fp.hpp>
#include <ack/types.hpp>
#include <ack/utils.hpp>

namespace ack {
    template<std::size_t N>
    using ec_fixed_bigint = fixed_bigint<N * 2>; // 2x size required for multiplication

    // Affine coordinates representation of an elliptic curve point
    template<typename PointT, typename CurveT>
    struct ec_point_base
    {
        constexpr ec_point_base() : // represents point at infinity
            curve_( nullptr )
        {}

        constexpr ec_point_base(const PointT& p) = delete;
        constexpr ec_point_base(PointT&& p) noexcept = delete;
        constexpr PointT& operator=(const PointT& p) = delete;
        constexpr PointT& operator=(PointT&& p) noexcept = delete;

        /**
         * Returns the curve this point belongs to.
         * @return the curve this point belongs to.
        */
        const CurveT& curve() const
        {
            return *curve_;
        }

        /**
         * Returns the inverse of this point.
         * R = -this
         *
         * @return the inverse of this point
        */
        [[nodiscard]] constexpr PointT invert() const
        {
            return underlying().invert();
        }

        /**
         * Checks if this point is the identity element of the curve, i.e. point at infinity.
         * @return true if this point is the identity element of the curve, false otherwise
        */
        constexpr bool is_identity() const
        {
            return underlying().is_identity();
        }

        /**
         * Checks if this point is on the curve.
         * @return true if this point is on the curve, false otherwise
        */
        [[nodiscard]] bool is_on_curve() const
        {
            return underlying().is_on_curve();
        }

        /**
         * Adds the given point to this point.
         * R = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        [[nodiscard]] PointT add(const PointT& a) const
        {
            return underlying().add( a );
        }

        /**
         * Adds the given point to this point.
         * R = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        [[nodiscard]] PointT add(const ec_point_base& a) const
        {
            return add( a.underlying() );
        }

        /**
         * Returns the double of this point.
         * R = 2 * this
         *
         * @return the double of this point
         */
        [[nodiscard]] PointT doubled() const
        {
            return underlying().doubled();
        }

        /**
         * Subtracts the given point from this point.
         * R = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        [[nodiscard]] PointT sub(const PointT& a) const
        {
            return underlying().sub( a );
        }

        /**
         * Subtracts the given point from this point.
         * R = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        [[nodiscard]] PointT sub(const ec_point_base& a) const
        {
            return sub( a.underlying() );
        }

        /**
         * Multiplies this point by the given scalar.
         * R = this * scalar
         *
         * @param scalar - the scalar to multiply this point by
         * @return the resulting point
        */
        template<typename BigNumT>
        [[nodiscard]] PointT mul(const BigNumT& scalar) const
        {
            return underlying().mul( scalar );
        }

        /**
         * Adds the given point to this point.
         * this = this + a
         *
         * @param a - the point to add other point
         * @param b - the point to add to the other point
         * @return reference to this point
        */
        [[nodiscard]] friend PointT operator + (const PointT& a, const PointT& b)
        {
            return a.add( b );
        }

        [[nodiscard]] friend PointT operator + (const ec_point_base& a, const ec_point_base& b)
        {
            return a.add( b );
        }

        /**
         * Adds the given point to this point.
         * this = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        PointT& operator += (const PointT& a)
        {
            return underlying() = add( a );
        }

        /**
         * Adds the given point to this point.
         * this = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        PointT& operator += (const ec_point_base& a)
        {
            return this-> operator += ( a.underlying() );
        }

        /**
         * Subtracts the given point from this point.
         * R = P - Q
         *
         * @param a - the point to subtract other point from
         * @param b - the point to subtract from the other point
         * @return the result point of the subtraction
        */
        [[nodiscard]] friend PointT operator - (const PointT& a, const PointT& b)
        {
            return a.sub( b );
        }

        /**
         * Subtracts the given point from this point.
         * R = P - Q
         *
         * @param a - the point to subtract other point from
         * @param b - the point to subtract from the other point
         * @return the result point of the subtraction
        */
        [[nodiscard]] friend PointT operator - (const ec_point_base& a, const ec_point_base& b)
        {
            return a.sub( b );
        }

        /**
         * Subtracts the given point from this point.
         * this = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        PointT& operator -= (const PointT& a)
        {
            return underlying() = sub( a );
        }

         /**
         * Subtracts the given point from this point.
         * this = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        PointT& operator -= (const ec_point_base& a)
        {
            return this->operator -= ( a.underlying() );
        }

        /**
         * Multiplies given point by the given scalar.
         * R = P * s
         *
         * @param p - the point to multiply
         * @param s - the scalar to multiply the point by
         * @return the result point of the multiplication
        */
        template<typename BigNumT>
        [[nodiscard]] friend PointT operator * (const PointT& p, const BigNumT& s)
        {
            return p.mul( s );
        }

        /**
         * Multiplies given point by the given scalar.
         * R = P * s
         *
         * @param p - the point to multiply
         * @param s - the scalar to multiply the point by
         * @return the result point of the multiplication
        */
        template<typename BigNumT>
        [[nodiscard]] friend PointT operator * (const ec_point_base& p, const BigNumT& s)
        {
            return p.mul( s );
        }

        /**
         * Multiplies the given scalar by this point.
         * R = s * P
         *
         * @param s - the scalar to multiply this point by
         * @param p - the point to multiply
         * @return the result point of the multiplication
        */
        template<typename BigNumT>
        [[nodiscard]] friend PointT operator * (const BigNumT& s, const PointT& p)
        {
            return p.mul( s );
        }

        /**
         * Multiplies the given scalar by this point.
         * R = s * P
         *
         * @param s - the scalar to multiply this point by
         * @param p - the point to multiply
         * @return the result point of the multiplication
        */
        template<typename BigNumT>
        [[nodiscard]] friend PointT operator * (const BigNumT& s, const ec_point_base& p)
        {
            return p.mul( s );
        }

        /**
         * Multiplies this point by the given scalar.
         * this = this * s
         *
         * @param s - the scalar to multiply this point by.
         * @return reference to this point
        */
        template<typename BigNumT>
        PointT& operator *= (const BigNumT& s)
        {
            return underlying() = mul( s );
        }

        /**
         * Returns the inverse of this point.
         * R = -this
         *
         * @return the inverse of this point
        */
        [[nodiscard]] constexpr PointT operator - () const
        {
            return invert();
        }

        private:
            constexpr ec_point_base( const CurveT& curve ) :
                curve_( &curve )
            {}

            constexpr inline PointT& underlying()
            {
                return static_cast<PointT&>( *this );
            }

            constexpr inline const PointT& underlying() const
            {
                return static_cast<const PointT&>( *this );
            }

        private:
            friend PointT;
            friend CurveT;
            const CurveT* curve_;
    };


    /**
     * Struct represents a affine point on an elliptic curve
     * over a prime finite field GF(p) with short Weierstrass equation:
     * y^2 = x^3 + ax + b
     *
     * The implementation followed the algorithms described in:
     *  - SECG standards SEC 1: Elliptic Curve Cryptography, Version 2.0
     *    https://www.secg.org/sec1-v2.pdf
     *  - RFC-6090: https://www.rfc-editor.org/rfc/rfc6090
     *
     * @warning The point's curve is stored as a pointer to the curve object.
     *          The curve object must outlive the point object.
    */
    template<typename BigNumT, typename CurveT>
    struct ec_point_fp : ec_point_base<ec_point_fp<BigNumT, CurveT>, CurveT>
    {
        using base_type          = ec_point_base<ec_point_fp<BigNumT, CurveT>, CurveT>;
        using field_element_type = typename  CurveT::field_element_type;
        using base_type::base_type;

        field_element_type x;
        field_element_type y;

        /**
         * Constructs a point at infinity
        */
        constexpr ec_point_fp() :
            base_type(),
            x( field_element_type::zero() ),
            y( field_element_type::zero() )
        {}

        /**
         * Returns the inverse of this point.
         * R = -this
         *
         * @return the inverse of this point
        */
        [[nodiscard]] constexpr ec_point_fp invert() const
        {
            if ( is_identity() ) {
                return *this;
            }
            return ec_point_fp( this->curve(), x, -y );
        }

        /**
         * Checks if this point is the identity element of the curve, i.e. point at infinity.
         * @return true if this point is the identity element of the curve, false otherwise
        */
        constexpr bool is_identity() const
        {
            return (x.is_zero() && y.is_zero()) || this->curve_ == nullptr;
        }

         /**
         * Checks if this point is on the curve by calculating
         * the left and right hand side of the equation:  y^2 = x^3 + ax + b
         *
         * @return true if this point is on the curve, false otherwise
        */
        [[nodiscard]] bool is_on_curve() const
        {
            if ( is_identity() ) {
                return true;
            }

            return ( y.sqr() - ( ( x.sqr() + this->curve().a ) * x + this->curve().b )) == 0;
        }

        /**
         * Adds the given point to this point.
         * R = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        [[nodiscard]] ec_point_fp add(const ec_point_fp& a) const
        {
            if ( is_identity() ) {
                return a;
            }

            if ( a.is_identity() ) {
                return *this;
            }

             // TODO: before this sub operation caused error in wasm:  memcpy with overlapping memory memcpy can only accept non-aliasing pointers
            auto s = a.x - x;
            if ( s.is_zero() ) {
                if ( y == a.y ) { // double point
                    return this->doubled();
                }
                return ec_point_fp(); // point at infinity
            }

            // Calculate tangent slope
            s = ( a.y - y ) / s;

            // Calculate new x and y
            auto x3 = s.sqr() - x - a.x;
            auto y3 = s * ( x - x3 ) - y;
            return ec_point_fp( this->curve(), x3, y3 );
        }

         /**
         * Returns the double of this point.
         * R = 2 * this
         *
         * @return the double of this point
         */
        [[nodiscard]] ec_point_fp doubled() const
        {
            if ( is_identity() || y.is_zero() ) { // check for y == 0 handles division by zero issue
                return ec_point_fp();
            }

            // Calculate tangent slope
            auto x_sqr = x.sqr();
            auto s = ( x_sqr + x_sqr + x_sqr + this->curve().a ) / ( y + y ) ;

            // Calculate new x and y
            auto x2 = s.sqr() - x - x;
            auto y2 = s * ( x - x2 ) - y;
            return ec_point_fp( this->curve(), x2, y2 );
        }

        /**
         * Subtracts the given point from this point.
         * R = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        [[nodiscard]] ec_point_fp sub(const ec_point_fp& a) const
        {
            return *this + (-a);
        }

        /**
         * Multiplies this point by the given scalar using double and add algorithm.
         * R = this * scalar
         *
         * @param scalar - the scalar to multiply this point by
         * @return the resulting point
        */
        [[nodiscard]] ec_point_fp mul(const BigNumT& scalar) const
        {
            if ( scalar == 1 || is_identity() ) {
                return *this;
            }

            if ( scalar.is_zero() ) {
                return ec_point_fp();
            }

            if ( scalar < 0 ) {
                return invert() * -scalar;
            }

            auto r   = ec_point_fp();
            auto tmp = *this;
            auto s   = scalar;
            while ( s != 0 ) {
                if ( ( s & 1U ) != 0 ) {
                    r += tmp;
                }
                tmp = tmp.doubled();
                s >>= 1;
            }
            return r;
        }

        constexpr friend bool operator == (const ec_point_fp& a, const ec_point_fp& b)
        {
            if ( a.x == b.x && a.y == b.y ) {
                return ( a.curve_ == b.curve_  ) || a.x == 0; // a.x == 0 means point at infinity
            }
            return false;
        }

        constexpr friend bool operator != (const ec_point_fp& a, const ec_point_fp& b)
        {
            return !(a == b);
        }

        private:
            friend CurveT;
            constexpr ec_point_fp( const CurveT& curve, field_element_type x, field_element_type y ) :
                base_type( curve ),
                x( std::move(x) ),
                y( std::move(y) )
            {}
    };

    /**
     * Struct represents a point on an elliptic curve in standard projective coordinates (homogeneous coordinates)
     * over a prime finite field GF(p) with short Weierstrass equation:
     * y^2 * z = x^3 + ax * z^2 + b * z^3
     *
     * Implementation follows the RFC 6090: https://www.rfc-editor.org/rfc/rfc6090
     *
     * @warning The point's curve is stored as a pointer to the curve object.
     *          The curve object must outlive the point object.
     *
    */
    template<typename BigNumT, typename CurveT>
    struct ec_point_fp_proj : ec_point_base<ec_point_fp_proj<BigNumT, CurveT>, CurveT>
    {
        using base_type          = ec_point_base<ec_point_fp_proj<BigNumT, CurveT>, CurveT>;
        using field_element_type = typename CurveT::field_element_type;
        using affine_point_type  = typename CurveT::point_type;
        using base_type::base_type;

        field_element_type x;
        field_element_type y;
        field_element_type z;

        /**
         * Constructs a point at infinity
        */
        constexpr ec_point_fp_proj() :
            base_type(),
            x( field_element_type::zero() ),
            y( field_element_type::one()  ),
            z( field_element_type::zero() )
        {}

        /**
         * Constructs this point from the given affine point.
         * @warning The point's curve is stored as a pointer to the curve object.
         *          The curve object must outlive the point object.
         *
         * @param p - the affine point to construct this point from.
        */
        explicit constexpr ec_point_fp_proj(affine_point_type p) :
            ec_point_fp_proj()
        {
            if ( !p.is_identity() ) {
                this->curve_ = &p.curve();
                x = std::move(p.x);
                y = std::move(p.y);
                z = field_element_type( 1, p.curve().p );
            }
        }

        /**
         * Returns the affine representation of this point.
         * @param verify - If true, verifies that the point is on the curve.
         * @return this point in affine form
        */
        [[nodiscard]] const affine_point_type to_affine(bool verify = false) const
        {
            if ( is_identity() ) {
                return affine_point_type();
            }
            auto z_inv = z.inv();
            return this->curve().make_point( x * z_inv, y * z_inv, verify );
        }

        /**
         * Returns the inverse of this point.
         * R = -this
         *
         * @return the inverse of this point
        */
        [[nodiscard]] constexpr ec_point_fp_proj invert() const
        {
            if ( is_identity() ) {
                return *this;
            }
            return ec_point_fp_proj( this->curve(), x, -y, z );
        }

        /**
         * Checks if this point is the identity element of the curve, i.e. point at infinity.
         * @return true if this point is the identity element of the curve, false otherwise
        */
        constexpr bool is_identity() const
        {
            return this->curve_ == nullptr ||( z.is_zero() );
        }

         /**
         * Checks if this point is on the curve by calculating
         * the left and right hand side of the equation:  y^2 * z = x^3 + ax * z^2 + b * z^3
         *
         * @return true if this point is on the curve, false otherwise
        */
        [[nodiscard]] bool is_on_curve() const
        {
            if ( is_identity() ) {
                return true;
            }
            const auto z2 = z.sqr();
            return ( y.sqr() * z - ( ( x.sqr() * x + this->curve().a * x * z2 + this->curve().b * z * z2 ) ) ) == 0;
        }

        /**
         * Adds the given point to this point.
         * R = this + a
         *
         * @param a - the point to add to this point
         * @return reference to this point
        */
        [[nodiscard]] ec_point_fp_proj add(const ec_point_fp_proj& q) const
        {
            const auto& p = *this;
            if ( p.is_identity() ) {
                return q;
            }

            if ( q.is_identity() ) {
                return p;
            }

            auto t0 = p.y * q.z;
            auto t1 = q.y * p.z;
            auto u0 = p.x * q.z;
            auto u1 = q.x * p.z;
            if ( u0 == u1 ) {
                if ( t0 == t1 ) {
                    return doubled();
                } else {
                    return ec_point_fp_proj();
                }
            }

            auto t  = t0 - t1;
            auto u  = u0 - u1;
            auto v  = p.z * q.z;
            auto u2 = u.sqr();
            auto w  = t * t * v - u2 * ( u0 + u1 );
            auto u3 = u * u2;

            auto rx = u * w;
            auto ry = t * ( u0 * u2 - w ) - t0 * u3;
            auto rz = u3 * v;
            return make_point( std::move(rx), std::move(ry), std::move(rz) );
        }

         /**
         * Returns the double of this point.
         * R = 2 * this
         *
         * @return the double of this point
         */
        [[nodiscard]] ec_point_fp_proj doubled() const
        {
            const auto& p = *this;
            if ( p.is_identity() ) {
                return p;
            }

            if ( p.is_identity() || p.y == 0 ) {
                return p;
            }

            auto t  = p.x.sqr() * 3 + this->curve().a * p.z.sqr();
            auto u  = p.y * p.z * 2;
            auto v  = u * p.x * p.y * 2;
            auto w  = t.sqr() - v * 2;

            auto rx = u * w;

            auto u2 = u.sqr();
            auto ry = t * ( v - w ) - u2 * p.y.sqr() * 2;

            auto rz = u2 * u;
            return make_point( std::move(rx), std::move(ry), std::move(rz) );
        }

        /**
         * Subtracts the given point from this point.
         * R = this - a
         *
         * @param a - the point to subtract from this point
         * @return reference to this point
        */
        [[nodiscard]] ec_point_fp_proj sub(const ec_point_fp_proj& a) const
        {
            return *this + (-a);
        }

        /**
         * Multiplies this point by the given scalar using the double and add algorithm.
         * R = this * scalar
         *
         * @param scalar - the scalar to multiply this point by
         * @return the resulting point
        */
        [[nodiscard]] ec_point_fp_proj mul(const BigNumT& scalar) const
        {
            if ( scalar == 1 || is_identity() ) {
                return *this;
            }

            if ( scalar.is_zero() ) {
                return ec_point_fp_proj();
            }

            if ( scalar < 0 ) {
                return invert() * -scalar;
            }

            auto r   = ec_point_fp_proj();
            auto tmp = *this;
            auto s   = scalar;
            while ( s != 0 ) {
                if ( ( s & 1U ) != 0 ) {
                    r += tmp;
                }
                tmp = tmp.doubled();
                s >>= 1;
            }
            return r;
        }

        constexpr friend bool operator == (const ec_point_fp_proj& a, const ec_point_fp_proj& b)
        {
            if ( a.x == b.x && a.y == b.y && a.z == b.z) {
                return ( a.curve_ == b.curve_  ) || a.is_identity(); // a.x == 0 && a.y == 1 is the point at infinity
            }
            return false;
        }

        constexpr friend bool operator != (const ec_point_fp_proj& a, const ec_point_fp_proj& b)
        {
            return !(a == b);
        }

        private:
            friend CurveT;
            constexpr ec_point_fp_proj( const CurveT& curve, field_element_type x, field_element_type y, field_element_type z ) :
                base_type( curve ),
                x( std::move(x) ),
                y( std::move(y) ),
                z( std::move(z) )
            {}

            ec_point_fp_proj make_point( field_element_type x, field_element_type y, field_element_type z ) const
            {
                return ec_point_fp_proj( this->curve(), std::move(x), std::move(y), std::move(z) );
            }
    };

    template<typename CurveT, typename FieldElementT, typename PointT>
    struct ec_curve_base {
        using field_element_type = FieldElementT;
        using point_type         = PointT;

        /**
         * Returns curve field element from the given big number.
         * @note The big number must be in the range [0, p-1]. Not checked!
         * @param x the big number to convert
         * @return curve field element
        */
        template<typename BigNumT = typename field_element_type::bignum_type>
        [[nodiscard]] constexpr field_element_type make_field_element(BigNumT x) const
        {
            return static_cast<const CurveT&>(*this)
                .make_field_element( std::move(x) );
        }

        /**
         * Returns curve point from the given big numbers.
         * @param x the x coordinate of the point
         * @param y the y coordinate of the point
         * @param verify if true, the point is verified to be on the curve
         * @return curve point
        */
        template<typename BigNumT = typename field_element_type::bignum_type>
        [[nodiscard]] constexpr point_type make_point(BigNumT x, BigNumT y, bool verify = false) const
        {
            return static_cast<const CurveT&>(*this)
                .make_point( std::move(x), std::move(y), verify );
        }

        /**
         * Verifies curve parameters.
         * @return true if curve parameters are valid.
        */
        [[nodiscard]] bool verify() const
        {
            return static_cast<const CurveT&>(*this).verify();
        }
    };

    /**
     * Defines curve over a prime field GF(p)
     * with Weierstrass equation y^2 = x^3 + ax + b.
     *
     * @tparam BigNumT  - big number type
     * @tparam CurveTag - The curve tag
    */
    template<typename BigNumT, typename CurveTag>
    struct ec_curve_fp :
        ec_curve_base<
            ec_curve_fp<BigNumT, CurveTag>,
            fp_element<BigNumT, CurveTag>,
            ec_point_fp<BigNumT, ec_curve_fp<BigNumT, CurveTag>>
        >
    {
        using base_type = ec_curve_base<ec_curve_fp<BigNumT, CurveTag>,
                            fp_element<BigNumT, CurveTag>,
                            ec_point_fp<BigNumT, ec_curve_fp<BigNumT, CurveTag>>>;

        using curve_tag          = CurveTag;
        using field_element_type = typename base_type::field_element_type;
        using point_type         = typename base_type::point_type;

        const BigNumT p;          // curve prime
        const BigNumT a;          // curve coefficient
        const BigNumT b;          // curve coefficient
        const point_type g;       // generator
        const BigNumT n;          // order of g
        const uint32_t h;         // cofactor, i.e.: h = p / n

        /**
         * Creates a curve from the given parameters.
         * @param p - curve prime
         * @param a - curve coefficient
         * @param b - curve coefficient
         * @param g - generator point coordinates
         * @param n - order of g
         * @param h - cofactor, i.e.: h = p / n
        */
        constexpr ec_curve_fp(BigNumT p, BigNumT a, BigNumT b, std::pair<BigNumT, BigNumT> g, BigNumT n, uint32_t h):
            p( std::move(p) ),
            a( std::move(a) ),
            b( std::move(b) ),
            g( make_point( std::move(g.first), std::move(g.second) )),
            n( std::move(n) ),
            h( h )
        {}

        /**
         * Creates a field element from a given integer.
         * @warning Returned field element stores pointer to curve prime.
         *          The curve must outlive the field element.
         *
         * @note Expects x > 0 and x < p
         *
         * @note Returned field element is not checked for validity.
         *
         * @param x - Integer to convert to field element
         * @return Field element
         *
        */
        [[nodiscard]] constexpr field_element_type make_field_element(BigNumT x) const
        {
            return field_element_type( std::move(x), p );
        }

        /**
         * Creates a point from a given pair of integers x & y.
         * @warning Returned point stores pointer to curve prime.
         *          The curve must outlive the point.
         *
         * @param x - x coordinate of the point
         * @param y - y coordinate of the point
         * @param verify - If true, the point is checked for validity, i.e. x & y are in range [0, p-1] and created point lies on the curve.
         *                 Default is false.
         * @return Curve point
        */
        [[nodiscard]] constexpr point_type make_point(BigNumT x, BigNumT y, bool verify = false) const
        {
            if (verify) {
                check( !x.is_negative() && y < p && !y.is_negative() && y < p, "Invalid x or y point coordinate" );
            }

            auto p = point_type {
                *this,
                make_field_element( std::move(x) ),
                make_field_element( std::move(y) )
            };

            if (verify) {
                check( p.is_on_curve(), "Point is not on curve" );
            }

            return p;
        }

        /**
         * Verifies curve parameters.
         * @note Very basic verification is performed, no check for primality of p and n;
         *       Very slow operation.
         *
         * @return true if curve parameters are valid.
        */
        [[nodiscard]] bool verify() const
        {
            // Verify that p is prime
            // if ( !p.is_prime() ) {
            //     return false;
            // }

            // Verify that a and b are in the range [0, p-1]
            if ( a >= p || b >= p ) {
                return false;
            }

            // Verify that a^3 + 27 * b^2 != 0
            auto afe = make_field_element( a );
            auto bfe = make_field_element( b );
            auto y2  = 4 * afe.sqr() * afe + 27 * bfe.sqr();
            if ( y2 == 0 ) {
                return false;
            }

            // check that the discriminant is nonzero. If zero, the curve is singular.
            if ( ( -16 * y2 ) == 0) {
                return false;
            }

            // Verify that g is on the curve and not the point at infinity
            if ( !g.is_on_curve() || g.is_identity() ) {
                return false;
            }

            // Verify that the generator point has order n
            if ( ( g * n ) != point_type() ) {
                return false;
            }

            // Verify that n is prime
            // if ( !n.is_prime() ) {
            //     return false;
            // }

            // Verify that h is in the range [1, p-1]
            if ( h < 1 || h >= p ) {
                return false;
            }

            // Verify that n * h = p - 1
            if ( n * h == p - 1 ) {
                return false;
            }

            return true;
        }
    };

    // Type aliases for convenience
    template<typename PointT, typename BigNumT, typename CurveTag>
    using ec_point_fp_base_t = ec_point_base<PointT, ec_curve_fp<BigNumT, CurveTag>>;

    template<typename BigNumT, typename CurveTag>
    using ec_point_fp_t = ec_point_fp<BigNumT, ec_curve_fp<BigNumT,CurveTag>>;

    template<typename BigNumT, typename CurveTag>
    using ec_point_fp_proj_t = ec_point_fp_proj<BigNumT, ec_curve_fp<BigNumT, CurveTag>>;

    // helper functions
    /**
     * Creates a point in homogeneous coordinates from affine point.
     * @warning Returned point stores pointer to curve.
     *         The curve must outlive the point.
     *
     * @tparam BigNumT  - Big number type
     * @tparam CurveTag - Curve tag
     * @param p - Affine point
     * @return ec_point_fp_proj_t<BigNumT, CurveTag> - Point in homogeneous coordinates
    */
    template<typename BigNumT, typename CurveTag>
    [[nodiscard]] inline auto make_ec_point_fp_proj(ec_point_fp_t<BigNumT, CurveTag> p) ->
        ec_point_fp_proj_t<BigNumT, CurveTag>
    {
        return ec_point_fp_proj_t<BigNumT,CurveTag>( std::move(p) );
    }

    /**
     * Fast multiplication of points and addition of points, i.e. a*P + b*Q
     * Function uses Shamir's trick to calculate a*P + b*Q in one batch,
     * thus the speedup shoule be ~2x.
     *
     * @tparam PointT  - Point type
     * @tparam BigNumT - Big number type
     *
     * @param a - First multiplier
     * @param p - First point
     * @param b - Second multiplier
     * @param q - Second point
     * @return PointT - Result of a*P + b*Q
    */
    template<typename PointT, typename BigNumT, typename CurveTag>
    [[nodiscard]] PointT ec_mul_add_fast(const BigNumT& a, const ec_point_fp_base_t<PointT, BigNumT, CurveTag>& p,
                           const BigNumT& b, const ec_point_fp_base_t<PointT, BigNumT, CurveTag>& q)
    {
        using bpt = ec_point_fp_base_t<PointT, BigNumT, CurveTag>;

        auto s1_bits = a.bit_length();
        auto s2_bits = b.bit_length();
        int l = std::max(s1_bits, s2_bits) - 1;

        const PointT pq_sum = p + q;
        const bpt* points[4] = { nullptr, &p, &q, &pq_sum };

        const auto get_point = [&](int i) {
            return points[ a.test_bit( i ) | ( b.test_bit( i ) << 1 ) ];
        };

        PointT r;
        auto point = get_point( l-- );
        if (point) {
            r = static_cast<const PointT&>( *point );
        }

        for( ; l >= 0; l-- ) {
            r = r.doubled();
            auto point = get_point( l );
            if (point) {
                r += *point;
            }
        }

        return r;
    }
}
