// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/bigint.hpp>
#include <ack/fe.hpp>
#include <ack/utils.hpp>

#include <type_traits>

namespace ack {
    namespace detail {
        template<typename IntT, typename = std::enable_if_t<std::is_integral_v<IntT> || is_bigint_v<IntT>>>
        using cref_int_t = std::conditional_t<std::is_integral_v<IntT>, const IntT, const IntT&>;

        template<typename IntA, typename IntB>
        [[nodiscard]] inline constexpr bool fp_is_valid(cref_int_t<IntA> a, cref_int_t<IntB> p)
        {
            return ( a >= 0 ) && ( a < p );
        }

        template<typename IntA, typename IntB>
        [[nodiscard]] inline constexpr IntB fp_neg(cref_int_t<IntA> a, cref_int_t<IntB> p)
        {
            if ( a == 0 ) {
                return a;
            }
            return p - a;
        }

        template<typename IntA, typename IntB>
        inline constexpr void fp_normalize(IntA& a, cref_int_t<IntB> p)
        {
            if ( a == 0  || ( a == 1 && p != 1 ) ) {
                return;
            }

            if ( a < 0 ) {
                if constexpr (is_bigint_v<IntA> && is_bigint_v<IntB>) {
                    if ( a.byte_length() > p.byte_length() ) {
                        a %= p;
                    }
                    a += p;
                }
                else {
                    a %= p;
                    a += p;
                }
            }
            else if ( a >= p ) {
                if constexpr (is_bigint_v<IntA> && is_bigint_v<IntB>) {
                    if ( a.byte_length() > p.byte_length() ) {
                        a %= p;
                    }
                    else {
                        a -= p;
                    }
                }
                else {
                    a -= p;
                }
            }
        }

        template<typename IntA, typename IntB, typename IntC>
        [[nodiscard]] inline auto constexpr fp_add(cref_int_t<IntA> a, cref_int_t<IntB> b, cref_int_t<IntC> p)
        {
            auto res = a + b;
            if ( res >= p ) {
                res -= p;
            }
            return res;
        }

        template<typename IntA, typename IntB, typename IntC>
        [[nodiscard]] inline auto constexpr fp_sub(cref_int_t<IntA> a, cref_int_t<IntB> b, cref_int_t<IntC> p)
        {
            auto res = a - b;
            if ( res < 0 ) {
                res += p;
            }
            return res;
        }

        template<typename IntA, typename IntB, typename IntC>
        [[nodiscard]] inline IntA fp_mul(cref_int_t<IntA> a, cref_int_t<IntB> b, cref_int_t<IntC> p)
        {
            return ( a * b ) % p;
        }

        template<typename IntA, typename BufferB, typename IntC>
        [[nodiscard]] inline auto fp_div(cref_int_t<IntA> a, const bigint<BufferB>& b, cref_int_t<IntC> p)
        {
            return ( a * b.modinv( p ) ) % p;
        }

        template<typename BufferA, typename BufferC>
        [[nodiscard]] inline bigint<BufferA> fp_sqrt(const bigint<BufferA>& n, const bigint<BufferC>& p)
        {
            // Check that n is indeed a square: (n | p) must be = 1
            // The Legendre symbol (n | p) denotes the value of n^(p-1)/2 (mod p).
            if ( n.jacobi( p ) != 1 ) {
                return 0;
            }

            if (( p % 4 ) == 3 ) {
                // sqrt(a) = a^((p + 1) / 4) (mod p)
                return n.modexp( ( p + 1 ) / 4, p );
            }

            /* Fallback to general Tonelli-Shanks algorithm */

            // Find q and s such that p - 1 = q2^s with q odd
            auto q = p - 1;
            std::size_t s = 0;
            while ( q.is_even() ) {
                s++;
                q >>= 1;
            }

            // Find non-square z such that (z | p) = -1
            bigint<BufferC> z = 2;
            while ( z.jacobi( p ) != -1 ) { // TODO: Possible infinite loop
                ++z;
            }

            auto c = z.modexp( q, p );
            auto r = n.modexp(( q - 1 ) / 2, p );
            auto t = ( r.sqr() % p ) * n % p;
            r = n * r % p;

            while ( t != 1 )
            {
                std::size_t m = 0;
                z = t;
                do
                {
                    m++;
                    z = z.sqr() % p;
                    if ( m == s ) {
                        return 0;
                    }
                }
                while ( z != 1 );

                auto b = c;
                for ( std::size_t i = 0; i < ( s - m - 1 ); i++ ) {
                    b = b.sqr() % p;
                }

                c = b.sqr() % p;
                s = m;
                r = r * b % p;
                t = t * c % p;
            }

            return r;
        }
    }

    /** Checks if finite field element a is valid.
     * i.e.: a >= 0 and a < p.
     *
     * @tparam BufferA - Big integer buffer type of finite field element.
     * @tparam BufferB - Big integer buffer type of the prime modulus.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return true if a is valid finite field element, false otherwise.
     */
    template<typename BufferA, typename BufferB>
    [[nodiscard]] inline constexpr bool fp_is_valid(const bigint<BufferA>& a, const bigint<BufferB>& p)
    {
        return detail::fp_is_valid<bigint<BufferA>, bigint<BufferB>>( a, p );
    }

    /** Checks if finite field element a is valid.
     * i.e.: a >= 0 and a < p.
     *
     * @tparam IntA - Small integer type of finite field element.
     * @tparam BufferB - Big integer buffer type of the prime modulus.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return true if a is valid finite field element, false otherwise.
     */
    template<typename IntA, typename BufferB, typename = std::enable_if_t<std::is_integral_v<IntA>>>
    [[nodiscard]] inline constexpr bool fp_is_valid(IntA a, const bigint<BufferB>& p)
    {
        return detail::fp_is_valid<IntA, bigint<BufferB>>( a, p );
    }

    /**
     * Negates prime finite field element a.
     * The result is -a mod p.
     *
     * @note Expects that a is positive integer and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Big integer buffer type of finite field element.
     * @tparam BufferB - Big integer buffer type of the prime modulus.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return -a mod p.
     */
    template<typename BufferA, typename BufferB>
    [[nodiscard]] inline constexpr bigint<BufferA> fp_neg(const bigint<BufferA>& a, const bigint<BufferB>& p)
    {
        return detail::fp_neg<bigint<BufferA>, bigint<BufferB>>( a, p );
    }

    /**
     * Negates prime finite field element a.
     * The result is -a mod p.
     *
     * @note Expects that a is positive integer and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam IntA - Small integer type of finite field element.
     * @tparam BufferB - Big integer buffer type of the prime modulus.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return -a mod p.
     */
    template<typename IntA, typename BufferB, typename = std::enable_if_t<std::is_integral_v<IntA>>>
    [[nodiscard]] inline constexpr bigint<BufferB> fp_neg(IntA a, const bigint<BufferB>& p)
    {
        return detail::fp_neg<IntA, bigint<BufferB>>( a, p );
    }

    /**
     * Normalizes prime finite field element a.
     *
     * @tparam BufferA - Big integer buffer type of finite field element.
     * @tparam BufferB - Big integer buffer type of the prime modulus.
     *
     * @param a - reference to finite field element.
     * @param p - Prime modulus of the finite field.
    */
    template<typename BufferA, typename BufferB>
    inline constexpr void fp_normalize(bigint<BufferA>& a, const bigint<BufferB>& p)
    {
        detail::fp_normalize<bigint<BufferA>, bigint<BufferB>>( a, p );
    }

    /**
     * Calculates addition of prime finite field elements a and b.
     * The result is a + b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam BufferB - Type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a + b mod p.
    */
    template<typename BufferA, typename BufferB, typename BufferC>
    [[nodiscard]] inline bigint<BufferA> constexpr fp_add(const bigint<BufferA>& a, const bigint<BufferB>& b, const bigint<BufferC>& p)
    {
        return detail::fp_add<bigint<BufferA>, bigint<BufferB>, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates addition of prime finite field elements a and b.
     * The result is a + b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam IntB    - Small integer type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a + b mod p.
    */
    template<typename BufferA, typename IntB, typename BufferC, typename = std::enable_if_t<std::is_integral_v<IntB>>>
    [[nodiscard]] inline bigint<BufferA> constexpr fp_add(const bigint<BufferA>& a, IntB b, const bigint<BufferC>& p)
    {
        return detail::fp_add<bigint<BufferA>, IntB, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates subtraction of prime finite field elements a and b.
     * The result is a - b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam BufferB - Type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a - b mod p.
    */
    template<typename BufferA, typename BufferB, typename BufferC>
    [[nodiscard]] inline bigint<BufferA> fp_sub(const bigint<BufferA>& a, const bigint<BufferB>& b, const bigint<BufferC>& p)
    {
        return detail::fp_sub<bigint<BufferA>, bigint<BufferB>, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates subtraction of prime finite field elements a and b.
     * The result is a - b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam IntB    - Small integer type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a - b mod p.
    */
    template<typename BufferA, typename IntB, typename BufferC, typename = std::enable_if_t<std::is_integral_v<IntB>>>
    [[nodiscard]] inline bigint<BufferA> fp_sub(const bigint<BufferA>& a, IntB b, const bigint<BufferC>& p)
    {
        return detail::fp_sub<bigint<BufferA>, IntB, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates multiplication of prime finite field elements a and b.
     * The result is a * b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam BufferB - Type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a * b mod p.
    */
    template<typename BufferA, typename BufferB, typename BufferC>
    [[nodiscard]] inline bigint<BufferA> fp_mul(const bigint<BufferA>& a, const bigint<BufferB>& b, const bigint<BufferC>& p)
    {
        return detail::fp_mul<bigint<BufferA>, bigint<BufferB>, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates multiplication of prime finite field elements a and b.
     * The result is a * b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam IntB    - Small integer type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a * b mod p.
    */
    template<typename BufferA, typename IntB, typename BufferC, typename = std::enable_if_t<std::is_integral_v<IntB>>>
    [[nodiscard]] inline bigint<BufferA> fp_mul(const bigint<BufferA>& a, IntB b, const bigint<BufferC>& p)
    {
        return detail::fp_mul<bigint<BufferA>, IntB, bigint<BufferC>>( a, b, p );
    }

    /**
     * Calculates square of prime finite field element a.
     * The result is a * a mod p.
     *
     * @note Expects that a is positive integer and less than p.
     *       Out of range values are not checked and will produce wrong results.
     *
     * @tparam BufferA - Type of the finite field element.
     * @tparam BufferB - Type of the prime modulus.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a * a mod p.
    */
    template<typename BufferA, typename BufferB>
    [[nodiscard]] inline bigint<BufferA> fp_sqr(const bigint<BufferA>& a, const bigint<BufferB>& p)
    {
        return fp_mul( a, a, p );
    }

   /**
    * Calculates the modular square root of an integer 'n' modulo odd prime 'p'.
    * The function returns the first root, where r^2 == n (mod p), and not r^2 == -n (mod p).
    * The caller is responsible for verifying if the returned root 'r' satisfies r^2 == n (mod p).
    * If not, the caller should calculate r = p - r to get the correct root.
    *
    * @note This function has an optimization for the case where 'p' == 3 (mod 4).
    *       In this case, the square root is efficiently computed.
    *       If 'p' is not congruent to 3 modulo 4, the function uses a general
    *       Tonelli-Shanks algorithm to find the modular square root.
    *
    * @param n - The integer for which the modular square root is calculated.
    * @param p - The odd prime modulus.
    * @return The first modular square root of 'n' modulo 'p', or 0 if no square root exists.
    *
    */
    template<typename BufferA, typename BufferB>
    [[nodiscard]] inline bigint<BufferA> fp_sqrt(const bigint<BufferA>& n, const bigint<BufferB>& p)
    {
        return detail::fp_sqrt<BufferA, BufferB>( n, p );
    }

    /**
     * Calculates division of prime finite field elements a and b.
     * The result is a / b mod p. Internally it's calculated as (a * b^-1) mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *
     * @tparam BufferA - Type of the first finite field element.
     * @tparam BufferB - Type of the second finite field element.
     * @tparam BufferC - Type of the prime modulus.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a / b mod p.
    */
    template<typename BufferA, typename BufferB, typename BufferC>
    [[nodiscard]] inline bigint<BufferA> fp_div(const bigint<BufferA>& a, const bigint<BufferB>& b, const bigint<BufferC>& p)
    {
        return detail::fp_div<bigint<BufferA>, BufferB, bigint<BufferC>>( a, b, p );
    }

    /**
     * struct represents a finite field element.
     * @tparam BigNumT       - The big number type used to represent the element.
     * @tparam PrimeFieldTag - The tag to distinguish prime field element from other field elements.
    */
    template<typename IntT, typename PrimeFieldTag>
    class fp_element : public field_element<fp_element<IntT, PrimeFieldTag>, IntT, PrimeFieldTag> {
        public:
            using base_type = field_element<fp_element<IntT, PrimeFieldTag>, IntT, PrimeFieldTag>;
            using base_type::base_type;
            using base_type::to_bytes;

            /**
             * Constructs a zero finite field element.
             *@note This instance doesn't have a valid modulus,
             *      so it can't be used for any operations.
             *      The returned instance is invalid and can be used only for comparison.
             *
             * @return Zero finite field element.
            */
            constexpr static fp_element zero()
            {
                return fp_element();
            }

            /**
             * Constructs a finite field element of value 1.
             * @note This instance doesn't have a valid modulus,
             *       so it can't be used for any operations.
             *       The returned instance is invalid and can be used only for comparison.
             *
             * @return Finite field element with value 1.
            */
            constexpr static fp_element one()
            {
                auto one = fp_element();
                one.v_ = 1;
                return one;
            }

            /**
             * Constructs a finite field element.
             * @note Expects that modulus is prime number.
             *
             * @warning modulus is not copied, but referenced.
             *          It is expected that modulus will be valid for the lifetime of the element.
             *
             * @param modulus - Prime modulus of the finite field.
            */
            constexpr fp_element(const IntT& modulus) :
                pm_(&modulus)
            {}

            // Prevents construction from rvalue reference to modulus.
            constexpr fp_element(IntT&& modulus) = delete;

            /**
             * Constructs a finite field element.
             * @note Expects that value is positive integer and less than modulus.
             *       And modulus is prime number.
             *
             * @note The modulus is not copied, but referenced. It is expected that
             *       the modulus will be valid for the lifetime of the element.
             *
             * @param value   - Value of the finite field element.
             * @param modulus - Prime modulus of the finite field. Not checked for primality.
             * @param check   - If true, then the value is checked for validity.
             *                  False by default.
             *
             *                  Note, this check can be performed also after construction
             *                  by calling `is_valid()` method.
            */
            constexpr fp_element(IntT value, const IntT& modulus, bool check = false)
                : v_(std::move(value))
                , pm_(&modulus)
            {
                if ( check ) {
                    ack::check( is_valid(), "invalid value for given modulus" );
                }
            }

            // Prevents construction from rvalue reference to modulus.
            constexpr fp_element(const IntT& value, IntT&& modulus) = delete;

            constexpr fp_element(const fp_element& other) = default;
            constexpr fp_element(fp_element&& other) = default;
            constexpr fp_element& operator=(const fp_element& other) = default;
            constexpr fp_element& operator=(fp_element&& other) = default;

            /**
             * Returns the max element bytes size.
             * @return max element size.
            */
            constexpr std::size_t max_byte_length() const
            {
                if ( !is_valid()) {
                    return 0;
                }
                return ( *pm_ - 1 ).byte_length();
            }

            /**
             * Assigns big integer value to the finite field element.
             * If element is invalid, then it will not be changed.
             *
             * @note Expects that value is positive integer and less than modulus.
             *
             * @param value - Value of the finite field element.
             * @param check - If true, then value is checked to be positive integer and less than modulus.
             *                False by default.
             *
             *                Note, this check can be also performed after assignment via `is_valid()` method
             *
             * @return Reference to this.
            */
            constexpr fp_element& assign(IntT value, bool check = false)
            {
                if ( pm_ == nullptr ) {
                    return *this;
                }

                if ( check ) {
                    ack::check( fp_is_valid( value,  *pm_ ), "invalid value" );
                }

                v_ = std::move( value );
                return *this;
            }

            /**
             * Assigns big integer value to the finite field element.
             * If element is invalid, then it will not be changed.
             *
             * @note Expects that value is positive integer and less than modulus.
             * @note Method doesn't check if the element is valid.
             *       This check can be performed after assignment via `is_valid()` method.
             *
             * @param value - Value of the finite field element.
             *
             * @return Reference to this.
            */
            constexpr fp_element& operator = (IntT value)
            {
                return assign( std::move( value ), /*check=*/ false );
            }

            /**
             * Returns big integer value of the finite field element.
             * @return Value of the finite field element.
            */
            constexpr const IntT& value() const
            {
                return v_;
            }

            /**
             * Casts finite field element to big integer value.
             * @return const reference to big integer value of the finite field element.
            */
            constexpr operator const IntT&() const
            {
                return v_;
            }

            /**
             * Returns modulus of the finite field element.
             * @note Function asserts that modulus is not null.
             * @return Modulus of the finite field element.
            */
            constexpr const IntT& modulus() const
            {
                check( pm_ != nullptr, "modulus is null" );
                return *pm_;
            }

            /**
             * Checks if object has a valid modulus, i.e. it's not nullptr and
             * the value is less than the modulus.
             * @return True if object has a valid modulus, otherwise false.
            */
            constexpr bool is_valid() const
            {
                return pm_ != nullptr && fp_is_valid( v_, *pm_ );
            }

            /**
             * Returns true if the finite field element is zero or modulus is null or modulus is either zero or 1.
             * @return True if the finite field element is zero.
            */
            constexpr bool is_zero() const
            {
                return !v_.is_one()  && ( pm_ == nullptr || pm_->is_zero() || pm_->is_one() || v_.is_zero() );
            }

            /**
             * Returns true if the finite field element is 1.
             * @return True if the finite field element is 1.
            */
            constexpr bool is_one() const
            {
                return v_.is_one();
            }

            /**
             * Returns true if the finite field element is negative.
             * @return True if the finite field element is negative.
            */
            constexpr bool is_negative() const
            {
                return v_.is_negative();
            }

            /**
             * Returns the byte-encoded representation of this object.
             *
             * @param len - The desired length of the byte-encoded representation
             *        The full byte-encoded representation is returned if len is smaller
             *        than the byte length of the original object.
             *
             * @return The byte-encoded representation of this object.
            */
            bytes to_bytes(std::size_t len) const
            {
                bytes ev;
                if ( is_valid() ) {
                    ev = v_.to_bytes();
                    if ( len > ev.size() ) {
                        ev = bytes( len - ev.size(), 0 ) + ev;
                    }
                }
                return ev;
            }

            /**
             * Calculates modular inverse of this finite field element.
             * @return (1 / this) % modulus.
            */
            [[nodiscard]] fp_element inv() const
            {
                return fp_element( v_.modinv( *pm_ ), *pm_ );
            }

            /**
             * Calculates modular addition of this finite field element and another one.
             * @param x - Finite field element to add.
             * @return (this + x) % modulus.
            */
            [[nodiscard]] constexpr fp_element add(const fp_element& x) const
            {
                return add( x.v_ );
            }

            /**
             * Calculates modular addition of this finite field element and big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param x - Big integer to add.
             * @return (this + x) % modulus.
            */
            template<typename BufferT>
            [[nodiscard]]  constexpr fp_element add(const bigint<BufferT>& x) const
            {
                return fp_element( fp_add( v_, x, *pm_), *pm_ );
            }

            /**
             *  Calculates modular addition of this finite field element and integer.
             * @tparam IntU - Small integer type.
             * @param x - Integer to add.
             * @return (this + x) % modulus.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr fp_element add(IntU x) const
            {
                return fp_element( fp_add( v_, x, *pm_), *pm_ );
            }

            /**
             * Calculates modular subtraction of this finite field element and another one.
             * @param x - Finite field element to subtract.
             * @return (this - x) % modulus.
            */
            [[nodiscard]] constexpr fp_element sub(const fp_element& x) const
            {
                return sub( x.v_ );
            }

            /**
             * Calculates modular subtraction of this finite field element and big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param x - Big integer to subtract.
             * @return (this - x) % modulus.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr fp_element sub(const bigint<BufferT>& x) const
            {
                return fp_element( fp_sub( v_, x, *pm_), *pm_ );
            }

            /**
             * Calculates modular subtraction of this finite field element and integer.
             * @tparam IntU - Small integer type.
             * @param x - Integer to subtract.
             * @return (this - x) % modulus.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr fp_element sub(IntU x) const
            {
                return fp_element( fp_sub( v_, x, *pm_), *pm_ );
            }

            /**
             * Calculates modular multiplication of this finite field element and another one.
             * @param x - Finite field element to multiply.
             * @return (this * x) % modulus.
            */
            [[nodiscard]] fp_element mul(const fp_element& x) const
            {
                return mul( x.v_ );
            }

            /**
             * Calculates modular multiplication of this finite field element and big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param x - Big integer to multiply.
             * @return (this * x) % modulus.
            */
            template<typename BufferT>
            [[nodiscard]] fp_element mul(const bigint<BufferT>& x) const
            {
                if ( v_.is_one() ) {
                    return fp_element( x, *pm_ ); // note x can be bigger than modulus
                }
                if ( x.is_one() ) {
                    return *this;
                }
                return fp_element( fp_mul( v_ , x, *pm_ ), *pm_ );
            }

            /**
             * Calculates modular multiplication of this finite field element and integer.
             * @tparam IntU - Small integer type.
             * @param x - Integer to multiply.
             * @return (this * x) % modulus.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] fp_element mul(IntU x) const
            {
                if ( v_.is_one() ) {
                    return fp_element( x, *pm_ ); // note x can be bigger than modulus
                }
                if ( x == 1 ) {
                    return *this;
                }
                return fp_element( fp_mul( v_ , x, *pm_ ), *pm_ );
            }

            /**
             * Calculates modular square of this finite field element.
             * @return (this^2) % modulus.
            */
            [[nodiscard]] fp_element sqr() const
            {
                if ( v_.is_one() ) {
                    return *this;
                }
                return fp_element( fp_sqr( v_, *pm_ ), *pm_ );
            }

            /**
             * Calculates the modular square root of this finite field element.
             * The function returns the first root, where r^2 == n (mod p), and not r^2 == -n (mod p).
             * The caller is responsible for verifying if the returned root 'r' satisfies r^2 == n (mod p).
             * If not, the caller should calculate r = p - r to get the correct root.
             *
             * @return  The first modular square root of this mod modulus, or 0 if no square root exists.
            */
            [[nodiscard]] fp_element sqrt() const
            {
                if ( v_.is_one() ) {
                    return *this;
                }
                return fp_element( fp_sqrt( v_, *pm_ ), *pm_ );
            }

            /**
             * Calculates modular division of this finite field element and another one.
             * @param x - Finite field element to divide.
             * @return (this / x) % modulus.
            */
            [[nodiscard]] fp_element div(const fp_element& x) const
            {
                return div( x.v_ );
            }

            /**
             * Calculates modular division of this finite field element and big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param x - Big integer to divide.
             * @return (this / x) % modulus.
            */
            template<typename BufferT>
            [[nodiscard]] fp_element div(const bigint<BufferT>& x) const
            {
                if ( x.is_one() ) {
                    return *this;
                }
                return fp_element( fp_div( v_, x, *pm_ ), *pm_);
            }

            /**
             * Returns negative of this finite field element.
             * @return (-this) % modulus.
            */
            [[nodiscard]] constexpr fp_element neg() const
            {
                return fp_element( fp_neg( v_, *pm_ ) , *pm_ );
            }

            /**
             * Checks if finite field element is equal to another one.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator == (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ == rhs.v_;
            }

            /**
             * Checks if finite field element is equal to big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is equal to rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator == (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ == rhs;
            }

            /**
             * Checks if finite field element is equal to integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is equal to rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator == (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ == rhs;
            }

            /**
             * Checks if finite field element is not equal to another one.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is not equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator != (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ != rhs.v_;
            }

            /**
             * Checks if finite field element is not equal to big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is not equal to rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator != (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ != rhs;
            }

            /**
             * Checks if finite field element is not equal to integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is not equal to rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator != (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ != rhs;
            }

            /**
             * Checks if finite field element is less
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is less than rhs.
            */
            [[nodiscard]] constexpr friend bool operator < (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ < rhs.v_;
            }

            /**
             * Checks if finite field element is less than big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is less than rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator < (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ < rhs;
            }

            /**
             * Checks if finite field element is less than integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is less than rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator < (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ < rhs;
            }

            /**
             * Checks if finite field element is less or equal to another one.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is less or equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator <= (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ <= rhs.v_;
            }

            /**
             * Checks if finite field element is less or equal to big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is less or equal to rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator <= (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ <= rhs;
            }

            /**
             * Checks if finite field element is less or equal to integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is less or equal to rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator <= (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ <= rhs;
            }

            /**
             * Checks if finite field element is greater
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is greater than rhs.
            */
            [[nodiscard]] constexpr friend bool operator > (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ > rhs.v_;
            }

            /**
             * Checks if finite field element is greater than big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is greater than rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator > (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ > rhs;
            }

            /**
             * Checks if finite field element is greater than integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is greater than rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator > (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ > rhs;
            }

            /**
             * Checks if finite field element is greater or equal to another one.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side finite field element.
             * @return True if lhs is greater or equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator >= (const fp_element& lhs, const fp_element& rhs)
            {
                return lhs.v_ >= rhs.v_;
            }

            /**
             * Checks if finite field element is greater or equal to big integer.
             * @tparam BufferT - Buffer type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is greater or equal to rhs.
            */
            template<typename BufferT>
            [[nodiscard]] constexpr friend bool operator >= (const fp_element& lhs, const bigint<BufferT>& rhs)
            {
                return lhs.v_ >= rhs;
            }

            /**
             * Checks if finite field element is greater or equal to integer.
             * @tparam IntU - Small integer type.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is greater or equal to rhs.
            */
            template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
            [[nodiscard]] constexpr friend bool operator >= (const fp_element& lhs, IntU rhs)
            {
                return lhs.v_ >= rhs;
            }

            /**
             * Prints this element.
             * @note EOSIO helper function.
            */
            void print() const
            {
                v_.print();
            }

        private:
            IntT v_;
            const IntT* pm_ = nullptr;
    };
}
