// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/bigint.hpp>
#include <ack/fe.hpp>
#include <ack/utils.hpp>

namespace ack {

    /** Checks if finite field element a is valid.
     * i.e.: a >= 0 and a < p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return true if a is valid finite field element, false otherwise.
     */
    template<typename BigNumT>
    [[nodiscard]] inline constexpr bool fp_is_valid(const BigNumT& a, const BigNumT& p)
    {
        return ( a >= 0 ) && ( a < p );
    }

    /**
     * Negates prime finite field element a.
     * The result is -a mod p.
     *
     * @note Expects that a is positive integer and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return -a mod p.
     */
    template<typename BigNumT>
    [[nodiscard]] inline constexpr BigNumT fp_neg(const BigNumT& a, const BigNumT& p)
    {
        return p - a;
    }

    /**
     * Calculates addition of prime finite field elements a and b.
     * The result is a + b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a + b mod p.
    */
    template<typename BigNumT>
    [[nodiscard]] inline BigNumT constexpr fp_add(const BigNumT& a, const BigNumT& b, const BigNumT& p)
    {
        BigNumT res = a + b;
        if ( res >= p ) {
            res -= p;
        }
        return res;
    }

    /**
     * Calculates subtraction of prime finite field elements a and b.
     * The result is a - b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a - b mod p.
    */
    template<typename BigNumT>
    [[nodiscard]] inline constexpr BigNumT fp_sub(const BigNumT& a, const BigNumT& b, const BigNumT& p)
    {
        BigNumT res = a - b;
        if ( res.is_negative() ) {
            res += p;
        }
        return res;
    }

    /**
     * Calculates multiplication of prime finite field elements a and b.
     * The result is a * b mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a * b mod p.
    */
    template<typename BigNumT>
    [[nodiscard]] inline BigNumT fp_mul(const BigNumT& a, const BigNumT& b, const BigNumT& p)
    {
        return (a * b) % p;
    }

    /**
     * Calculates multiplication of prime finite field element a and word b.
     * The result is a * b mod p.
     *
     * @note Expects that a is positive integer and a & b are less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - Finite field element.
     * @param b - Finite field element.
     * @param p - Prime modulus of the finite field.
    */
    template<typename BigNumT>
    [[nodiscard]] inline BigNumT fp_mul(const BigNumT& a, const word_t b, const BigNumT& p)
    {
        return (a * b) % p;
    }

    /**
     * Calculates square of prime finite field element a.
     * The result is a * a mod p.
     *
     * @note Expects that a is positive integer and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - Finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a * a mod p.
    */
    template<typename BigNumT>
    [[maybe_unused]] inline BigNumT fp_sqr(const BigNumT& a, const BigNumT& p)
    {
        return fp_mul( a, a, p );
    }

    /**
     * Calculates division of prime finite field elements a and b.
     * The result is a / b mod p. Internally it's calculated as (a * b^-1) mod p.
     *
     * @note Expects that a, b are positive integers and less than p.
     *
     * @tparam BigNumT Type of the finite field element.
     *
     * @param a - First finite field element.
     * @param b - Second finite field element.
     * @param p - Prime modulus of the finite field.
     * @return a / b mod p.
    */
    template<typename BigNumT>
    [[maybe_unused]] inline BigNumT fp_div(const BigNumT& a, const BigNumT& b, const BigNumT& p)
    {
        return (a * b.mod_inv(p)) % p;
    }


    /**
     * struct represents a finite field element.
     * @tparam BigNumT       - The big number type used to represent the element.
     * @tparam PrimeFieldTag - The tag to distinguish prime field element from other field elements.
     */
    template<typename BigNumT, typename PrimeFieldTag>
    class fp_element : public field_element<fp_element<BigNumT, PrimeFieldTag>, BigNumT, PrimeFieldTag> {
        public:
            using base_type = field_element<fp_element<BigNumT, PrimeFieldTag>, BigNumT, PrimeFieldTag>;
            using base_type::base_type;

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
             * Constructs a one finite field element.
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
            constexpr fp_element(const BigNumT& modulus) :
                pm_(&modulus)
            {}

            // Prevents construction from rvalue reference to modulus.
            constexpr fp_element(BigNumT&& modulus) = delete;

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

            constexpr fp_element(BigNumT value, const BigNumT& modulus, bool check = false)
                : v_(std::move(value))
                , pm_(&modulus)
            {
                if ( check ) {
                    ack::check( is_valid(), "value is not valid for the given modulus" );
                }
            }

            // Prevents construction from rvalue reference to modulus.
            constexpr fp_element(const BigNumT& value, BigNumT&& modulus) = delete;

            constexpr fp_element(const fp_element& other) = default;
            constexpr fp_element(fp_element&& other) = default;
            constexpr fp_element& operator=(const fp_element& other) = default;
            constexpr fp_element& operator=(fp_element&& other) = default;

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
            constexpr fp_element& assign(BigNumT value, bool check = false)
            {
                if (pm_ == nullptr) {
                    return *this;
                }

                if (check) {
                    check( fp_is_valid( value,  *pm_ ), "Value is not valid." );
                }

                v_ = std::move(value);
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
            constexpr fp_element& operator=(BigNumT value)
            {
                if (pm_ == nullptr) {
                    return *this;
                }

                v_ = std::move( value );
                return *this;
            }

            /**
             * Returns big integer value of the finite field element.
             * @return Value of the finite field element.
             */
            constexpr const BigNumT& value() const
            {
                return v_;
            }

            /**
             * Casts finite field element to big integer value.
             * @return const reference to big integer value of the finite field element.
            */
            constexpr operator const BigNumT&() const
            {
                return v_;
            }

            /**
             * Returns modulus of the finite field element.
             * @note Function asserts that modulus is not null.
             * @return Modulus of the finite field element.
             */
            constexpr const BigNumT& modulus() const
            {
                check( pm_ != nullptr, "Modulus is null." );
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
             * Returns true if the finite field element is zero or modulus is null.
             * @return True if the finite field element is zero.
             */
            constexpr bool is_zero() const
            {
                return pm_ == nullptr || pm_->is_zero() || v_.is_zero();
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
             * Calculates modular inverse of this finite field element.
             * @return (1 / this) % modulus.
            */
            [[nodiscard]] fp_element inv() const
            {
                return fp_element( v_.mod_inv( *pm_ ), *pm_ );
            }

            /**
             * Calculate modular addition of this finite field element and another one.
             * @param x - Finite field element to add.
             * @return (this + x) % modulus.
            */
            [[nodiscard]] constexpr fp_element add(const fp_element& x) const
            {
                return add( x.v_ );
            }

            /**
             * Calculate modular addition of this finite field element and big integer.
             * @tparam BigNumU - Type of big integer.
             * @param x - Big integer to add.
             * @return (this + x) % modulus.
            */
            template<typename BigNumU>
            [[nodiscard]]  constexpr fp_element add(const BigNumU& x) const
            {
                return fp_element( fp_add( v_, x, *pm_), *pm_ );
            }

            /**
             * Calculate modular subtraction of this finite field element and another one.
             * @param x - Finite field element to subtract.
             * @return (this - x) % modulus.
            */
            [[nodiscard]] constexpr fp_element sub(const fp_element& x) const
            {
                return sub( x.v_ );
            }

            /**
             * Calculate modular subtraction of this finite field element and big integer.
             * @tparam BigNumU - Type of big integer.
             * @param x - Big integer to subtract.
             * @return (this - x) % modulus.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr fp_element sub(const BigNumU& x) const
            {
                return fp_element( fp_sub( v_, x, *pm_), *pm_ );
            }

            /**
             * Calculate modular multiplication of this finite field element and another one.
             * @param x - Finite field element to multiply.
             * @return (this * x) % modulus.
            */
            [[nodiscard]] fp_element mul(const fp_element& x) const
            {
                return mul( x.v_ );
            }

            /**
             * Calculate modular multiplication of this finite field element and big integer.
             * @tparam BigNumU - Type of big integer.
             * @param x - Big integer to multiply.
             * @return (this * x) % modulus.
            */
            template<typename BigNumU>
            [[nodiscard]] fp_element mul(const BigNumU& x) const
            {
                return fp_element( fp_mul( v_ , x, *pm_ ), *pm_ );
            }

            /**
             * Calculate modular multiplication of this finite field element and word.
             * @param x - Word to multiply.
             * @return (this * x) % modulus.
            */
            [[nodiscard]] fp_element mul(word_t x) const
            {
                return fp_element( fp_mul( v_ , x, *pm_ ), *pm_ );
            }

            /**
             * Calculate modular square of this finite field element.
             * @return (this^2) % modulus.
            */
            [[nodiscard]] fp_element sqr() const
            {
                return fp_element( fp_sqr( v_, *pm_ ), *pm_ );
            }

            /**
             * Calculate modular division of this finite field element and another one.
             * @param x - Finite field element to divide.
             * @return (this / x) % modulus.
            */
            [[nodiscard]] fp_element div(const fp_element& x) const
            {
                return div( x.v_ );
            }

            /**
             * Calculate modular division of this finite field element and big integer.
             * @tparam BigNumU - Type of big integer.
             * @param x - Big integer to divide.
             * @return (this / x) % modulus.
            */
            template<typename BigNumU>
            [[nodiscard]] fp_element div(const BigNumU& x) const
            {
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is equal to rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator == (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ == rhs;
            }

            /**
             * Checks if finite field element is equal to word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator == (const fp_element& lhs, word_t rhs)
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is not equal to rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator != (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ != rhs;
            }

            /**
             * Checks if finite field element is not equal to word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is not equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator != (const fp_element& lhs, word_t rhs)
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is less than rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator < (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ < rhs;
            }

            /**
             * Checks if finite field element is less than word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is less than rhs.
            */
            [[nodiscard]] constexpr friend bool operator < (const fp_element& lhs, word_t rhs)
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is less or equal to rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator <= (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ <= rhs;
            }

            /**
             * Checks if finite field element is less or equal to word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is less or equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator <= (const fp_element& lhs, word_t rhs)
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is greater than rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator > (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ > rhs;
            }

            /**
             * Checks if finite field element is greater than word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is greater than rhs.
            */
            [[nodiscard]] constexpr friend bool operator > (const fp_element& lhs, word_t rhs)
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
             * @tparam BigNumU - Type of big integer.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side big integer.
             * @return True if lhs is greater or equal to rhs.
            */
            template<typename BigNumU>
            [[nodiscard]] constexpr friend bool operator >= (const fp_element& lhs, const BigNumU& rhs)
            {
                return lhs.v_ >= rhs;
            }

            /**
             * Checks if finite field element is greater or equal to word.
             * @param lhs - Left hand side finite field element.
             * @param rhs - Right hand side word.
             * @return True if lhs is greater or equal to rhs.
            */
            [[nodiscard]] constexpr friend bool operator >= (const fp_element& lhs, word_t rhs)
            {
                return lhs.v_ >= rhs;
            }

            /**
             * Prints this element. EOSIO helper function.
            */
            void print() const
            {
                v_.print();
            }

        private:
            BigNumT v_;
            const BigNumT* pm_ = nullptr;
    };
}