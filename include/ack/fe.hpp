// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <ack/bigint.hpp>

namespace ack {
    /**
     * CRTP base class for field elements.
    */
    template<typename Derived, typename IntT, typename FieldTagT>
    struct field_element
    {
        using int_type = IntT;

        // Delete constructors and assignment operators from derived class.
        // This is to prevent object slicing.
        constexpr field_element(const Derived& p) = delete;
        constexpr field_element(Derived&& p) noexcept = delete;
        constexpr Derived& operator=(const Derived& p) = delete;
        constexpr Derived& operator=(Derived&& p) noexcept = delete;

        /**
         * Constructs zero element.
         * @return Zero element.
        */
        constexpr static Derived zero()
        {
            return Derived::zero();
        }

        /**
         * Constructs element with value one.
         * @return One element.
        */
        constexpr static Derived one()
        {
            return Derived::one();
        }

        /**
         * Casts this element to big integer.
         * @return const reference to big integer representation of this element.
        */
        constexpr const IntT& value() const
        {
            return underlying().value_;
        }

        /**
         * Casts this element to big integer.
         * @return reference to big integer representation of this element.
        */
        constexpr operator const IntT&() const
        {
            return value();
        }

        /**
         * Checks if this element is zero.
         * @return True if this element is zero, false otherwise.
        */
        constexpr bool is_zero() const
        {
            return underlying().is_zero();
        }

        /**
         * Checks if this element is 1.
         * @return True if this element is 1, false otherwise.
        */
        constexpr bool is_one() const
        {
            return underlying().is_zero();
        }

        /**
         * Checks if this element is negative.
         * @return True if this element is negative, false otherwise.
        */
        constexpr bool is_negative() const
        {
            return underlying().is_negative();
        }

        /**
         * Returns the inverse of this element, i.e. 1 / this.
         * @return Inverse of this element.
        */
        [[nodiscard]] Derived inv() const
        {
            return underlying().inv();
        }

        /**
         * Calculates addition of this element with another.
         * @param x - Element to add.
         * @return R = this + x.
        */
        [[nodiscard]] Derived add(const Derived& x) const
        {
            return underlying().add( x );
        }

        /**
         * Calculates addition of this element with big integer.
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to add.
         * @return R = this + x.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr Derived add(const bigint<BufferT>& x) const
        {
            return underlying().add( x );
        }

        /**
         * Calculates addition of this element with integer.
         * @tparam IntU - Small integer type.
         * @param x - Integer to add.
         * @return R = this + x.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr Derived add(IntU x) const
        {
            return underlying().add( x );
        }

        /**
         * Calculates subtraction of this element with another.
         * @param x - Element to subtract.
         * @return R = this - x.
        */
        [[nodiscard]] constexpr Derived sub(const Derived& x) const
        {
            return underlying().sub( x );
        }

        /**
         * Calculates subtraction of this element with big integer.
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to subtract.
         * @return R = this - x.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr Derived sub(const bigint<BufferT>& x) const
        {
            return underlying().sub( x );
        }

        /**
         * Calculates subtraction of this element with integer.
         * @tparam IntU - Small integer type.
         * @param x - Integer to subtract.
         * @return R = this - x.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr Derived sub(IntU x) const
        {
            return underlying().sub( x );
        }

        /**
         * Calculates multiplication of this element with another.
         * @param x - Element to multiply.
         * @return R = this * x.
        */
        [[nodiscard]] Derived mul(const Derived& x) const
        {
            return underlying().mul( x );
        }

        /**
         * Calculates multiplication of this element with big integer.
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to multiply.
         * @return R = this * x.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr Derived mul(const bigint<BufferT>& x) const
        {
            return underlying().mul( x );
        }

        /**
         * Calculates multiplication of this element with integer.
         * @tparam IntU - Small integer type.
         * @param x - Integer to multiply.
         * @return R = this * x.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr Derived mul(IntU x) const
        {
            return underlying().mul( x );
        }

        /**
         * Calculates square of this element.
         * @return R = this^2.
        */
        [[nodiscard]] Derived sqr() const
        {
            return underlying().sqr();
        }

        /**
         * Calculates square root of this element.
         * @return R = sqrt(this).
        */
        [[nodiscard]] Derived sqrt() const
        {
            return underlying().sqrt();
        }

        /**
         * Calculates division of this element with another.
         * @param x - Element to divide.
         * @return R = this / x.
        */
        [[nodiscard]] Derived div(const Derived& x) const
        {
            return underlying().div( x );
        }

        /**
         * Calculates division of this element with big integer.
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to divide.
         * @return R = this / x.
        */
        template<typename BufferT>
        [[nodiscard]] Derived div(const bigint<BufferT>& x) const
        {
            return underlying().div( x );
        }

        /**
         * Calculates division of this element with integer.
         * @tparam IntU - Small integer type.
         * @param x - Integer to divide.
         * @return R = this / x.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] Derived div(IntU x) const
        {
            return underlying().div( x );
        }

        /**
         * Returns the negation of this element, i.e. -this.
         * @return Negation of this element.
        */
        [[nodiscard]] constexpr Derived neg() const
        {
            return underlying().neg();
        }

        /**
         * Calculates addition of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @return R = a + b.
        */
        [[nodiscard]] constexpr friend Derived operator + (const Derived& a, const Derived& b)
        {
            return a.add( b );
        }

        /**
         * Calculates addition of element a and big integer b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a + b.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr friend Derived operator + (const Derived& a, const bigint<BufferT>& b)
        {
            return a.add( b );
        }

        /**
         * Calculates addition of element a and integer b.
         * @tparam IntU - Small integer type.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a + b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr friend Derived operator + (const Derived& a, IntU b)
        {
            return a.add( b );
        }

        /**
         * Calculates addition of big integer a and element b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a + b.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr friend Derived operator + (const bigint<BufferT>& a, const Derived& b)
        {
            return b.add( a );
        }

        /**
         * Calculates addition of integer a and element b.
         * @tparam IntU - Small integer type.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a + b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr friend Derived operator + (IntU a, const Derived& b)
        {
            return b.add( a );
        }

        /**
         * Calculates subtraction of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @return R = a - b.
        */
        [[nodiscard]] constexpr friend Derived operator - (const Derived& a, const Derived& b)
        {
            return a.sub( b );
        }

        /**
         * Calculates subtraction of element a and big integer b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a - b.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr friend Derived operator - (const Derived& a, const bigint<BufferT>& b)
        {
            return a.sub( b );
        }

        /**
         * Calculates subtraction of element a and integer b.
         * @tparam IntU - Small integer type.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a - b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr friend Derived operator - (const Derived& a, IntU b)
        {
            return a.sub( b );
        }

        /**
         * Calculates subtraction of big integer a and element b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a - b.
        */
        template<typename BufferT>
        [[nodiscard]] constexpr friend Derived operator - (const bigint<BufferT>& a, const Derived& b)
        {
            return b.sub( a );
        }

        /**
         * Calculates subtraction of integer a and element b.
         * @tparam IntU - Small integer type.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a - b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] constexpr friend Derived operator - (IntU a, const Derived& b)
        {
            return b.sub( a );
        }

        /**
         * Calculates multiplication of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @return R = a * b.
        */
        [[nodiscard]] friend Derived operator * (const Derived& a, const Derived& b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of element a and big integer b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a * b.
        */
        template<typename BufferT>
        [[nodiscard]] friend Derived operator * (const Derived& a, const bigint<BufferT>& b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of element a and integer b.
         * @tparam IntU - Small integer type.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a * b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] friend Derived operator * (const Derived& a, IntU b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of big integer a and element b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a * b.
        */
        template<typename BufferT>
        [[nodiscard]] friend Derived operator * (const bigint<BufferT>& a, const Derived& b)
        {
            return b.mul( a );
        }

        /**
         * Calculates multiplication of integer a and element b.
         * @tparam IntU - Small integer type.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a * b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] friend Derived operator * (IntU a, const Derived& b)
        {
            return b.mul( a );
        }

        /**
         * Calculates division of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @return R = a / b.
        */
        [[nodiscard]] friend Derived operator / (const Derived& a, const Derived& b)
        {
            return a.div( b );
        }

        /**
         * Calculates division of element a and big integer b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a / b.
        */
        template<typename BufferT>
        [[nodiscard]] friend Derived operator / (const Derived& a, const bigint<BufferT>& b)
        {
            return a.div( b );
        }

        /**
         * Calculates division of element a and integer b.
         * @tparam IntU - Small integer type.
         * @param a - Element.
         * @param b - Integer.
         * @return R = a / b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] friend Derived operator / (const Derived& a, IntU b)
        {
            return a.div( b );
        }

        /**
         * Calculates division of big integer a and element b.
         * @tparam BufferT - Buffer type of big integer.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a / b.
        */
        template<typename BufferT>
        [[nodiscard]] friend Derived operator / (const bigint<BufferT>& a, const Derived& b)
        {
            return b.div( a );
        }

        /**
         * Calculates division of integer a and element b.
         * @tparam IntU - Small integer type.
         * @param a - Integer.
         * @param b - Element.
         * @return R = a / b.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        [[nodiscard]] friend Derived operator / (IntU a, const Derived& b)
        {
            return b.div( a );
        }

        /**
         * Calculates addition of this element with another element
         * and assigns the result to this element: this = this + x.
         *
         * @param x - Element to add.
         * @return Reference to this element.
        */
        constexpr Derived& operator += (const Derived& x)
        {
            auto& self = underlying();
            self = add( x );
            return self;
        }

        /**
         * Calculates addition of this element with big integer
         * and assigns the result to this element: this = this + x.
         *
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to add.
         * @return Reference to this element.
        */
        template<typename BufferT>
        constexpr Derived& operator += (const bigint<BufferT>& x)
        {
            auto& self = underlying();
            self = add( x );
            return self;
        }

        /**
         * Calculates addition of this element with small integer
         * and assigns the result to this element: this = this + x.
         *
         * @tparam IntU - Small integer type.
         * @param x - Integer to add.
         * @return Reference to this element.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        constexpr Derived& operator += (IntU x)
        {
            auto& self = underlying();
            self = add( x );
            return self;
        }

        /**
         * Calculates subtraction of this element with another element
         * and assigns the result to this element: this = this - x.
         *
         * @param x - Element to subtract.
         * @return Reference to this element.
        */
        constexpr Derived& operator -= (const Derived& x)
        {
            auto& self = underlying();
            self = sub( x );
            return self;
        }

        /**
         * Calculates subtraction of this element with big integer
         * and assigns the result to this element: this = this - x.
         *
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to subtract.
         * @return Reference to this element.
        */
        template<typename BufferT>
        constexpr Derived& operator -= (const bigint<BufferT>& x)
        {
            auto& self = underlying();
            self = sub( x );
            return self;
        }

        /**
         * Calculates subtraction of this element with small integer
         * and assigns the result to this element: this = this - x.
         *
         * @tparam IntU - Small integer type.
         * @param x - Integer to subtract.
         * @return Reference to this element.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        constexpr Derived& operator -= (IntU x)
        {
            auto& self = underlying();
            self = sub( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with another element
         * and assigns the result to this element: this = this * x.
         *
         * @param x - Element to multiply.
         * @return Reference to this element.
        */
        Derived& operator *= (const Derived& x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with big integer
         * and assigns the result to this element: this = this * x.
         *
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to multiply.
         * @return Reference to this element.
        */
        template<typename BufferT>
        Derived& operator *= (const bigint<BufferT>& x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with small integer
         * and assigns the result to this element: this = this * x.
         *
         * @tparam IntU - Small integer type.
         * @param x - Integer to multiply.
         * @return Reference to this element.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        Derived& operator *= (IntU x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates division of this element with another element
         * and assigns the result to this element: this = this / x.
         *
         * @param x - Element to divide.
         * @return Reference to this element.
        */
        Derived& operator /= (const Derived& x)
        {
            auto& self = underlying();
            self = div( x );
            return self;
        }

        /**
         * Calculates division of this element with big integer
         * and assigns the result to this element: this = this / x.
         *
         * @tparam BufferT - Buffer type of big integer.
         * @param x - Integer to divide.
         * @return Reference to this element.
        */
        template<typename BufferT>
        Derived& operator /= (const bigint<BufferT>& x)
        {
            auto& self = underlying();
            self = div( x );
            return self;
        }

        /**
         * Calculates division of this element with small integer
         * and assigns the result to this element: this = this / x.
         *
         * @tparam IntU - Small integer type.
         * @param x - Integer to divide.
         * @return Reference to this element.
        */
        template<typename IntU, typename = std::enable_if_t<std::is_integral_v<IntU>>>
        Derived& operator /= (IntU x)
        {
            auto& self = underlying();
            self = div( x );
            return self;
        }

        /**
         * Returns negation of this element.
         * @return -this.
        */
        [[nodiscard]] constexpr Derived operator - () const
        {
            return neg();
        }

        /**
         * Prints this element.
         * @note EOSIO helper function.
        */
        void print() const
        {
            underlying().print();
        }

        private:
            friend Derived;

            field_element() = default;
            inline constexpr Derived& underlying()
            {
                return static_cast<Derived&>( *this );
            }

            inline constexpr const Derived& underlying() const
            {
                return static_cast<const Derived&>( *this );
            }
    };
}
