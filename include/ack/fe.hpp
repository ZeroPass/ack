// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once

namespace ack {
    /**
     * CRTP base class for field elements.
    */
    template<typename Derived, typename BigNumT, typename FieldTagT>
    struct field_element
    {
        using bignum_type = BigNumT;

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
        constexpr const BigNumT& value() const
        {
            return underlying().value_;
        }

        /**
         * Casts this element to big integer.
         * @return reference to big integer representation of this element.
        */
        constexpr operator const BigNumT&() const
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
         * @param R = this + x.
        */
        [[nodiscard]] Derived add(const Derived& x) const
        {
            return underlying().add( x );
        }

        /**
         * Calculates addition of this element with big integer.
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to add.
         * @param R = this + x.
        */
        template<typename BigNumU>
        [[nodiscard]] constexpr Derived add(const BigNumU& x) const
        {
            return underlying().add( x );
        }

        /**
         * Calculates subtraction of this element with another.
         * @param x - Element to subtract.
         * @param R = this - x.
        */
        [[nodiscard]] constexpr Derived sub(const Derived& x) const
        {
            return underlying().sub( x );
        }

        /**
         * Calculates subtraction of this element with big integer.
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to subtract.
         * @param R = this - x.
        */
        template<typename BigNumU>
        [[nodiscard]] constexpr Derived sub(const BigNumU& x) const
        {
            return underlying().sub( x );
        }

        /**
         * Calculates multiplication of this element with another.
         * @param x - Element to multiply.
         * @param R = this * x.
        */
        [[nodiscard]] Derived mul(const Derived& x) const
        {
            return underlying().mul( x );
        }

        /**
         * Calculates multiplication of this element with big integer.
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to multiply.
         * @param R = this * x.
        */
        template<typename BigNumU>
        [[nodiscard]] Derived mul(const BigNumU& x) const
        {
            return underlying().mul( x );
        }

        /**
         * Calculates multiplication of this element with word.
         * @param x - Word to multiply.
         * @param R = this * x.
        */
        [[nodiscard]] Derived mul(word_t x) const
        {
            return underlying().mul( x );
        }

         /**
         * Calculates square of this element.
         * @param R = this^2.
        */
        [[nodiscard]] Derived sqr() const
        {
            return underlying().sqr();
        }

        /**
         * Calculates division of this element with another.
         * @param x - Element to divide.
         * @param R = this / x.
        */
        [[nodiscard]] Derived div(const Derived& x) const
        {
            return underlying().div( x );
        }

        /**
         * Calculates division of this element with big integer.
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to divide.
        */
        template<typename BigNumU>
        [[nodiscard]] Derived div(const BigNumU& x) const
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
         * @param R = a + b.
        */
        [[nodiscard]] constexpr friend Derived operator + (const Derived& a, const Derived& b)
        {
            return a.add( b );
        }

        /**
         * Calculates addition of element a and big integer b.
         * @tparam BigNumU - Type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @param R = a + b.
        */
        template<typename BigNumU>
        [[nodiscard]] constexpr friend Derived operator + (const Derived& a, const BigNumU& b)
        {
            return a.add( b );
        }

        /**
         * Calculates subtraction of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @param R = a - b.
        */
        [[nodiscard]] constexpr friend Derived operator - (const Derived& a, const Derived& b)
        {
            return a.sub( b );
        }

        /**
         * Calculates subtraction of element a and big integer b.
         * @tparam BigNumU - Type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @param R = a - b.
        */
        template<typename BigNumU>
        [[nodiscard]] constexpr friend Derived operator - (const Derived& a, const BigNumU& b)
        {
            return a.sub( b );
        }

        /**
         * Calculates multiplication of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @param R = a * b.
        */
        [[nodiscard]] friend Derived operator * (const Derived& a, const Derived& b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of element a and big integer b.
         * @tparam BigNumU - Type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @param R = a * b.
        */
        template<typename BigNumU, typename = std::enable_if< !std::is_same_v<BigNumU, Derived> >>
        [[nodiscard]] friend Derived operator * (const Derived& a, const BigNumU& b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of element a and big integer b.
         * @tparam BigNumU - Type of big integer.
         * @param a - Integer.
         * @param b - Element.
         * @param R = a * b.
        */
        template<typename BigNumU, typename = std::enable_if< !std::is_same_v<BigNumU, Derived> >>
        [[nodiscard]] friend Derived operator * (const BigNumU& a, const Derived& b)
        {
            return b.mul( a );
        }

        /**
         * Calculates multiplication of element a and word b.
         * @param a - Element.
         * @param b - Word.
         * @param R = a * b.
        */
        [[nodiscard]] friend Derived operator * (const Derived& a, word_t b)
        {
            return a.mul( b );
        }

        /**
         * Calculates multiplication of element a and word b.
         * @param a - Word.
         * @param b - Element.
         * @param R = a * b.
        */
        [[nodiscard]] friend Derived operator * (word_t a, const Derived& b )
        {
            return b.mul( a );
        }

        /**
         * Calculates division of elements a and b.
         * @param a - First element.
         * @param b - Second element.
         * @param R = a / b.
        */
        [[nodiscard]] friend Derived operator / (const Derived& a, const Derived& b)
        {
            return a.div( b );
        }

        /**
         * Calculates division of element a and big integer b.
         * @tparam BigNumU - Type of big integer.
         * @param a - Element.
         * @param b - Integer.
         * @param R = a / b.
        */
        template<typename BigNumU>
        [[nodiscard]] friend Derived operator / (const Derived& a, const BigNumU& b)
        {
            return a.div( b );
        }

        /**
         * Calculates addition of this element with another element
         * and assigns the result to this element.
         *
         * @param x - Element to add.
         * @param this = this + x.
        */
        constexpr Derived& operator += (const Derived& x)
        {
            auto& self = underlying();
            self = add( x );
            return self;
        }

        /**
         * Calculates addition of this element with big integer
         * and assigns the result to this element.
         *
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to add.
         * @param this = this + x.
        */
        template<typename BigNumU>
        constexpr Derived& operator += (const BigNumU& x)
        {
            auto& self = underlying();
            self = add( x );
            return self;
        }

        /**
         * Calculates subtraction of this element with another element
         * and assigns the result to this element.
         *
         * @param x - Element to subtract.
         * @param this = this - x.
        */
        constexpr Derived& operator -= (const Derived& x)
        {
            auto& self = underlying();
            self = sub( x );
            return self;
        }

        /**
         * Calculates subtraction of this element with big integer
         * and assigns the result to this element.
         *
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to subtract.
         * @param this = this - x.
         * @return Reference to this element.
        */
        template<typename BigNumU>
        constexpr Derived& operator -= (const BigNumU& x)
        {
            auto& self = underlying();
            self = sub( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with another element
         * and assigns the result to this element.
         *
         * @param x - Element to multiply.
         * @param this = this * x.
        */
        Derived& operator *= (const Derived& x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with big integer
         * and assigns the result to this element.
         *
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to multiply.
         * @param this = this * x.
        */
        template<typename BigNumU>
        Derived& operator *= (const BigNumU& x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates multiplication of this element with word
         * and assigns the result to this element.
         *
         * @param x - Word to multiply.
         * @param this = this * x.
        */
        Derived& operator *= (word_t x)
        {
            auto& self = underlying();
            self = mul( x );
            return self;
        }

        /**
         * Calculates division of this element with another element
         * and assigns the result to this element.
         *
         * @param x - Element to divide.
         * @param this = this / x.
        */
        Derived& operator /= (const Derived& x)
        {
            auto& self = underlying();
            self = div( x );
            return self;
        }

        /**
         * Calculates division of this element with big integer
         * and assigns the result to this element.
         *
         * @tparam BigNumU - Type of big integer.
         * @param x - Integer to divide.
         * @param this = this / x.
        */
        template<typename BigNumU>
        Derived& operator /= (const BigNumU& x)
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
         * Prints this element. EOSIO helper function.
        */
        void print() const
        {
            underlying().print();
        }

        private:
            friend Derived;

            field_element() = default;
            constexpr inline Derived& underlying()
            {
                return static_cast<Derived&>( *this );
            }

            constexpr inline const Derived& underlying() const
            {
                return static_cast<const Derived&>( *this );
            }
    };
}