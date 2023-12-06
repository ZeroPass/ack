// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <cstdint>
#include <type_traits>

#include <ack/types.hpp>
#include <ack/type_traits.hpp>
#include <ack/utils.hpp>

namespace ack {

    // TODO: Replace std::enable_if_t with concepts when clang 10 is supported
    template<typename Derived, typename ValueType, typename = std::enable_if_t<std::is_integral_v<ValueType>>>
    class buffer_base {
        public:
            using value_type = ValueType;
            using derived_type = Derived;

            constexpr bool alloc(size_t n)
            {
                return static_cast<derived_type&>(*this).alloc(n);
            }

            constexpr void clear()
            {
                static_cast<derived_type&>(*this).clear();
            }

            constexpr value_type* data()
            {
                return static_cast<derived_type&>(*this).data();
            }

            constexpr const value_type* data() const
            {
                return static_cast<const derived_type&>(*this).data();
            }

            constexpr std::size_t size() const
            {
                return static_cast<const derived_type&>(*this).size();
            }

            constexpr std::size_t max_size() const
            {
                return static_cast<const derived_type&>(*this).max_size();
            }

            constexpr const value_type& operator[](size_t n) const
            {
                return static_cast<const derived_type&>(*this).operator[](n);
            }

            constexpr value_type& operator[](size_t n)
            {
                return static_cast<derived_type&>(*this).operator[](n);
            }

        private:
            buffer_base() = default;
            friend derived_type;
    };

    template<typename T, std::size_t N>
    class fixed_buffer : public buffer_base<fixed_buffer<T, N>, T> {
        public:
            using value_type = T;

            constexpr fixed_buffer() = default;
            constexpr fixed_buffer(const fixed_buffer& rhs) = default;
            constexpr fixed_buffer(fixed_buffer&& rhs) = default;
            constexpr fixed_buffer& operator=(const fixed_buffer& rhs) = default;
            constexpr fixed_buffer& operator=(fixed_buffer&& rhs) = default;

            constexpr bool alloc(size_t n)
            {
                if ( n > N ) {
                    return false;
                }
                size_ = n;
                return true;
            }

            constexpr void clear()
            {
                size_ = 0;
            }

            constexpr T* data()
            {
                return data_.data();
            }

            constexpr const T* data() const
            {
                return data_.data();
            }

            constexpr std::size_t size() const
            {
                return size_;
            }

            constexpr std::size_t max_size() const
            {
                return N;
            }

            constexpr void swap(fixed_buffer& rhs)
            {
                std::swap( data_, rhs.data_ );
                std::swap( size_, rhs.size_ );
            }

            constexpr const T& operator[](size_t n) const
            {
                check( n < size_, "fixed_buffer:operator[]: overflow" );
                return data_[n];
            }

            constexpr T& operator[](size_t n)
            {
                check( n < size_, "fixed_buffer:operator[]: overflow" );
                return data_[n];
            }

        private:
            std::array<T, N> data_ = {};
            std::size_t size_ = 0;
    };

    template<std::size_t N>
    using fixed_word_buffer = fixed_buffer<word_t, N>;
}