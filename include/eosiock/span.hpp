// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>

#include <eosio/eosio.hpp>

#include "type_traits.hpp"

namespace eosiock {
    //!< @note When c++20 is supported, use std::span
    template <typename T>
    class span {
    public:
        constexpr span() noexcept = default;
        template <class It>
        constexpr span( It first, It last ) {
            pFirst = &(*first);
            size_  = abs(std::distance(first, last));
        }

        template <class It>
        constexpr span( It first, size_t size ) {
            pFirst = &(*first);
            size_  = size;
        }

        template <std::size_t N>
        span(T (&arr)[N] ) noexcept {
            pFirst = &arr;
            size_  = N;
        }

        template <class U, std::size_t N >
        constexpr span( std::array<U, N>& arr ) noexcept {
            pFirst = arr.data();
            size_  = arr.size();
        }

        template <class U, std::size_t N>
        constexpr span( const std::array<U, N>& arr ) noexcept {
            pFirst = arr.data();
            size_  = arr.size();
        }

        template <class Container,
            typename std::enable_if<is_container_v<Container>, int>::type = 0>
        constexpr span( Container&& c ) noexcept {
            pFirst = std::data(c);
            size_  = std::size(c);
        }

        constexpr span( const span& other ) noexcept = default;

        constexpr  T* begin() const noexcept {
            return pFirst;
        }

        constexpr  T* end() const noexcept {
            return pFirst + size_;
        }

        constexpr bool empty() const noexcept {
            return size_ == 0 || pFirst == nullptr;
        }

        constexpr T* data() const noexcept {
            return pFirst;
        }

        constexpr size_t size() const noexcept {
            return size_;
        }

        constexpr T& operator[]( size_t idx ) const {
            eosio::check( idx < size_, "span idx is out of range" );
            return pFirst[idx];
        }

        constexpr span<T> subspan( size_t idx, size_t count = std::numeric_limits<std::size_t>::max() ) const {
            eosio::check( idx < size_ &&
                 ( count == std::numeric_limits<std::size_t>::max() || idx + count <= size_ ),
                 "subspan out of range"
            );

            count = std::min( count,  size_ - idx );
            return span( &pFirst[idx], count );
        }

    private:
        T* pFirst = nullptr;
        size_t size_ = 0;
        template<typename U>
        friend bool operator == (const span<U>&, const span<U>&);
    };

    template <typename T>
    inline bool operator == (const span<T>& lhs, const span<T>& rhs) {
        if ( lhs.pFirst == rhs.pFirst ) {
            return lhs.size_ == rhs.size_;
        }
        return std::equal(
            std::begin(lhs), std::end(lhs),
            std::begin(rhs), std::end(rhs)
        );
    }

    template <typename T, typename U>
    inline bool operator == (const span<T>& lhs, const U& rhs) {
        return lhs == span<T>{ rhs };
    }

    template <typename T, typename U>
    inline bool operator == (const U& lhs, const span<T>& rhs) {
        return span<T>{ lhs } == rhs;
    }

    template <typename T>
    inline bool operator != (const span<T>& lhs, const span<T>& rhs) {
        return !( lhs == rhs );
    }

    template <typename T, typename U>
    inline bool operator != (const span<T>& lhs, const U& rhs) {
        return lhs != span<T>{ rhs };
    }

     template <typename T, typename U>
    inline bool operator != (const U& lhs, const span<T>& rhs) {
        return !( lhs == rhs );
    }
}