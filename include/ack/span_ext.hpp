// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <iterator>
#include <span>

#include <ack/type_traits.hpp>
#include <ack/types.hpp>
#include <ack/utils.hpp>

namespace ack {
    template <typename T>
    inline constexpr bool operator == (const std::span<T> lhs, const std::span<T> rhs) {
        if ( lhs.data() == rhs.data() ) {
            return lhs.size() == rhs.size();
        }
        return std::equal(
            std::begin(lhs), std::end(lhs),
            std::begin(rhs), std::end(rhs)
        );
    }

    template <typename T, typename U>
    inline constexpr bool operator == (const std::span<T> lhs, const U& rhs) {
        return lhs == std::span<T>{ rhs };
    }

    template <typename T, typename U>
    inline constexpr bool operator == (const U& lhs, const std::span<T> rhs) {
        return std::span<T>{ lhs } == rhs;
    }

    template <typename T>
    inline constexpr bool operator != (const std::span<T> lhs, const std::span<T> rhs) {
        return !( lhs == rhs );
    }

    template <typename T, typename U>
    inline constexpr bool operator != (const std::span<T> lhs, const U& rhs) {
        return lhs != std::span<T>{ rhs };
    }

    template <typename T, typename U>
    inline bool operator != (const U& lhs, const std::span<T> rhs) {
        return !( lhs == rhs );
    }
}