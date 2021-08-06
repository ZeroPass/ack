// Copyright © 2021 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros

#pragma once
#include <array>
#include <type_traits>
#include <vector>

namespace eosiock {
    template <typename T>
    using uncvref_t =
        typename std::remove_cv<typename std::remove_reference<T>::type>::type;

    template <typename, typename = void>
    struct has_size_and_data : std::false_type {};

    template <typename T>
    struct has_size_and_data<T, std::void_t<decltype(std::size(std::declval<T>())),
                                    decltype(std::data(std::declval<T>()))>>
        : std::true_type {};

    template <typename T>
    constexpr bool has_size_and_data_v = has_size_and_data<T>::value;

    template <typename ElementType>
    class span;

    template <typename>
    struct is_span : std::false_type {};

    template <typename T>
    struct is_span<span<T>> : std::true_type {};

    template <typename T>
    constexpr bool is_span_v = is_span<T>::value;

    template <typename>
    struct is_std_array : std::false_type {};

    template <typename T, std::size_t N>
    struct is_std_array<std::array<T, N>> : std::true_type {};

    template <typename T>
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename C, typename U = uncvref_t<C>>
    struct is_container {
        static constexpr bool value =
            !is_span_v<U> && !is_std_array_v<U> &&
            !std::is_array_v<U> && has_size_and_data_v<C>;
    };

    template <typename C, typename U = uncvref_t<C>>
    constexpr bool is_container_v = is_container<C, U>::value;
}