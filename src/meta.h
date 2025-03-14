// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef META_H
#define META_H

#include <cstdint>
#include <ranges>
#include <type_traits>

/// \file
/// \brief Meta-programming helper functions.

namespace cartesi {

/// \brief Converts a strongly typed constant to its underlying integer type
template <typename E>
constexpr auto to_underlying(E e) noexcept {
    return static_cast<std::underlying_type_t<E>>(e);
}

namespace detail {
template <template <typename...> class BASE, typename DERIVED>
struct is_template_base_of_helper {
    struct no {};
    struct yes {};
    no operator()(...);
    template <typename... T>
    yes operator()(const BASE<T...> &);
};
} // namespace detail

/// \class is_template_base_of
/// \brief SFINAE test if class is derived from from a base template class.
/// \tparam BASE Base template.
/// \tparam DERIVED Derived class.
template <template <typename...> class BASE, typename DERIVED>
using is_template_base_of = std::integral_constant<bool,
    std::is_same_v<std::invoke_result_t<detail::is_template_base_of_helper<BASE, DERIVED>, const DERIVED &>,
        typename detail::is_template_base_of_helper<BASE, DERIVED>::yes>>;

template <template <typename...> class BASE, typename DERIVED>
constexpr bool is_template_base_of_v = is_template_base_of<BASE, DERIVED>::value;

/// \class log2_size
/// \brief Provides an int member value with the log<sub>2</sub> of size of \p T
/// \param T Type from which the size is needed.
template <typename T>
struct log2_size {};

template <typename T>
constexpr int log2_size_v = log2_size<T>::value;

/// \cond HIDDEN_SYMBOLS

template <>
struct log2_size<uint8_t> {
    static constexpr int value = 0;
};

template <>
struct log2_size<uint16_t> {
    static constexpr int value = 1;
};

template <>
struct log2_size<uint32_t> {
    static constexpr int value = 2;
};

template <>
struct log2_size<uint64_t> {
    static constexpr int value = 3;
};

// helper type for visitor
template <class... Ts>
struct overloads : Ts... {
    using Ts::operator()...;
};

/// \endcond
///
///
///

// C++20 concept for a POD type
template <typename T>
concept POD = std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>;

// C++20 concept for something that is just like a byte
template <typename T>
concept ByteLike = POD<T> && (sizeof(T) == 1);

// C++20 concept for a contiguous range of byte-like elements
template <typename D>
concept ContiguousRangeOfByteLike =
    std::ranges::contiguous_range<D> && ByteLike<std::ranges::range_value_t<std::remove_cvref_t<D>>>;

// C++20 concept comparing types while ignoring const, volatile, reference
template <typename T, typename U>
concept SameAsNoCVRef = std::same_as<std::remove_cvref_t<T>, std::remove_cvref_t<U>>;

// C++20 concept to check for scoped enums
template <typename E>
concept ScopedEnum = std::is_enum_v<E> && !std::is_convertible_v<E, std::underlying_type_t<E>>;

// C++20 concept to check for multiple accepted types
template <typename T, typename... Ts>
concept SameAsAny = (std::same_as<T, Ts> || ...);

namespace views {

/// \brief View that allows a range-based for bind to iterator values, instead of dereferenced values
template <std::ranges::range R>
    requires(std::ranges::borrowed_range<R> || std::is_lvalue_reference_v<R>)
constexpr auto iterators(R &&r) {
    return std::views::iota(r.begin(), r.end());
}

/// \brief View that casts to another type
template <typename T>
constexpr auto cast_to = std::views::transform([](auto x) -> T { return static_cast<T>(x); });

/// \brief Implementation of C++23 slice
template <std::ranges::viewable_range R>
constexpr auto slice(R &&r, std::ranges::range_difference_t<R> from, std::ranges::range_difference_t<R> to) {
    auto count = std::max(to - from, std::ranges::range_difference_t<R>(0));
    return std::forward<R>(r) | std::views::drop(from) | std::views::take(count);
}

} // namespace views

} // namespace cartesi

#endif
