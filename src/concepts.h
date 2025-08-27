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

#ifndef CONCEPTS_H
#define CONCEPTS_H

#include <ranges>

/// \file
/// \brief Concepts helper functions.

namespace cartesi {

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

// C++20 concept for a (not necessarily contiguous) range of byte-like elements
template <typename D>
concept RangeOfByteLike = std::ranges::range<D> && ByteLike<std::ranges::range_value_t<std::remove_cvref_t<D>>>;

// C++20 concept comparing types while ignoring const, volatile, reference
template <typename T, typename U>
concept SameAsNoCVRef = std::same_as<std::remove_cvref_t<T>, std::remove_cvref_t<U>>;

// C++20 concept to check for scoped enums
template <typename E>
concept ScopedEnum = std::is_enum_v<E> && !std::is_convertible_v<E, std::underlying_type_t<E>>;

// C++20 concept to check for multiple accepted types
template <typename T, typename... Ts>
concept SameAsAny = (std::same_as<T, Ts> || ...);

// C++20 concept to check if a container is back insertable
template <typename T>
concept BackInsertableContainer = std::ranges::range<T> && requires(T container, typename T::value_type value) {
    { container.empty() } -> std::convertible_to<bool>;
    { container.back() } -> std::convertible_to<typename T::reference>;
    container.push_back(value);
};

} // namespace cartesi

#endif
