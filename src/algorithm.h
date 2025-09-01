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

#ifndef ALGORITHM_H
#define ALGORITHM_H

#include <concepts>
#include <limits>
#include <type_traits>

#include "concepts.h"

namespace cartesi {

/// \brief Adds new entry to back of container, if not already there
/// \tparam Container Container type
/// \tparam T Value type
/// \param container Container to push back into
/// \param value Value to push back
template <typename Container, typename T>
    requires BackInsertableWith<Container, T>
constexpr void try_push_back(Container &container, T &&value) {
    if (container.empty() || container.back() != value) {
        container.push_back(std::forward<T>(value));
    }
}

/// \brief Performs saturating addition of two unsigned integers
/// \tparam T Unsigned integer type
/// \param a First addend
/// \param b Second addend
/// \param max Maximum value of T (default: std::numeric_limits<T>::max())
/// \returns The sum of a and b, or the maximum value of T if overflow occurs
template <typename T>
    requires std::is_unsigned_v<T>
static constexpr T saturating_add(T a, T b, T max = std::numeric_limits<T>::max()) noexcept {
    if (b > max || a > max - b) [[unlikely]] {
        return max;
    }
    return a + b;
}

} // namespace cartesi

#endif
