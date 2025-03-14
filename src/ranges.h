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

#ifndef RANGES_H
#define RANGES_H

#include <ranges>

/// \file
/// \brief Range helper functions.

namespace cartesi::views {

/// \brief View that allows a range-based for bind to iterator values, instead of dereferenced values
template <std::ranges::range R>
    requires(std::ranges::borrowed_range<R> || std::is_lvalue_reference_v<R>)
constexpr auto iterators(R &&r) { // NOLINT(cppcoreguidelines-missing-std-forward)
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

} // namespace cartesi::views

#endif
