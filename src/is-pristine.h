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

#ifndef IS_PRISTINE_H
#define IS_PRISTINE_H

#include <cstddef>
#include <cstdint>
#include <ranges>

#include "concepts.h"
#include "meta.h"

namespace cartesi {

/// \brief This is an optimized function for checking if memory page is pristine.
/// \param data Memory pointer
/// \param length Memory length
/// \returns True if all values are 0, false otherwise
/// \details It's to be used in situations where length is equal or less than a page size.
static inline bool is_pristine(const unsigned char *data, size_t length) {
    // This tight for loop has no branches, and is optimized to SIMD instructions in x86_64,
    // making it very fast to check if a given page is pristine.
    unsigned char bits = 0;
    for (size_t i = 0; i < length; ++i) {
        bits |= data[i];
    }
    return bits == 0;
}

/// \brief This is an optimized function for checking if memory page is pristine.
/// \param r Contiguous range of byte-like values
/// \returns True if all values are 0, false otherwise
/// \details It's to be used in situations where length is equal or less than a page size.
template <ContiguousRangeOfByteLike R>
static inline bool is_pristine(R &&r) { // NOLINT(cppcoreguidelines-missing-std-forward)
    std::ranges::range_value_t<R> bits{0};
    for (auto b : r) {
        bits |= b;
    }
    return bits == 0;
}

} // namespace cartesi

#endif
