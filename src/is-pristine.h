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

#include "compiler-defines.h"

#include <bit>
#include <cstddef>
#include <cstdint>

// NOLINTBEGIN(clang-diagnostic-unknown-pragmas)

namespace cartesi {

/// \brief This is an optimized function for checking if memory page is pristine.
/// \param data Memory pointer
/// \param length Memory length
/// \returns True if the page is pristine, false otherwise.
/// \details It's instead to be used in situations where length is equal or less than a page size.
static inline bool is_pristine(const unsigned char *data, size_t length) noexcept {
    // This tight for loop has no branches, and is optimized to SIMD instructions,
    // making it very fast to check if a given page is pristine.
    unsigned char bits = 0;
#ifdef __GNUC__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < length; ++i) {
        bits |= data[i];
    }
    return bits == 0;
}

/// \brief This is an optimized function for checking if memory aligned page is pristine.
/// \tparam ALIGNED_PAGE_SIZE Memory page size.
/// \param data Memory pointer, must be aligned to ALIGNED_PAGE_SIZE and of size ALIGNED_PAGE_SIZE.
/// \returns True if the page is pristine, false otherwise.
template <size_t ALIGNED_PAGE_SIZE>
static inline bool is_aligned_page_pristine(const unsigned char *data) noexcept {
    static_assert(ALIGNED_PAGE_SIZE % sizeof(uint64_t) == 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *aligned_data = reinterpret_cast<const uint64_t *>(__builtin_assume_aligned(data, ALIGNED_PAGE_SIZE));
    // This tight for loop has no branches, and is optimized to used SIMD instructions,
    // making it very fast to check if a given page is pristine.
    uint64_t bits = 0;
#ifdef __GNUC__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < ALIGNED_PAGE_SIZE / sizeof(uint64_t); ++i) {
        bits |= aligned_data[i];
    }
    return bits == 0;
}

} // namespace cartesi

// NOLINTEND(clang-diagnostic-unknown-pragmas)

#endif
