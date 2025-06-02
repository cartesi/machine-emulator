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

#include "is-pristine.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "address-range-constants.h"
#include "compiler-defines.h"

namespace cartesi {

template <size_t Extent>
FORCE_INLINE static bool is_pristine_impl(std::span<const unsigned char, Extent> data) noexcept {
    unsigned char bits = 0;
    // GCC and Clang are smart enough to use SIMD instructions with large words on this loop,
    // however it may not unroll the loops, so we unroll it manually.
    UNROLL_LOOP(64)
    for (const unsigned char b : data) {
        bits |= b;
    }
    return bits == 0;
}

// Generic implementations

MULTIVERSION_GENERIC bool is_pristine(std::span<const unsigned char> data) noexcept {
    return is_pristine_impl(data);
}
MULTIVERSION_GENERIC bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept {
    return is_pristine_impl(data);
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64
MULTIVERSION_AMD64_AVX2 bool is_pristine(std::span<const unsigned char> data) noexcept {
    return is_pristine_impl(data);
}
MULTIVERSION_AMD64_AVX2 bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept {
    return is_pristine_impl(data);
}

MULTIVERSION_AMD64_AVX512 bool is_pristine(std::span<const unsigned char> data) noexcept {
    return is_pristine_impl(data);
}
MULTIVERSION_AMD64_AVX512 bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept {
    return is_pristine_impl(data);
}
#endif

} // namespace cartesi
