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

#include <ranges>
#include <span>

#include "address-range-constants.h"
#include "concepts.h"

namespace cartesi {

/// \brief This is an optimized function for checking if data is pristine.
/// \param data Memory data.
/// \returns True if all values are 0, false otherwise.
/// \details It's to be used in situations where length is equal or less than a page size.
MULTIVERSION_GENERIC bool is_pristine(std::span<const unsigned char> data) noexcept;

/// \brief This is an optimized function for checking if memory page is pristine.
MULTIVERSION_GENERIC bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept;

template <ContiguousRangeOfByteLike R>
bool is_pristine(R &&r) noexcept { // NOLINT(cppcoreguidelines-missing-std-forward)
    return is_pristine(std::span<const unsigned char>{std::ranges::data(r), std::ranges::size(r)});
}

#ifdef USE_MULTIVERSINING_AMD64
MULTIVERSION_AMD64_AVX2 bool is_pristine(std::span<const unsigned char> data) noexcept;
MULTIVERSION_AMD64_AVX2 bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept;

MULTIVERSION_AMD64_AVX512 bool is_pristine(std::span<const unsigned char> data) noexcept;
MULTIVERSION_AMD64_AVX512 bool is_pristine(std::span<const unsigned char, AR_PAGE_SIZE> data) noexcept;
#endif

} // namespace cartesi

#endif
