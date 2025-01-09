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

#ifndef FIND_PMA_ENTRY_H
#define FIND_PMA_ENTRY_H

#include "compiler-defines.h"
#include <cstdint>

namespace cartesi {

/// \brief Returns PMAs entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \param index Receives index where PMA entry was found.
/// \returns PMA entry where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
auto &find_pma_entry(STATE_ACCESS &a, uint64_t paddr, uint64_t &index) {
    index = 0;
    while (true) {
        auto &pma = a.read_pma_entry(index);
        const auto length = pma.get_length();
        // The pmas array always contain a sentinel.
        // It is an entry with zero length.
        // If we hit it, return it
        if (unlikely(length == 0)) {
            return pma;
        }
        // Otherwise, if we found an entry where the access fits, return it
        // Note the "strange" order of arithmetic operations.
        // This is to ensure there is no overflow.
        // Since we know paddr >= start, there is no chance of overflow in the first subtraction.
        // Since length is at least 4096 (an entire page), there is no chance of overflow in the second subtraction.
        const auto start = pma.get_start();
        if (paddr >= start && paddr - start <= length - sizeof(T)) {
            return pma;
        }
        ++index;
    }
}

/// \brief Returns PMAs entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \returns PMA entry where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
FORCE_INLINE auto &find_pma_entry(STATE_ACCESS &a, uint64_t paddr) {
    uint64_t index = 0;
    return find_pma_entry<T>(a, paddr, index);
}

} // namespace cartesi

#endif // FIND_PMA_ENTRY_H
