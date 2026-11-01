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

#ifndef FIND_PMA_HPP
#define FIND_PMA_HPP

#include <cstdint>

#include "address-range.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"

namespace cartesi {

/// \brief Probe RAM, then binary-search the sorted nonempty PMA tail.
/// Empty suffix entries compare as +infinity. A miss selects the synthetic empty
/// PMA entry at PMA_MAX. The caller constructs and validates the selected address range.
template <typename T, typename ENTRY>
uint64_t find_pma_index(uint64_t paddr, ENTRY entry) {
    const auto ram_entry = entry(PMA_RAM_INDEX);
    const uint64_t ram_start = ram_entry.istart & PMA_ISTART_START_MASK;
    if (ram_entry.ilength == 0) [[unlikely]] {
        return PMA_RAM_INDEX;
    }
    if (paddr >= ram_start && ram_entry.ilength >= sizeof(T) && paddr - ram_start <= ram_entry.ilength - sizeof(T)) {
        return PMA_RAM_INDEX;
    }
    uint64_t lower = 1;
    uint64_t upper = PMA_MAX;
    while (lower < upper) {
        const uint64_t index = lower + ((upper - lower) / 2);
        const auto current = entry(index);
        const uint64_t start = current.istart & PMA_ISTART_START_MASK;
        if (current.ilength == 0 || paddr < start) {
            upper = index;
        } else if (current.ilength >= sizeof(T) && paddr - start <= current.ilength - sizeof(T)) {
            return index;
        } else {
            lower = index + 1;
        }
    }
    return PMA_MAX;
}

/// \brief Returns address range associated to the PMA entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \param index Receives index where PMA entry was found.
/// \returns Address range where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
auto &find_pma(const STATE_ACCESS a, uint64_t paddr, uint64_t &index) {
    [[maybe_unused]] auto note = a.make_scoped_note("find_pma");
    if constexpr (requires { a.template find_pma<T>(paddr, index); }) {
        return a.template find_pma<T>(paddr, index);
    } else {
        index = find_pma_index<T>(paddr, [a](uint64_t i) {
            if constexpr (requires { a.read_pma_bounds(i); }) {
                const auto [start, length] = a.read_pma_bounds(i);
                return pmas_entry{.istart = start, .ilength = length};
            } else {
                const auto &ar = a.read_pma(i);
                return pmas_entry{.istart = ar.get_istart(), .ilength = ar.get_length()};
            }
        });
        return a.read_pma(index);
    }
}

/// \brief Returns address range associated to the PMA entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \returns Address range where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
FORCE_INLINE auto &find_pma(const STATE_ACCESS a, uint64_t paddr) {
    uint64_t index = 0;
    return find_pma<T>(a, paddr, index);
}

} // namespace cartesi

#endif // FIND_PMA_ENTRY_H
