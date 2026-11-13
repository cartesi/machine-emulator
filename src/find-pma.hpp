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

} // namespace cartesi

#endif
