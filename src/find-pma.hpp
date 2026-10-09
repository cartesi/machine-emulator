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

namespace cartesi {

/// \brief Returns address range associated to the PMA entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \param index Receives index where PMA entry was found.
/// \returns PMA entry where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
auto &find_pma(const STATE_ACCESS a, uint64_t paddr, uint64_t &index) {
    [[maybe_unused]] auto note = a.make_scoped_note("find_pma");
    if constexpr (requires { a.template find_pma<T>(paddr, index); }) {
        return a.template find_pma<T>(paddr, index);
    } else if constexpr (requires { a.read_pma_bounds(index); }) {
        // Probe RAM, then binary-search the sorted nonempty tail, treating
        // empty suffix entries as +infinity. A miss returns the synthetic empty
        // descriptor at index 32 (PMA_MAX). Only the selected descriptor is constructed and validated.
        index = PMA_RAM_INDEX;
        const auto [ram_start, ram_length] = a.read_pma_bounds(index);
        if (ram_length == 0) [[unlikely]] {
            return a.read_pma(index);
        }
        if (paddr >= ram_start && ram_length >= sizeof(T) && paddr - ram_start <= ram_length - sizeof(T)) {
            return a.read_pma(index);
        }
        uint64_t lower = 1;
        uint64_t upper = PMA_MAX;
        while (lower < upper) {
            index = lower + (upper - lower) / 2;
            const auto [start, length] = a.read_pma_bounds(index);
            // Constructible tails are sorted and disjoint. Empty slots are +infinity.
            if (length == 0 || paddr < start) {
                upper = index;
            } else if (length >= sizeof(T) && paddr - start <= length - sizeof(T)) {
                return a.read_pma(index);
            } else {
                lower = index + 1;
            }
        }
        // PMA_MAX selects the accessor's synthetic empty descriptor.
        index = PMA_MAX;
        return a.read_pma(index);
    } else {
        // Native accessors already own constructed descriptors. Preserve their lookup path.
        // Probe RAM, then binary-search the sorted nonempty tail, treating
        // empty suffix entries as +infinity. A miss returns the synthetic empty
        // descriptor at index 32 (PMA_MAX). Only probed descriptors are validated.
        index = PMA_RAM_INDEX;
        auto &ram = a.read_pma(index);
        if (ram.is_empty()) [[unlikely]] {
            return ram;
        }
        if (ram.contains_absolute(paddr, sizeof(T))) {
            return ram;
        }
        uint64_t lower = 1;
        uint64_t upper = PMA_MAX;
        while (lower < upper) {
            index = lower + (upper - lower) / 2;
            auto &ar = a.read_pma(index);
            // Constructible tails are sorted and disjoint. Empty slots are +infinity.
            if (ar.is_empty() || paddr < ar.get_start()) {
                upper = index;
            } else if (ar.contains_absolute(paddr, sizeof(T))) {
                return ar;
            } else {
                lower = index + 1;
            }
        }
        // PMA_MAX selects the accessor's synthetic empty descriptor.
        index = PMA_MAX;
        return a.read_pma(index);
    }
}

/// \brief Returns address range associated to the PMA entry where a word falls.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address of word.
/// \returns PMA entry where word falls, or empty sentinel.
template <typename T, typename STATE_ACCESS>
FORCE_INLINE auto &find_pma(const STATE_ACCESS a, uint64_t paddr) {
    uint64_t index = 0;
    return find_pma<T>(a, paddr, index);
}

} // namespace cartesi

#endif // FIND_PMA_ENTRY_H
