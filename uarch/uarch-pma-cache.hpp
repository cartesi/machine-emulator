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

#ifndef UARCH_PMA_CACHE_HPP
#define UARCH_PMA_CACHE_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "address-range-constants.hpp"
#include "uarch-address-range.hpp"

namespace cartesi {

/// Guest descriptor snapshots and successful disjoint address intervals.
/// All storage is part of the hashed guest memory and restored by guest reset.
class uarch_pma_cache {
    struct interval_lookup {
        uint64_t start{};
        uint64_t end{};
        uint64_t index{};
    };

    uarch_address_ranges m_ranges{};
    std::array<interval_lookup, 16> m_intervals{};
    size_t m_interval_count{};

public:
    template <typename READ_ENTRY, typename ABRT>
    uarch_address_range &read(uint64_t index, READ_ENTRY read_entry, ABRT abrt) {
        if (index >= PMA_MAX) [[unlikely]] {
            static uarch_address_range sentinel;
            return sentinel;
        }
        const auto entry = read_entry(index);
        auto &ar = m_ranges[index];
        ar.initialize(entry.istart, entry.ilength, abrt);
        return ar;
    }

    template <typename T, typename READ_ENTRY, typename ABRT>
    uarch_address_range &find(uint64_t paddr, uint64_t &index, READ_ENTRY read_entry, ABRT abrt) {
        static_assert(sizeof(T) <= AR_PAGE_SIZE);
        const uint64_t page = paddr & ~(AR_PAGE_SIZE - 1);
        const bool within_page = (paddr - page) <= AR_PAGE_SIZE - sizeof(T);
        if (within_page) {
            for (size_t i = 0; i < m_interval_count; ++i) {
                if (paddr >= m_intervals[i].start && paddr < m_intervals[i].end) {
                    index = m_intervals[i].index;
                    return m_ranges[index];
                }
            }
        }
        // Probe index 0 (RAM), then binary-search the sorted nonempty tail, treating
        // empty suffix entries as +infinity. A miss returns the synthetic empty
        // descriptor at index 32 (PMA_MAX). Only probed descriptors are validated.
        index = 0;
        auto &ram = read(index, read_entry, abrt);
        if (ram.is_empty()) [[unlikely]] {
            return ram;
        }
        if (ram.contains_absolute(paddr, sizeof(T))) {
            if (within_page && m_interval_count < m_intervals.size()) {
                m_intervals[m_interval_count++] = {.start = ram.get_start(),
                    .end = ram.get_start() + ram.get_length(),
                    .index = index};
            }
            return ram;
        }
        uint64_t lower = 1;
        uint64_t upper = PMA_MAX;
        while (lower < upper) {
            index = lower + (upper - lower) / 2;
            auto &ar = read(index, read_entry, abrt);
            // Validate each probe; constructor-sorted, disjoint tails need no exclusions.
            if (ar.is_empty() || paddr < ar.get_start()) {
                upper = index;
            } else if (ar.contains_absolute(paddr, sizeof(T))) {
                if (within_page && m_interval_count < m_intervals.size()) {
                    m_intervals[m_interval_count++] = {.start = ar.get_start(),
                        .end = ar.get_start() + ar.get_length(),
                        .index = index};
                }
                return ar;
            } else {
                lower = index + 1;
            }
        }
        // PMA_MAX selects the accessor's synthetic empty descriptor.
        index = PMA_MAX;
        return read(index, read_entry, abrt);
    }

    void invalidate_on_write(uint64_t paddr) {
        // Replay may accept unusual descriptors permitting writes to PMA storage.
        // Keep descriptor snapshots, as before, but repeat the uncached search.
        if (paddr >= AR_PMAS_START && paddr - AR_PMAS_START < AR_PMAS_LENGTH) [[unlikely]] {
            m_interval_count = 0;
        }
    }
};

} // namespace cartesi

#endif
