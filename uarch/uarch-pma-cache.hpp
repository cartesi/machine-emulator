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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "address-range-constants.hpp"
#include "mock-address-range.hpp"
#include "uarch-address-range.hpp"

namespace cartesi {

/// Guest descriptor snapshots and successful first-match address intervals.
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

    static void exclude(uint64_t start, uint64_t length, uint64_t paddr, uint64_t &lower, uint64_t &upper) {
        if (paddr < start) {
            upper = std::min(upper, start);
        } else {
            lower = std::max(lower, start + length);
        }
    }

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
        uint64_t lower = 0;
        uint64_t upper = UINT64_MAX;
        for (index = 0; index < PMA_MAX; ++index) {
            const auto entry = read_entry(index);
            auto &ar = m_ranges[index];
            if (!ar.is_initialized() && can_skip_mock_memory_range(entry.istart, entry.ilength, paddr, sizeof(T))) {
                exclude(entry.istart & PMA_ISTART_START_MASK, entry.ilength, paddr, lower, upper);
                continue;
            }
            ar.initialize(entry.istart, entry.ilength, abrt);
            if (ar.is_empty()) {
                return ar;
            }
            if (ar.contains_absolute(paddr, sizeof(T))) {
                // Exclude every earlier range from the matching interval. All
                // validated bounds are page aligned, so a contained word in this
                // interval has the same first match. Cross-page queries do not
                // populate the cache, and later entries remain unvalidated.
                if (within_page && m_interval_count < m_intervals.size()) {
                    m_intervals[m_interval_count++] = {.start = std::max(lower, ar.get_start()),
                        .end = std::min(upper, ar.get_start() + ar.get_length()),
                        .index = index};
                }
                return ar;
            }
            exclude(ar.get_start(), ar.get_length(), paddr, lower, upper);
        }
        return read(index, read_entry, abrt);
    }

    void invalidate_on_write(uint64_t paddr) {
        // Replay may accept unusual descriptors permitting writes to PMA storage.
        // Keep descriptor snapshots, as before, but rescan their uncached prefix.
        if (paddr >= AR_PMAS_START && paddr - AR_PMAS_START < AR_PMAS_LENGTH) [[unlikely]] {
            m_interval_count = 0;
        }
    }
};

} // namespace cartesi

#endif
