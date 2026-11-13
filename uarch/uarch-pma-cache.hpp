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
#include "selected-address-ranges.hpp"

namespace cartesi {

/// Guest cached PMA entries and successful disjoint address ranges.
/// All storage is part of the hashed guest memory and restored by guest reset.
class uarch_pma_cache {
    struct range_hit {
        uint64_t start{};
        uint64_t end{};
        uint64_t index{};
    };

    // The cache, including its ranges, must fit one witness page (see uarch-run.cpp).
    static constexpr size_t HIT_CAPACITY = 16;
    selected_address_ranges m_ranges;
    address_range m_sentinel;
    std::array<range_hit, HIT_CAPACITY> m_hits{};
    size_t m_hit_count{};

    template <typename READ_ENTRY>
    pmas_entry probe(uint64_t index, READ_ENTRY read_entry) const {
        // Cached entries selected earlier remain authoritative.
        if (const auto *ar = m_ranges.find(index)) {
            return {.istart = ar->get_istart(), .ilength = ar->get_length()};
        }
        return read_entry(index);
    }

public:
    template <typename READ_ENTRY, typename ABRT>
    address_range &read(uint64_t index, READ_ENTRY read_entry, ABRT abrt) {
        if (index >= PMA_MAX) [[unlikely]] {
            return m_sentinel;
        }
        const auto entry = read_entry(index);
        return m_ranges.select(index, entry.istart, entry.ilength, abrt);
    }

    template <typename T, typename READ_ENTRY, typename ABRT>
    address_range &find(uint64_t paddr, uint64_t &index, READ_ENTRY read_entry, ABRT abrt) {
        static_assert(sizeof(T) <= AR_PAGE_SIZE);
        const uint64_t page = paddr & ~(AR_PAGE_SIZE - 1);
        const bool within_page = (paddr - page) <= AR_PAGE_SIZE - sizeof(T);
        if (within_page) {
            for (size_t i = 0; i < m_hit_count; ++i) {
                if (paddr >= m_hits[i].start && paddr < m_hits[i].end) {
                    index = m_hits[i].index;
                    return *m_ranges.find(index);
                }
            }
        }
        // Same search as find_pma_index. Kept inline here: sharing it changes the guest's
        // inlining and costs witness pages and cycles (tests/lua/cartesi/tests/witness-locality-expectations.lua).
        index = PMA_RAM_INDEX;
        const auto ram_entry = probe(index, read_entry);
        const uint64_t ram_start = ram_entry.istart & PMA_ISTART_START_MASK;
        if (ram_entry.ilength == 0) [[unlikely]] {
            return read(index, read_entry, abrt);
        }
        if (paddr >= ram_start && ram_entry.ilength >= sizeof(T) &&
            paddr - ram_start <= ram_entry.ilength - sizeof(T)) {
            auto &ram = m_ranges.select(index, ram_entry.istart, ram_entry.ilength, abrt);
            if (within_page && m_hit_count < m_hits.size()) {
                m_hits[m_hit_count++] = {.start = ram.get_start(),
                    .end = ram.get_start() + ram.get_length(),
                    .index = index};
            }
            return ram;
        }
        uint64_t lower = 1;
        uint64_t upper = PMA_MAX;
        while (lower < upper) {
            index = lower + ((upper - lower) / 2);
            const auto entry = probe(index, read_entry);
            const uint64_t start = entry.istart & PMA_ISTART_START_MASK;
            // Raw bounds suffice for rejection; construct only the selected address range.
            if (entry.ilength == 0 || paddr < start) {
                upper = index;
            } else if (entry.ilength >= sizeof(T) && paddr - start <= entry.ilength - sizeof(T)) {
                auto &ar = m_ranges.select(index, entry.istart, entry.ilength, abrt);
                if (within_page && m_hit_count < m_hits.size()) {
                    m_hits[m_hit_count++] = {.start = ar.get_start(),
                        .end = ar.get_start() + ar.get_length(),
                        .index = index};
                }
                return ar;
            } else {
                lower = index + 1;
            }
        }
        // PMA_MAX selects the accessor's synthetic empty PMA entry.
        index = PMA_MAX;
        return read(index, read_entry, abrt);
    }

    void invalidate_on_write(uint64_t paddr) {
        // Replay may accept unusual PMA entries permitting writes to PMA storage.
        // Cached entries stay valid; only the range cache is cleared.
        if (paddr >= AR_PMAS_START && paddr - AR_PMAS_START < AR_PMAS_LENGTH) [[unlikely]] {
            m_hit_count = 0;
        }
    }
};

} // namespace cartesi

#endif
