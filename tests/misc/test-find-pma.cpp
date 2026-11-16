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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stdexcept>

#include "find-pma.hpp"
#include "lazy-address-ranges.hpp"

using namespace cartesi;

namespace {

void fail(const char *message) {
    throw std::runtime_error(message);
}

void require(bool condition) {
    if (!condition) {
        throw std::logic_error("PMA lookup mismatch");
    }
}

// Reads PMA entries the way the machine replayer does.
struct replayer_access {
    const pmas_state &entries;
    lazy_address_ranges ranges{};

    pmas_entry read_pma_entry(uint64_t index) {
        require(index < PMA_MAX);
        if (const auto *ar = ranges.get(index)) {
            return {.istart = ar->get_istart(), .ilength = ar->get_length()};
        }
        return entries[index];
    }

    address_range &read_pma(uint64_t index) {
        require(index <= PMA_MAX);
        if (index == PMA_MAX) {
            return ranges.get_sentinel();
        }
        return ranges.get_or_create(index, entries[index].istart, entries[index].ilength, fail);
    }
};

// The lookup every accessor runs by default (i_state_access::do_find_pma).
template <typename T>
address_range &find_pma(replayer_access &access, uint64_t paddr, uint64_t &index) {
    index = find_pma_index(paddr, sizeof(T), [&](uint64_t i) { return access.read_pma_entry(i); });
    return access.read_pma(index);
}

uint64_t comparisons = 0;

// Independent linear containment oracle for valid, disjoint tables. Misses use
// the synthetic address range at PMA_MAX, regardless of where the empty suffix starts.
template <typename T>
uint64_t reference_index(const pmas_state &entries, uint64_t paddr) {
    if (entries[0].ilength == 0) {
        return 0; // Defensive empty-RAM handling; not constructor-produced.
    }
    for (uint64_t i = 0; i < PMA_MAX && entries[i].ilength != 0; ++i) {
        const uint64_t start = entries[i].istart & PMA_ISTART_START_MASK;
        const uint64_t length = entries[i].ilength;
        if (paddr >= start && sizeof(T) <= length && paddr - start <= length - sizeof(T)) {
            return i;
        }
    }
    return PMA_MAX;
}

template <typename T>
void compare(uint64_t paddr, const pmas_state &entries, replayer_access &access) {
    const auto expected = reference_index<T>(entries, paddr);
    uint64_t index = UINT64_MAX;
    const auto &ar = find_pma<T>(access, paddr, index);
    require(index == expected);
    if (expected == PMA_MAX || entries[0].ilength == 0) {
        require(ar.is_empty());
    } else {
        require(ar.get_istart() == entries[expected].istart && ar.get_length() == entries[expected].ilength);
    }
    ++comparisons;
}

void differential_cases() {
    uint64_t seed = 7;
    for (uint64_t count = 0; count <= PMA_MAX; ++count) {
        for (uint64_t trial = 0; trial < 4; ++trial) {
            pmas_state entries{};
            uint64_t start = 0;
            for (uint64_t i = 0; i < count; ++i) {
                seed = seed * 6364136223846793005ULL + 1;
                start += ((seed >> 32) % 5) * AR_PAGE_SIZE;
                const uint64_t length = (1 + (seed >> 40) % 8) * AR_PAGE_SIZE;
                entries[i] = {.istart = start | 0xfd, .ilength = length};
                start += length;
            }
            // RAM may lie before, between, or after the other ranges. Moving it
            // to index zero must leave the remaining disjoint ranges sorted.
            if (count != 0) {
                const uint64_t chosen = trial * (count - 1) / 3;
                const auto ram = entries[chosen];
                for (uint64_t i = chosen; i > 0; --i) {
                    entries[i] = entries[i - 1];
                }
                entries[0] = ram;
            }
            replayer_access access{entries};
            auto query = [&](uint64_t paddr) {
                compare<uint8_t>(paddr, entries, access);
                compare<uint16_t>(paddr, entries, access);
                compare<uint32_t>(paddr, entries, access);
                compare<uint64_t>(paddr, entries, access);
            };
            for (unsigned pass = 0; pass < 2; ++pass) {
                for (uint64_t i = 0; i < count; ++i) {
                    const auto base = entries[i].istart & PMA_ISTART_START_MASK;
                    const auto end = base + entries[i].ilength;
                    for (uint64_t paddr : {base, base + 1, base + 4093, end - 8, end - 1, end, base - 1}) {
                        query(paddr);
                    }
                }
                query(0);
                query(start + AR_PAGE_SIZE);
                query(UINT64_MAX);
                query(UINT64_MAX - 7);
            }
        }
    }
}

bool rejects(replayer_access &access, uint64_t paddr, uint64_t &index) {
    try {
        find_pma<uint64_t>(access, paddr, index);
    } catch (const std::runtime_error &) {
        return true;
    }
    return false;
}

void malformed_cases() {
    // A RAM hit never probes index 1, so its malformed length goes unnoticed:
    // whole-table validation is not the contract.
    for (bool corrupt_ram : {false, true}) {
        pmas_state entries{};
        entries[0] = {.istart = 0x8000 | 0xfd, .ilength = corrupt_ram ? 4095U : 4096U};
        entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4095};
        replayer_access access{entries};
        uint64_t index = UINT64_MAX;
        require(rejects(access, 0x8000, index) == corrupt_ram);
        require(corrupt_ram || index == 0);
    }
    // A malformed entry is rejected only when the lookup lands on it.
    for (bool match_invalid : {false, true}) {
        pmas_state entries{};
        entries[0] = {.istart = 0x8000 | 0xfd, .ilength = 4095};
        entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4096};
        replayer_access access{entries};
        uint64_t index = UINT64_MAX;
        require(rejects(access, match_invalid ? 0x8000 : 0x2000, index) == match_invalid);
        require(match_invalid || index == 1);
    }
}

void created_range_cases() {
    pmas_state entries{};
    entries[0] = {.istart = 0x8000 | 0xfd, .ilength = 4096};
    entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4096};
    replayer_access access{entries};
    auto query = [&](uint64_t paddr, uint64_t expected) {
        uint64_t index = UINT64_MAX;
        find_pma<uint64_t>(access, paddr, index);
        require(index == expected);
    };
    query(0x2000, 1);
    // A range already created stays as it was; an entry not yet looked up is read anew.
    entries[0].istart = 0xa000 | 0xfd;
    entries[1].istart = 0x3000 | 0xfd;
    query(0x2000, 1);
    query(0x3000, PMA_MAX);
    query(0xa000, 0);
    require(access.read_pma(PMA_MAX).is_empty());
}

} // namespace

int main() {
    differential_cases();
    malformed_cases();
    created_range_cases();
    std::printf("%llu PMA lookups matched the linear reference; malformed entries and created ranges checked\n",
        static_cast<unsigned long long>(comparisons));
}
