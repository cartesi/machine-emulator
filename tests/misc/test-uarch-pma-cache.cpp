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
#include "uarch-pma-cache.hpp"

using namespace cartesi;

namespace {

void fail(const char *message) {
    throw std::runtime_error(message);
}

void require(bool condition) {
    if (!condition) {
        throw std::logic_error("RAM-first PMA lookup mismatch");
    }
}

// Reads PMA entries the way the machine replayer does.
struct shared_access {
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

// The lookup every host accessor runs by default (i_state_access::do_find_pma).
template <typename T>
address_range &shared_find(shared_access &access, uint64_t paddr, uint64_t &index) {
    index = find_pma_index<T>(paddr, [&](uint64_t i) { return access.read_pma_entry(i); });
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
void compare(uint64_t paddr, const pmas_state &entries, shared_access &access, uarch_pma_cache &cache) {
    const auto expected = reference_index<T>(entries, paddr);
    uint64_t shared_index = UINT64_MAX;
    uint64_t guest_index = UINT64_MAX;
    const auto &a = shared_find<T>(access, paddr, shared_index);
    const auto &b = cache.find<T>(
        paddr, guest_index,
        [&](uint64_t i) {
            require(i < PMA_MAX);
            return entries[i];
        },
        fail);
    require(shared_index == expected && guest_index == expected);
    require(a.is_empty() == (expected == PMA_MAX || entries[0].ilength == 0));
    require(a.is_empty() == b.is_empty());
    require(a.get_start() == b.get_start() && a.get_length() == b.get_length());
    require(a.is_memory() == b.is_memory() && a.is_device() == b.is_device());
    require(a.get_driver_id() == b.get_driver_id());
    require(a.is_readable() == b.is_readable() && a.is_writeable() == b.is_writeable());
    require(a.is_executable() == b.is_executable());
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
            shared_access access{entries};
            uarch_pma_cache cache;
            auto query = [&](uint64_t paddr) {
                compare<uint8_t>(paddr, entries, access, cache);
                compare<uint16_t>(paddr, entries, access, cache);
                compare<uint32_t>(paddr, entries, access, cache);
                compare<uint64_t>(paddr, entries, access, cache);
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

void cache_cases() {
    pmas_state entries{};
    entries[0] = {.istart = 0x8000 | 0xfd, .ilength = 0x2000};
    entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 0x3000};
    uarch_pma_cache cache;
    uint64_t reads = 0;
    auto read = [&](uint64_t i) {
        ++reads;
        return entries[i];
    };
    auto query = [&]<typename T>(uint64_t paddr) {
        uint64_t index = UINT64_MAX;
        cache.find<T>(paddr, index, read, fail);
        return index;
    };
    require(query.operator()<uint64_t>(0x3000) == 1);
    const auto cold_reads = reads;
    require(query.operator()<uint8_t>(0x2000) == 1);
    require(query.operator()<uint64_t>(0x4ff8) == 1);
    require(reads == cold_reads); // An interval spans pages without new metadata.
    require(query.operator()<uint64_t>(0x4ffc) == PMA_MAX);
    require(query.operator()<uint8_t>(0x4ffc) == 1); // Cross-page miss must not poison hits.
    const auto warm_reads = reads;
    cache.invalidate_on_write(0x8000);
    require(query.operator()<uint64_t>(0x3000) == 1 && reads == warm_reads);
    cache.invalidate_on_write(AR_PMAS_START);
    require(query.operator()<uint64_t>(0x3000) == 1 && reads > warm_reads);
    require(cache.read(PMA_MAX, read, fail).is_empty());
}

void malformed_cases() {
    // A RAM hit never probes index 1. Both lookup implementations deliberately
    // accept its malformed length; whole-table validation is not the contract.
    for (bool corrupt_ram : {false, true}) {
        pmas_state entries{};
        entries[0] = {.istart = 0x8000 | 0xfd, .ilength = corrupt_ram ? 4095U : 4096U};
        entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4095};
        shared_access access{entries};
        uarch_pma_cache cache;
        bool shared_rejected = false;
        bool guest_rejected = false;
        uint64_t index = UINT64_MAX;
        try {
            require(shared_find<uint64_t>(access, 0x8000, index).get_start() == 0x8000);
            require(index == 0);
        } catch (const std::runtime_error &) {
            shared_rejected = true;
        }
        try {
            require(cache.find<uint64_t>(
                             0x8000, index, [&](uint64_t i) { return entries[i]; }, fail)
                        .get_start() == 0x8000);
            require(index == 0);
        } catch (const std::runtime_error &) {
            guest_rejected = true;
        }
        require(shared_rejected == corrupt_ram && guest_rejected == corrupt_ram);
    }
}

void nonmatching_malformed_cases() {
    for (bool match_invalid : {false, true}) {
        pmas_state entries{};
        entries[0] = {.istart = 0x8000 | 0xfd, .ilength = 4095};
        entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4096};
        shared_access access{entries};
        uarch_pma_cache cache;
        const uint64_t address = match_invalid ? 0x8000 : 0x2000;
        uint64_t shared_index = UINT64_MAX, guest_index = UINT64_MAX;
        bool shared_rejected = false, guest_rejected = false;
        try {
            shared_find<uint64_t>(access, address, shared_index);
        } catch (const std::runtime_error &) {
            shared_rejected = true;
        }
        try {
            cache.find<uint64_t>(address, guest_index, [&](uint64_t i) { return entries[i]; }, fail);
        } catch (const std::runtime_error &) {
            guest_rejected = true;
        }
        require(shared_rejected == match_invalid && guest_rejected == match_invalid);
        if (!match_invalid)
            require(shared_index == 1 && guest_index == 1);
    }
}

void cached_entry_cases() {
    pmas_state entries{};
    entries[0] = {.istart = 0x8000 | 0xfd, .ilength = 4096};
    entries[1] = {.istart = 0x2000 | 0xfd, .ilength = 4096};
    shared_access access{entries};
    uarch_pma_cache cache;
    auto query = [&](uint64_t address, uint64_t expected) {
        uint64_t shared_index = UINT64_MAX, guest_index = UINT64_MAX;
        const auto &a = shared_find<uint64_t>(access, address, shared_index);
        const auto &b = cache.find<uint64_t>(address, guest_index, [&](uint64_t i) { return entries[i]; }, fail);
        require(shared_index == expected && guest_index == expected);
        require(a.get_start() == b.get_start() && a.get_length() == b.get_length());
    };
    query(0x2000, 1);
    // Outside the constructor invariant, replay cached entries still agree: the
    // selected address range stays frozen, but a raw nonmatching probe does not.
    entries[0].istart = 0xa000 | 0xfd;
    entries[1].istart = 0x3000 | 0xfd;
    cache.invalidate_on_write(AR_PMAS_START);
    query(0x2000, 1);
    query(0x3000, PMA_MAX);
    query(0xa000, 0);
}

} // namespace

int main() {
    differential_cases();
    cache_cases();
    malformed_cases();
    nonmatching_malformed_cases();
    cached_entry_cases();
    std::printf("%llu shared/cache index and bounds comparisons passed; malformed rejection policy and "
                "cached entries checked\n",
        static_cast<unsigned long long>(comparisons));
}
