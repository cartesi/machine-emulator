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
#include "mock-address-range.hpp"
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

// Use the polymorphic replay factory for the shared lookup; the guest uses its
// compact descriptors. Both instantiate and validate only entries they probe.
struct shared_access {
    const pmas_state &entries;
    mock_address_ranges ranges{};
    address_range sentinel{"sentinel"};

    int make_scoped_note(const char *) const {
        return 0;
    }

    address_range &read_pma(uint64_t index) {
        require(index <= PMA_MAX);
        if (index == PMA_MAX) {
            return sentinel;
        }
        auto &mock = ranges[index];
        if (std::holds_alternative<std::monostate>(mock)) {
            mock = make_mock_address_range(entries[index].istart, entries[index].ilength, fail);
        }
        return get_mock_address_range(mock, fail);
    }
};

// find_pma takes its accessor by value, just like the production accessors.
struct shared_access_ref {
    shared_access &state;
    int make_scoped_note(const char *) const {
        return 0;
    }
    address_range &read_pma(uint64_t index) const {
        return state.read_pma(index);
    }
};

uint64_t comparisons = 0;

// Independent linear containment oracle for valid, disjoint tables. Misses use
// the synthetic descriptor at PMA_MAX, regardless of where the empty suffix starts.
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
    const auto &a = find_pma<T>(shared_access_ref{access}, paddr, shared_index);
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
            require(find_pma<uint64_t>(shared_access_ref{access}, 0x8000, index).get_start() == 0x8000);
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

} // namespace

int main() {
    differential_cases();
    cache_cases();
    malformed_cases();
    std::printf("%llu width/address/cache comparisons passed; probed/unprobed malformed behavior agrees\n",
        static_cast<unsigned long long>(comparisons));
}
