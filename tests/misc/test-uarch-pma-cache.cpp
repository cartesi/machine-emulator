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
#include <utility>

#include "assert-printf.hpp"
#include "mock-address-range.hpp"
#include "uarch-pma-cache.hpp"

using namespace cartesi;

namespace {

void fail(const char *message) {
    throw std::runtime_error(message);
}

void require(bool condition) {
    if (!condition) {
        throw std::logic_error("PMA lookup cache differs from ordered reference");
    }
}

// The pre-cache lookup: independent polymorphic factory and containment checks.
class reference_cache {
    mock_address_ranges m_ranges{};
    address_range m_sentinel{"sentinel"};

public:
    address_range &read(uint64_t index, const pmas_state &entries) {
        if (index >= PMA_MAX) {
            return m_sentinel;
        }
        auto &mock = m_ranges[index];
        if (std::holds_alternative<std::monostate>(mock)) {
            mock = make_mock_address_range(entries[index].istart, entries[index].ilength, fail);
        }
        return get_mock_address_range(mock, fail);
    }

    template <typename T>
    address_range &find(uint64_t paddr, uint64_t &index, const pmas_state &entries) {
        for (index = 0; index < PMA_MAX; ++index) {
            if (std::holds_alternative<std::monostate>(m_ranges[index]) &&
                can_skip_mock_memory_range(entries[index].istart, entries[index].ilength, paddr, sizeof(T))) {
                continue;
            }
            auto &ar = read(index, entries);
            if (ar.is_empty() || ar.contains_absolute(paddr, sizeof(T))) {
                return ar;
            }
        }
        return m_sentinel;
    }
};

uint64_t comparisons = 0;
uint64_t rejections = 0;

class differential_cache {
    reference_cache m_reference{};
    uarch_pma_cache m_candidate{};

    static void compare(const address_range &a, const uarch_address_range &b) {
        require(a.get_start() == b.get_start() && a.get_length() == b.get_length());
        require(a.is_memory() == b.is_memory() && a.is_empty() == b.is_empty());
        require(a.get_driver_id() == b.get_driver_id() && a.is_device() == b.is_device());
        require(a.is_readable() == b.is_readable() && a.is_writeable() == b.is_writeable());
        require(a.is_executable() == b.is_executable());
    }

public:
    pmas_state entries{};
    uint64_t metadata_reads{};

    template <typename T>
    uint64_t find(uint64_t paddr) {
        uint64_t old_index = 0;
        uint64_t new_index = 0;
        address_range *old_ar = nullptr;
        uarch_address_range *new_ar = nullptr;
        try {
            old_ar = &m_reference.find<T>(paddr, old_index, entries);
        } catch (const std::runtime_error &) {
        }
        try {
            new_ar = &m_candidate.find<T>(
                paddr, new_index,
                [this](uint64_t i) {
                    ++metadata_reads;
                    return entries[i];
                },
                fail);
        } catch (const std::runtime_error &) {
        }
        ++comparisons;
        require((old_ar == nullptr) == (new_ar == nullptr));
        if (old_ar != nullptr) {
            require(old_index == new_index);
            compare(*old_ar, *new_ar);
            return new_index;
        }
        ++rejections;
        return UINT64_MAX;
    }

    void read(uint64_t index) {
        auto &a = m_reference.read(index, entries);
        auto &b = m_candidate.read(index, [this](uint64_t i) { return entries[i]; }, fail);
        compare(a, b);
    }

    void write_entry(uint64_t index, pmas_entry entry) {
        m_candidate.invalidate_on_write(pmas_get_abs_addr(index));
        entries[index] = entry;
    }

    void write_elsewhere(uint64_t paddr) {
        m_candidate.invalidate_on_write(paddr);
    }
};

pmas_entry memory(uint64_t start, uint64_t length, uint64_t permissions = 0x1c) {
    return {start | PMA_ISTART_M_MASK | permissions, length};
}

void targeted_cases() {
    differential_cache c;
    c.entries[0] = memory(0x3000, 0x1000);
    c.entries[1] = memory(0x2000, 0x4000);
    require(c.find<uint64_t>(0x2000) == 1);
    require(c.find<uint64_t>(0x3000) == 0); // Earlier overlap must win.
    const auto reads = c.metadata_reads;
    require(c.find<uint8_t>(0x2fff) == 1);
    require(c.find<uint32_t>(0x3800) == 0);
    require(c.metadata_reads == reads);     // Hits really avoid rescanning metadata.
    require(c.find<uint64_t>(0x3ffc) == 1); // Cross-page request cannot hit the first range.
    require(c.find<uint8_t>(0x3ffc) == 0);  // Nor may that cross-page result poison this page.
    require(c.find<uint64_t>(UINT64_MAX) == 2);
    require(c.find<uint64_t>(0) == 2);
    c.read(PMA_MAX);
    c.read(UINT64_MAX);

    // One interval can span pages, but must stop at earlier overlaps on either side.
    differential_cache intervals;
    intervals.entries[0] = memory(0x1000, 0x2000);
    intervals.entries[1] = memory(0x7000, 0x2000);
    intervals.entries[2] = memory(0, 0x10000);
    require(intervals.find<uint64_t>(0x4000) == 2);
    const auto interval_reads = intervals.metadata_reads;
    require(intervals.find<uint8_t>(0x3000) == 2);
    require(intervals.find<uint64_t>(0x6ff8) == 2);
    require(intervals.metadata_reads == interval_reads);
    require(intervals.find<uint64_t>(0x2ff8) == 0);
    require(intervals.find<uint64_t>(0x7000) == 1);
    require(intervals.find<uint64_t>(0) == 2);
    require(intervals.find<uint64_t>(0x9000) == 2);
    // Invalidation must use cached bounds even if their backing metadata changed.
    intervals.write_entry(0, memory(0x5000, 0x1000));
    require(intervals.find<uint64_t>(0x4000) == 2);
    require(intervals.find<uint64_t>(0x2000) == 0);
    require(intervals.find<uint64_t>(0x5000) == 2);

    // A skipped descriptor becomes frozen when a later lookup actually selects it.
    differential_cache prefix;
    prefix.entries[0] = memory(0x1000, 0x1000);
    prefix.entries[1] = memory(0x4000, 0x1000);
    prefix.entries[2] = {UINT64_MAX, 1}; // Must remain unreachable.
    require(prefix.find<uint64_t>(0x4000) == 1);
    require(prefix.find<uint64_t>(0x1000) == 0);
    prefix.read(0);
    prefix.write_entry(0, memory(0x7000, 0x1000));
    require(prefix.find<uint64_t>(0x1000) == 0);          // The successful lookup froze this descriptor.
    require(prefix.find<uint64_t>(0x7000) == UINT64_MAX); // Reach the malformed suffix now.

    // An uninitialized prefix can change after a prior successful lookup.
    differential_cache mutated;
    mutated.entries[0] = memory(0x9000, 0x1000);
    mutated.entries[1] = memory(0x2000, 0x4000);
    require(mutated.find<uint64_t>(0x3000) == 1);
    mutated.write_entry(0, memory(0x3000, 0x1000, 4));
    require(mutated.find<uint64_t>(0x3000) == 0);
    // Constructed descriptors retain their old value even after the backing entry changes.
    mutated.write_entry(0, {UINT64_MAX, 1});
    require(mutated.find<uint64_t>(0x3000) == 0);

    differential_cache rejected;
    rejected.entries[0] = memory(0x9000, 0x1000);
    rejected.entries[1] = memory(0x3000, 0x1000);
    rejected.entries[2] = {UINT64_MAX, 1}; // Unreachable malformed suffix must not reject a hit.
    require(rejected.find<uint64_t>(0x3000) == 1);
    require(rejected.find<uint64_t>(0x3800) == 1);
    rejected.write_entry(0, memory(0x9000, 1));
    require(rejected.find<uint64_t>(0x3000) == UINT64_MAX); // Now malformed prefix must reject.
    rejected.write_entry(0, {});
    require(rejected.find<uint64_t>(0x3000) == 0); // Earlier sentinel must win after invalidation.

    differential_cache full;
    for (uint64_t i = 0; i < PMA_MAX; ++i) {
        full.entries[i] = memory((i + 1) * AR_PAGE_SIZE, AR_PAGE_SIZE);
    }
    for (unsigned round = 0; round < 2; ++round) {
        for (uint64_t i = 0; i < PMA_MAX; ++i) {
            require(full.find<uint64_t>((i + 1) * AR_PAGE_SIZE) == i);
        }
    }
    require(full.find<uint64_t>(UINT64_C(1) << 40) == PMA_MAX);
    // PMA writes are detected throughout the table page, including subword end addresses.
    for (uint64_t paddr : {uint64_t{AR_PMAS_START}, AR_PMAS_START + AR_PMAS_LENGTH - 1}) {
        full.write_elsewhere(paddr);
        const auto before = full.metadata_reads;
        require(full.find<uint64_t>(AR_PAGE_SIZE) == 0);
        require(full.metadata_reads > before);
    }
    for (uint64_t paddr : {UINT64_C(0), AR_PMAS_START - 1, AR_PMAS_START + AR_PMAS_LENGTH, UINT64_MAX}) {
        full.write_elsewhere(paddr);
        const auto before = full.metadata_reads;
        require(full.find<uint64_t>(AR_PAGE_SIZE) == 0);
        require(full.metadata_reads == before);
    }
}

uint64_t random_state = UINT64_C(0xe271cc67a8bd9115);
uint64_t random_word() {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

void random_disjoint_sequences() {
    for (unsigned trial = 0; trial < 200; ++trial) {
        differential_cache c;
        for (uint64_t i = 0; i < PMA_MAX; ++i) {
            c.entries[i] = memory((i + 1) * AR_PAGE_SIZE, AR_PAGE_SIZE, random_word() & 0xffe);
        }
        // Metadata order is deliberately unrelated to physical address order.
        for (uint64_t i = PMA_MAX - 1; i > 0; --i) {
            std::swap(c.entries[i], c.entries[random_word() % (i + 1)]);
        }
        c.read(PMA_MAX - 1); // An explicit read may freeze a descriptor before any search.
        for (unsigned query = 0; query < 128; ++query) {
            const auto address = (random_word() % (PMA_MAX + 2)) * AR_PAGE_SIZE;
            c.find<uint64_t>(address);
            c.find<uint64_t>(address + AR_PAGE_SIZE - 4); // Straddles adjacent ranges.
            c.find<uint8_t>(address + AR_PAGE_SIZE - 1);
        }
    }
}

void random_sequences() {
    for (unsigned trial = 0; trial < 2000; ++trial) {
        differential_cache c;
        for (uint64_t i = 0; i < PMA_MAX; ++i) {
            c.entries[i] = memory((random_word() % 48) * AR_PAGE_SIZE, (1 + random_word() % 8) * AR_PAGE_SIZE,
                random_word() & 0xffe);
        }
        for (unsigned query = 0; query < 200; ++query) {
            if (query % 5 == 0) {
                const auto index = random_word() % PMA_MAX;
                auto entry = memory((random_word() % 48) * AR_PAGE_SIZE, (1 + random_word() % 8) * AR_PAGE_SIZE);
                if (query % 15 == 0) {
                    entry.ilength = random_word() % 3; // Empty and malformed entries.
                }
                c.write_entry(index, entry);
            }
            const uint64_t address = random_word() % (64 * AR_PAGE_SIZE);
            switch (query % 4) {
                case 0:
                    c.find<uint8_t>(address);
                    break;
                case 1:
                    c.find<uint16_t>(address);
                    break;
                case 2:
                    c.find<uint32_t>(address);
                    break;
                default:
                    c.find<uint64_t>(address);
                    break;
            }
        }
    }
}

} // namespace

int main() {
    targeted_cases();
    random_sequences();
    random_disjoint_sequences();
    std::printf("%llu ordered/cache comparisons passed, including %llu matching rejections\n",
        static_cast<unsigned long long>(comparisons), static_cast<unsigned long long>(rejections));
}
