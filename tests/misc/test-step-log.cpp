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
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "machine.hpp"
#include "replay-step-state-access.hpp"
#include "step-log-recorder.hpp"
#include "step-log-slice.hpp"
#include "step-log.hpp"

using namespace cartesi;

namespace {
void require(bool ok) {
    if (!ok) {
        throw std::runtime_error("step-log slice assertion failed");
    }
}

template <typename F>
void rejects(F &&fn, std::string_view expected) {
    try {
        fn();
    } catch (const std::exception &e) {
        require(e.what() == expected);
        return;
    }
    throw std::runtime_error("expected slice rejection");
}

// Enumerate every candidate subtree, rather than following the heuristic's descent.
std::pair<uint64_t, int> oracle(uint128_t mask, int floor) {
    if (mask == 0) {
        return {0, 12};
    }
    for (int size = floor; size <= 12; ++size) {
        for (uint64_t offset = 0; offset < 4096; offset += UINT64_C(1) << size) {
            bool covers = true;
            for (unsigned leaf = 0; leaf < 128; ++leaf) {
                if (((mask >> leaf) & 1) != 0 && (leaf * 32 < offset || leaf * 32 >= offset + (UINT64_C(1) << size))) {
                    covers = false;
                }
            }
            if (covers) {
                return {offset, size};
            }
        }
    }
    throw std::logic_error("no covering subtree");
}

void cuts() {
    unsigned count = 0;
    // All 256 masks of an eight-leaf tree, at every position within a page.
    // Sliding across internal boundaries also exercises both halves of the bitmap.
    for (unsigned start = 0; start <= 120; ++start) {
        for (unsigned mask = 0; mask < 256; ++mask) {
            for (int floor = 5; floor <= 12; ++floor) {
                const auto touched = static_cast<uint128_t>(mask) << start;
                require(select_page_slice(touched, floor) == oracle(touched, floor));
                ++count;
            }
        }
    }
    require(select_page_slice(~static_cast<uint128_t>(0), 5) == std::pair<uint64_t, int>{0, 12});
    std::printf("cut oracle: %u comparisons\n", count);
}

void append(std::vector<unsigned char> &v, const void *p, size_t count) {
    const auto *bytes = static_cast<const unsigned char *>(p);
    v.insert(v.end(), bytes, bytes + count);
}

// A single slice at either end of the 64-bit address space, with an independent
// bottom-up root calculation. Distinct sibling hashes expose walk-order mistakes.
void boundary_slices() {
    for (const auto fn : {hash_function_type::keccak256, hash_function_type::sha256}) {
        for (int size = 5; size <= 12; ++size) {
            for (uint64_t address : {UINT64_C(0), UINT64_MAX & ~((UINT64_C(1) << size) - 1)}) {
                const step_log_header header{STEP_LOG_SIGNATURE, static_cast<uint64_t>(fn), 1, 0,
                    static_cast<uint64_t>(64 - size)};
                const slice_entry_header entry{address, static_cast<uint64_t>(size)};
                std::vector<unsigned char> data(UINT64_C(1) << size, 0xab), wire;
                const machine_hash zero{};
                std::array<machine_hash, 64> siblings{};
                for (int level = size; level < 64; ++level) {
                    siblings[level].fill(static_cast<unsigned char>(level));
                }
                append(wire, &header, sizeof(header));
                append(wire, &entry, sizeof(entry));
                append(wire, data.data(), data.size());
                append(wire, &zero, sizeof(zero));
                for (int i = 0; i < 64 - size; ++i) {
                    const int level = address == 0 ? size + i : 63 - i;
                    append(wire, &siblings[level], sizeof(machine_hash));
                }
                variant_hasher hasher{fn};
                machine_hash root{};
                get_merkle_tree_hash(hasher, std::span<const unsigned char>{data}, HASH_TREE_WORD_SIZE, root);
                for (int level = size; level < 64; ++level) {
                    machine_hash parent{};
                    if (address == 0) {
                        get_concat_hash(hasher, root, siblings[level], parent);
                    } else {
                        get_concat_hash(hasher, siblings[level], root, parent);
                    }
                    root = parent;
                }
                std::array<slice_entry, 1> slices{};
                require(step_log::get_slice_count(wire.data(), wire.size()) == 1);
                rejects([&] { step_log::decode(wire.data(), wire.size(), {}); },
                    "slice count exceeds descriptor storage capacity");
                auto unaligned = wire;
                unaligned.insert(unaligned.begin(), 0);
                require(step_log::decode(unaligned.data() + 1, unaligned.size() - 1, slices).root_hash_before == root);
                auto replay_wire = wire;
                auto log = step_log::decode(wire.data(), wire.size(), slices);
                require(log.root_hash_before == root);
                require(log.find_data(address, data.size()) == log.pages[0].data);
                require(log.find_data(address + data.size() - 8, 8) == log.pages[0].data + data.size() - 8);
                rejects([&] { log.pages[0].find_data(address - 1, 1); }, "access outside witnessed slice");
                rejects([&] { log.pages[0].find_data(address, data.size() + 1); }, "access outside witnessed slice");
                rejects([&] { log.pages[0].find_data(address + data.size() - 8, 9); },
                    "access outside witnessed slice");
                rejects([&] { log.pages[0].find_data(address, UINT64_MAX); }, "access outside witnessed slice");
                // Exercise the resolved-value cache at both address-space ends,
                // including an accessor copy and a word straddling a slice boundary.
                replay_step_state_access<>::context context{};
                std::array<slice_entry, 1> replay_slices{};
                replay_step_state_access<> replay{context, replay_wire.data(), replay_wire.size(), replay_slices};
                auto copy = replay;
                uint64_t value{};
                replay.read_memory_word(address, 0, &value);
                require(value == UINT64_C(0xabababababababab));
                if (size < 12) {
                    const auto outside = address == 0 ? data.size() - 4 : address - 4;
                    rejects([&] { copy.read_memory_word<uint64_t, uint32_t>(outside, 0, &value); },
                        "access outside witnessed slice");
                    rejects([&] { copy.write_memory_word<uint64_t, uint32_t>(outside, 0, UINT64_C(1)); },
                        "access outside witnessed slice");
                }
                const auto last = address + data.size() - 8;
                copy.write_memory_word(last, 0, UINT64_C(42));
                replay.read_memory_word(last, 0, &value);
                require(value == 42 && *context.log.pages[0].hash == zero);
                require(context.log.compute_root_hash() != root);
                wire[0] = 0;
                rejects([&] { step_log::decode(wire.data(), wire.size(), slices); }, "invalid step log signature");
            }
        }
    }
    std::puts("boundary slices: both hash functions, all sizes, both address-space ends");
}

// Floor 12 retains the v3 page set, all first-touch bytes and the same page-level
// proof. Build the reference from the machine, independently of recorder finish().
void full_page_equivalence() {
    machine_config config;
    config.ram.length = 1 << 20;
    machine m{config};
    const auto before = m.get_root_hash();
    for (int floor : {4, 13}) {
        rejects([&] { step_log_recorder invalid{hash_function_type::keccak256, m, floor}; },
            "step log slice floor out of range");
    }
    constexpr std::array<uint64_t, 3> indices = {0, AR_RAM_START >> 12, (AR_RAM_START >> 12) + 3};
    std::array<std::array<unsigned char, 4096>, 3> saved{};
    step_log_recorder recorder{hash_function_type::keccak256, m, 12};
    for (size_t i = 0; i < indices.size(); ++i) {
        m.read_memory(indices[i] << 12, saved[i].data(), saved[i].size());
        recorder.touch_page((indices[i] << 12) + 88);
    }
    std::vector<machine_hash> siblings;
    std::function<void(uint64_t, int)> visit = [&](uint64_t first, int height) {
        bool contains = false;
        for (auto index : indices) {
            contains |= index >= first && index - first < (UINT64_C(1) << height);
        }
        if (!contains) {
            siblings.push_back(m.get_node_hash(first << 12, height + 12));
        } else if (height > 0) {
            visit(first, height - 1);
            visit(first + (UINT64_C(1) << (height - 1)), height - 1);
        }
    };
    visit(0, 52);
    const uint64_t replacement = 0x1122334455667788;
    m.write_memory(AR_RAM_START + 88, reinterpret_cast<const unsigned char *>(&replacement), sizeof(replacement));
    auto wire = recorder.finish();
    std::array<slice_entry, 3> slices{};
    auto log = step_log::decode(wire.data(), wire.size(), slices);
    require(log.root_hash_before == before && log.pages.size() == indices.size());
    require(std::ranges::equal(log.siblings, siblings));
    for (size_t i = 0; i < indices.size(); ++i) {
        require(log.pages[i].page_index() == indices[i] && log.pages[i].log2_size == 12);
        require(std::memcmp(log.pages[i].data, saved[i].data(), 4096) == 0);
    }
    require(log.compute_root_hash() == before);
    std::memcpy(log.find_data(AR_RAM_START + 88), &replacement, sizeof(replacement));
    *log.find_page(AR_RAM_START)->hash = machine_hash{};
    require(log.compute_root_hash() == m.get_root_hash());
    std::puts("floor 12: page set, contents, siblings and roots equal to page-level reference");
}
} // namespace

int main() {
    cuts();
    boundary_slices();
    full_page_equivalence();
}
