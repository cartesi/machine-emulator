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
#include "step-log.hpp"
#include "uarch-record-step-state-access.hpp"
#include "uarch-step.hpp"

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
std::pair<uint64_t, int> oracle(uint128_t mask, int log2_min_slice_size) {
    if (mask == 0) {
        return {0, 12};
    }
    for (int size = log2_min_slice_size; size <= 12; ++size) {
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
            for (int log2_min_slice_size = 5; log2_min_slice_size <= 12; ++log2_min_slice_size) {
                const auto touched = static_cast<uint128_t>(mask) << start;
                require(select_page_slice(touched, log2_min_slice_size) == oracle(touched, log2_min_slice_size));
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
                const slice_entry entry{address, static_cast<uint64_t>(size), 0, {}};
                std::vector<unsigned char> data(UINT64_C(1) << size, 0xab), wire;
                const machine_hash zero{};
                std::array<machine_hash, 64> siblings{};
                for (int level = size; level < 64; ++level) {
                    siblings[level].fill(static_cast<unsigned char>(level));
                }
                append(wire, &header, sizeof(header));
                append(wire, &entry, sizeof(entry));
                append(wire, data.data(), data.size());
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
                auto bad_offset = wire;
                const uint64_t invalid_offset = 8;
                std::memcpy(bad_offset.data() + sizeof(header) + offsetof(slice_entry, data_offset), &invalid_offset,
                    sizeof(invalid_offset));
                rejects([&] { step_log::decode(bad_offset.data(), bad_offset.size()); }, "slice data offset mismatch");
                auto short_data = wire;
                short_data.resize(sizeof(header) + sizeof(entry) + data.size() - 1);
                rejects([&] { step_log::decode(short_data.data(), short_data.size()); }, "truncated slice data");
                auto unaligned = wire;
                unaligned.insert(unaligned.begin(), 0);
                require(step_log::decode(unaligned.data() + 1, unaligned.size() - 1).root_hash_before == root);
                auto replay_wire = wire;
                auto log = step_log::decode(wire.data(), wire.size());
                require(log.root_hash_before == root);
                require(reinterpret_cast<unsigned char *>(log.slices.data()) == wire.data() + sizeof(header));
                require(log.data == wire.data() + sizeof(header) + sizeof(entry));
                require(log.find_data(address, data.size()) == log.get_data(log.slices[0]));
                require(log.find_data(address + data.size() - 8, 8) == log.get_data(log.slices[0]) + data.size() - 8);
                rejects([&] { log.find_data(log.slices[0], address - 1, 1); }, "access outside witnessed slice");
                rejects([&] { log.find_data(log.slices[0], address, data.size() + 1); },
                    "access outside witnessed slice");
                rejects([&] { log.find_data(log.slices[0], address + data.size() - 8, 9); },
                    "access outside witnessed slice");
                rejects([&] { log.find_data(log.slices[0], address, UINT64_MAX); }, "access outside witnessed slice");
                replay_step_state_access<>::context context{};
                if (size != 12) {
                    rejects([&] { replay_step_state_access<> replay{context, replay_wire.data(), replay_wire.size()}; },
                        "machine replay requires whole-page witnesses");
                    continue;
                }
                replay_step_state_access<> replay{context, replay_wire.data(), replay_wire.size()};
                auto copy = replay;
                uint64_t value{};
                replay.read_memory_word(replay.get_faddr(address, 0), 0, &value);
                require(value == UINT64_C(0xabababababababab));
                const auto last = address + data.size() - 8;
                copy.write_memory_word(copy.get_faddr(last, 0), 0, UINT64_C(42));
                replay.read_memory_word(replay.get_faddr(last, 0), 0, &value);
                require(value == 42 && context.log.slices[0].hash == zero);
                require(context.log.compute_root_hash() != root);
                wire[0] = 0;
                rejects([&] { step_log::decode(wire.data(), wire.size()); }, "invalid step log signature");
            }
        }
    }
    std::puts("boundary slices: both hash functions, all sizes, both address-space ends");
}

// A page-sized minimum slice size keeps every saved page whole, with all first-touch bytes and the
// page-level proof. Build the reference from the machine, independently of recorder finish().
void full_page_equivalence() {
    machine_config config;
    config.ram.length = 1 << 20;
    machine m{config};
    const auto before = m.get_root_hash();
    for (int log2_min_slice_size : {4, 13}) {
        rejects([&] { step_log_recorder invalid{hash_function_type::keccak256, m, log2_min_slice_size}; },
            "minimum slice size out of range");
    }
    constexpr std::array<uint64_t, 3> indices = {0, AR_RAM_START >> 12, (AR_RAM_START >> 12) + 3};
    std::array<std::array<unsigned char, 4096>, 3> saved{};
    step_log_recorder recorder{hash_function_type::keccak256, m, 12};
    for (size_t i = 0; i < indices.size(); ++i) {
        m.read_memory(indices[i] << 12, saved[i].data(), saved[i].size());
        recorder.touch_range((indices[i] << 12) + 88, sizeof(uint64_t));
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
    auto log = step_log::decode(wire.data(), wire.size());
    require(log.root_hash_before == before && log.slices.size() == indices.size());
    require(std::ranges::equal(log.siblings, siblings));
    for (size_t i = 0; i < indices.size(); ++i) {
        require(log.slices[i].page_index() == indices[i] && log.slices[i].log2_size == 12);
        require(log.slices[i].data_offset == i * 4096);
        require(std::memcmp(log.get_data(log.slices[i]), saved[i].data(), 4096) == 0);
    }
    require(log.compute_root_hash() == before);
    std::memcpy(log.find_data(AR_RAM_START + 88), &replacement, sizeof(replacement));
    log.find_slice(AR_RAM_START)->hash = machine_hash{};
    require(log.compute_root_hash() == m.get_root_hash());
    std::puts("4,096-byte minimum slice size: page set, contents, siblings and roots equal to page-level reference");
}

void uarch_registers_as_unit() {
    machine_config config;
    config.ram.length = 1 << 20;
    machine m{config};
    const uint32_t insn = 0x00100093; // addi x1, x0, 1: no access near the end of the register block.
    m.write_memory(UARCH_RAM_START_ADDRESS, reinterpret_cast<const unsigned char *>(&insn), sizeof(insn));
    const auto before = m.get_root_hash();
    step_log_recorder recorder{hash_function_type::keccak256, m, 5};
    const uarch_record_step_state_access record{recorder, m};
    require(uarch_step(record) == UArchStepStatus::Success);
    const auto after = m.get_root_hash();
    auto wire = recorder.finish();
    require(machine::verify_step_uarch(before, wire, 1) == after);
    auto log = step_log::decode(wire.data(), wire.size());
    const auto *slice = log.find_slice(AR_SHADOW_UARCH_STATE_START);
    require(slice->address == AR_SHADOW_UARCH_STATE_START);
    require((UINT64_C(1) << slice->log2_size) >= sizeof(shadow_uarch_state));
    std::puts("32-byte minimum slice size: uarch register unit covered and replay root matches");
}
void node_end_at_root_boundary() {
    machine_config config;
    config.ram.length = 1 << 20;
    machine m{config};
    m.get_root_hash();
    constexpr uint64_t high_half = UINT64_C(1) << 63;
    step_log_recorder outer{hash_function_type::keccak256, m};
    outer.touch_node(high_half, 63);
    rejects([&] { outer.touch_page(UINT64_MAX & ~PAGE_OFFSET_MASK); }, "page falls inside a recorded node's range");
    rejects([&] { outer.touch_node(high_half + (UINT64_C(1) << 62), 62); }, "node overlaps an existing node");
    step_log_recorder inner{hash_function_type::keccak256, m};
    inner.touch_node(high_half + (UINT64_C(1) << 62), 62);
    rejects([&] { inner.touch_node(high_half, 63); }, "node overlaps an existing node");
    std::puts("node overlap checks at the 2^64 boundary");
}
} // namespace

int main() {
    cuts();
    boundary_slices();
    full_page_equivalence();
    uarch_registers_as_unit();
    node_end_at_root_boundary();
}
