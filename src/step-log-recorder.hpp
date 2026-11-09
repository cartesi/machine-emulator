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

#ifndef STEP_LOG_RECORDER_HPP
#define STEP_LOG_RECORDER_HPP

/// \file
/// \brief Collects the witness of a recorded step and serializes it as a binary step log

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "hash-tree-constants.hpp"
#include "hash-tree.hpp"
#include "machine-hash.hpp"
#include "machine.hpp"
#include "step-log-data.hpp"
#include "step-log.hpp"
#include "uint128.hpp"

namespace cartesi {

/// \brief Smallest aligned piece of a page, not below 2^log2_min_size bytes, that contains every touched word.
/// Returns (offset in page, log2 size).
inline std::pair<uint64_t, int> select_page_slice(uint128_t touched, int log2_min_size) {
    uint64_t offset = 0;
    int log2_size = HASH_TREE_LOG2_PAGE_SIZE;
    while (log2_size > log2_min_size) {
        const auto half_words = UINT64_C(1) << (log2_size - HASH_TREE_LOG2_WORD_SIZE - 1);
        const auto left = touched & ((static_cast<uint128_t>(1) << half_words) - 1);
        const auto right = touched >> half_words;
        const bool left_touched = left != 0;
        const bool right_touched = right != 0;
        // Both halves touched: the slice cannot shrink.
        if (left_touched == right_touched) {
            break;
        }
        --log2_size;
        if (!left_touched) {
            offset += UINT64_C(1) << log2_size;
            touched = right;
        } else {
            touched = left;
        }
    }
    return {offset, log2_size};
}

/// \class step_log_recorder
/// \brief Records witnessed slices, subtree-write nodes and sibling hashes in a binary step log.
/// \details Each page is saved whole before its first access, and the recorder tracks which of its
/// 32-byte words the step reads or writes. finish() witnesses, per page, the smallest aligned slice
/// that contains those words, not below the minimum slice size; everything the step did not touch
/// is covered by sibling hashes.
class step_log_recorder {
    using page_data_type = std::array<uint8_t, HASH_TREE_PAGE_SIZE>;
    struct recorded_page {
        page_data_type data{}; ///< Page contents before the first access
        uint128_t touched{};   ///< One bit per 32-byte word read or written
    };
    using pages_type = std::map<uint64_t, recorded_page>;
    using nodes_type = std::map<uint64_t, node_entry>;
    using sibling_hashes_type = hash_tree::sibling_hashes_type;
    using slices_type = std::vector<slice_entry>;

    int m_log2_min_slice_size;
    hash_function_type m_hash_function;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Machine being recorded
    pages_type m_touched_pages;
    nodes_type m_touched_nodes;

public:
    // Default minimum slice size, 512 bytes. Verifiers accept slices down to one word,
    // so this can change without a format change.
    static constexpr int LOG2_MIN_SLICE_SIZE = 9;

    /// \param hash_function hash function type to use for the log
    /// \param m machine being recorded
    /// \param log2_min_slice_size minimum slice size, in log2 bytes (5..12); machine steps pass the page size
    /// \details The log is serialized when finish() is called
    step_log_recorder(hash_function_type hash_function, machine &m, int log2_min_slice_size = LOG2_MIN_SLICE_SIZE) :
        m_log2_min_slice_size(log2_min_slice_size),
        m_hash_function(hash_function),
        m_m(m) {
        if (log2_min_slice_size < HASH_TREE_LOG2_WORD_SIZE || log2_min_slice_size > HASH_TREE_LOG2_PAGE_SIZE) {
            throw std::invalid_argument("minimum slice size out of range");
        }
    }

    /// \brief Mark the words of [address, address + length) as read or written, saving each page before its
    /// first access. The range may span pages.
    void touch_range(uint64_t address, uint64_t length) {
        while (length != 0) {
            const auto offset = address & PAGE_OFFSET_MASK;
            const auto count = std::min(length, HASH_TREE_PAGE_SIZE - offset);
            auto &saved = save_page(address);
            const auto first = offset >> HASH_TREE_LOG2_WORD_SIZE;
            const auto last = (offset + count - 1) >> HASH_TREE_LOG2_WORD_SIZE;
            for (auto word = first; word <= last; ++word) {
                saved.touched |= static_cast<uint128_t>(1) << word;
            }
            address += count;
            length -= count;
        }
    }

    /// \brief Mark the whole page containing address as touched, saving it before its first access.
    void touch_page(uint64_t address) {
        save_page(address).touched = ~uint128_t{0};
    }

    /// \brief Record that the subtree at (address, log2_size) is being touched.
    /// \param address Subtree start address, must be aligned to 2^log2_size
    /// \param log2_size Log2 of the subtree size. Must be > HASH_TREE_LOG2_PAGE_SIZE and < HASH_TREE_LOG2_ROOT_SIZE.
    /// \details Rejects overlaps with existing nodes and enclosure of touched pages so
    /// the "slices and nodes are pairwise disjoint" invariant holds at replay.
    void touch_node(uint64_t address, int log2_size) {
        // A root-sized node would enclose every page, so the recorder never produces one;
        // rejecting it also keeps the shift below well defined.
        if (log2_size <= HASH_TREE_LOG2_PAGE_SIZE || log2_size >= HASH_TREE_LOG2_ROOT_SIZE) {
            throw std::runtime_error("node log2 size is out of range");
        }
        const auto node_size = UINT64_C(1) << log2_size;
        if ((address & (node_size - 1)) != 0) {
            throw std::runtime_error("node address is not aligned to its size");
        }
        const auto node_end = get_node_end(address, log2_size);
        // get first node with starting address >= address or end of map
        auto next_node_it = m_touched_nodes.lower_bound(address);
        if (next_node_it != m_touched_nodes.end() && next_node_it->first < node_end) {
            throw std::runtime_error("node overlaps an existing node");
        }
        if (next_node_it != m_touched_nodes.begin()) {
            const auto prev_node_it = std::prev(next_node_it);
            const auto prev_node_end = get_node_end(prev_node_it->first, prev_node_it->second.log2_size);
            if (prev_node_end > address) {
                throw std::runtime_error("node overlaps an existing node");
            }
        }
        // get first page with starting address >= address or end of map
        auto next_page_it = m_touched_pages.lower_bound(address);
        if (next_page_it != m_touched_pages.end() && next_page_it->first < node_end) {
            throw std::runtime_error("node would enclose an existing page");
        }
        m_touched_nodes.emplace(address,
            node_entry{
                .address = address,
                .log2_size = static_cast<uint64_t>(log2_size),
                .hash = m_m.get_node_hash(address, log2_size, skip_hash_tree_update),
            });
    }

    /// \brief Finish recording and return the binary step log
    step_log_data finish() {
        // Choose one slice per saved page.
        slices_type slices;
        uint64_t data_bytes = 0;
        for (const auto &[address, page] : m_touched_pages) {
            const auto [offset, log2_size] = select_page_slice(page.touched, m_log2_min_slice_size);
            slices.push_back({.address = address + offset,
                .log2_size = static_cast<uint64_t>(log2_size),
                .data_offset = data_bytes,
                .hash = {}});
            data_bytes += UINT64_C(1) << log2_size;
        }
        // Collect the sibling hashes of everything else.
        auto sibling_hashes = get_sibling_hashes(slices);

        const step_log_header header{
            .signature = STEP_LOG_SIGNATURE,
            .hash_function = static_cast<uint64_t>(m_hash_function),
            .slice_count = m_touched_pages.size(),
            .node_count = m_touched_nodes.size(),
            .sibling_count = sibling_hashes.size(),
        };
        step_log_data log;
        const auto slice_table_bytes = slices.size() * sizeof(slice_entry);
        const auto node_bytes = m_touched_nodes.size() * sizeof(node_entry);
        const auto sibling_bytes = sibling_hashes.size() * sizeof(machine_hash);
        log.reserve(sizeof(header) + slice_table_bytes + data_bytes + node_bytes + sibling_bytes);
        // Serialize in wire order: header, slice table, slice data, nodes, siblings.
        const auto append = [&log](const void *data, size_t size) {
            const auto *bytes = static_cast<const unsigned char *>(data);
            log.insert(log.end(), bytes, bytes + size);
        };
        append(&header, sizeof(header));
        for (const auto &slice : slices) {
            append(&slice, sizeof(slice));
        }
        for (const auto &slice : slices) {
            const auto page = slice.address & ~PAGE_OFFSET_MASK;
            const auto offset = slice.address & PAGE_OFFSET_MASK;
            append(m_touched_pages.at(page).data.data() + offset, UINT64_C(1) << slice.log2_size);
        }
        for (const auto &[_, node] : m_touched_nodes) {
            append(&node, sizeof(node));
        }
        if (!sibling_hashes.empty()) {
            append(sibling_hashes.data(), sibling_hashes.size() * sizeof(machine_hash));
        }
        return log;
    }

private:
    /// \brief Copy the page contents on its first access and return its record.
    recorded_page &save_page(uint64_t address) {
        auto page = address & ~PAGE_OFFSET_MASK;
        if (auto it = m_touched_pages.find(page); it != m_touched_pages.end()) {
            return it->second;
        }
        // get first node with starting address > page or end of map
        auto node_it = m_touched_nodes.upper_bound(page);
        if (node_it != m_touched_nodes.begin()) {
            const auto prev_node_it = std::prev(node_it);
            const auto prev_node_end = get_node_end(prev_node_it->first, prev_node_it->second.log2_size);
            if (prev_node_end > page) {
                throw std::runtime_error("page falls inside a recorded node's range");
            }
        }
        auto [it, _] = m_touched_pages.emplace(page, recorded_page{});
        m_m.read_memory(page, it->second.data.data(), it->second.data.size());
        return it->second;
    }

    // 128 bits: a node may end exactly at 2^64.
    static uint128_t get_node_end(uint64_t address, uint64_t log2_size) {
        return static_cast<uint128_t>(address) + (UINT64_C(1) << log2_size);
    }

    sibling_hashes_type get_sibling_hashes(const slices_type &slices) {
        sibling_hashes_type siblings;
        size_t next_slice = 0;
        auto next_node = m_touched_nodes.cbegin();
        get_sibling_hashes_impl(0, HASH_TREE_LOG2_ROOT_SIZE, slices, next_slice, next_node, siblings);
        if (next_slice != slices.size() || next_node != m_touched_nodes.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all slices or nodes");
        }
        return siblings;
    }

    /// \brief Collect, in address order, the hash of every subtree that contains no slice and no node.
    void get_sibling_hashes_impl(uint64_t address, int log2_size, const slices_type &slices, size_t &next_slice,
        nodes_type::const_iterator &next_node, sibling_hashes_type &siblings) {
        const uint128_t end = static_cast<uint128_t>(address) + (static_cast<uint128_t>(1) << log2_size);
        const bool slice_in = next_slice < slices.size() && slices[next_slice].address < end;
        const bool node_in = next_node != m_touched_nodes.cend() && next_node->first < end;
        if (!slice_in && !node_in) {
            // Inside a saved page, hash the saved copy: the sibling must reflect the state before the step,
            // and the live page may have changed. Whole untouched pages and larger subtrees come from
            // the machine's hash tree.
            if (log2_size < HASH_TREE_LOG2_PAGE_SIZE) {
                const auto &page = m_touched_pages.at(address & ~PAGE_OFFSET_MASK);
                machine_hash hash{};
                merkle_tree_hash(m_hash_function, page.data.data() + (address & PAGE_OFFSET_MASK),
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    UINT64_C(1) << log2_size, reinterpret_cast<hash_type>(&hash));
                siblings.push_back(hash);
            } else {
                siblings.push_back(m_m.get_node_hash(address, log2_size, skip_hash_tree_update));
            }
        } else if (node_in && next_node->first == address && std::cmp_equal(next_node->second.log2_size, log2_size)) {
            ++next_node;
        } else if (slice_in && slices[next_slice].address == address &&
            std::cmp_equal(slices[next_slice].log2_size, log2_size)) {
            ++next_slice;
        } else {
            get_sibling_hashes_impl(address, log2_size - 1, slices, next_slice, next_node, siblings);
            get_sibling_hashes_impl(address + (UINT64_C(1) << (log2_size - 1)), log2_size - 1, slices, next_slice,
                next_node, siblings);
        }
    }
};

} // namespace cartesi

#endif
