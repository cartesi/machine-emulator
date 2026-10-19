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
#include "shadow-uarch-state.hpp"
#include "step-log-data.hpp"
#include "step-log-slice.hpp"
#include "step-log.hpp"

namespace cartesi {

/// \class step_log_recorder
/// \brief Collects the pages, nodes and sibling hashes a recorded step touches into a binary step log.
class step_log_recorder {
    using page_data_type = std::array<uint8_t, HASH_TREE_PAGE_SIZE>;
    struct recorded_page {
        page_data_type data{};
        uint128_t touched{};
    };
    using pages_type = std::map<uint64_t, recorded_page>;
    using nodes_type = std::map<uint64_t, node_entry>;
    using sibling_hashes_type = hash_tree::sibling_hashes_type;
    using slices_type = std::vector<slice_entry_header>;

    int m_log2_floor;                   ///< Minimum recorded slice size (verifiers accept every legal size)
    hash_function_type m_hash_function; ///< Hash function type to use for the log
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m;               ///< Machine being recorded
    pages_type m_touched_pages; ///< Copy of all pages touched during execution
    nodes_type m_touched_nodes; ///< Subtrees touched during execution

public:
    static constexpr int LOG2_SLICE_FLOOR = 9;

    /// \brief Constructor
    /// \param hash_function hash function type to use for the log
    /// \param m machine being recorded
    /// \param log2_floor minimum slice size, in log2 bytes (5..12)
    /// \details The log is serialized when finish() is called
    // The optional floor argument is for tests; production uses LOG2_SLICE_FLOOR.
    step_log_recorder(hash_function_type hash_function, machine &m, int log2_floor = LOG2_SLICE_FLOOR) :
        m_log2_floor(log2_floor),
        m_hash_function(hash_function),
        m_m(m) {
        if (log2_floor < HASH_TREE_LOG2_WORD_SIZE || log2_floor > HASH_TREE_LOG2_PAGE_SIZE) {
            throw std::invalid_argument("step log slice floor out of range");
        }
    }

    /// Save the page before the first access or replay address-mapping dependency.
    void save_page(uint64_t address) {
        auto page = address & ~PAGE_OFFSET_MASK;
        if (m_touched_pages.contains(page)) {
            return; // already saved
        }
        // get first node with starting address > page or end of map
        auto node_it = m_touched_nodes.upper_bound(page);
        if (node_it != m_touched_nodes.begin()) {
            const auto prev_node_it = std::prev(node_it);
            const auto prev_node_end = prev_node_it->first + (UINT64_C(1) << prev_node_it->second.log2_size);
            // Reject if the page falls inside a previously recorded node's range.
            if (prev_node_end > page) {
                throw std::runtime_error("page falls inside a recorded node's range");
            }
        }
        auto [it, _] = m_touched_pages.emplace(page, recorded_page{});
        m_m.read_memory(page, it->second.data.data(), it->second.data.size());
    }

    /// Mark every leaf read or written; retain the full first-touch preimage until finish().
    void touch_page(uint64_t address, uint64_t length = sizeof(uint64_t)) {
        while (length != 0) {
            const auto page = address & ~PAGE_OFFSET_MASK;
            const auto offset = address & PAGE_OFFSET_MASK;
            const auto count = std::min(length, HASH_TREE_PAGE_SIZE - offset);
            save_page(address);
            auto &saved = m_touched_pages.at(page);
            const auto first = offset >> HASH_TREE_LOG2_WORD_SIZE;
            const auto last = (offset + count - 1) >> HASH_TREE_LOG2_WORD_SIZE;
            for (auto leaf = first; leaf <= last; ++leaf) {
                saved.touched |= static_cast<uint128_t>(1) << leaf;
            }
            // Solidity's dedicated register cache loads and flushes this whole window.
            if (page == AR_SHADOW_UARCH_STATE_START) {
                constexpr auto leaves = (sizeof(shadow_uarch_state) + HASH_TREE_WORD_SIZE - 1) / HASH_TREE_WORD_SIZE;
                saved.touched |= (static_cast<uint128_t>(1) << leaves) - 1;
            }
            address += count;
            length -= count;
        }
    }

    /// \brief Record that the subtree at (address, log2_size) is being touched.
    /// \param address Subtree start address, must be aligned to 2^log2_size
    /// \param log2_size Log2 of the subtree size. Must be > HASH_TREE_LOG2_PAGE_SIZE and < HASH_TREE_LOG2_ROOT_SIZE.
    /// \details Captures the subtree's current hash.
    /// Rejects overlaps with existing nodes and enclosure of touched pages so
    /// the "pages and nodes are pairwise disjoint" invariant holds at replay.
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
        const auto node_end = address + node_size;
        // get first node with starting address >= address or end of map
        auto next_node_it = m_touched_nodes.lower_bound(address);
        // Reject if the next node starts inside this node's range.
        if (next_node_it != m_touched_nodes.end() && next_node_it->first < node_end) {
            throw std::runtime_error("node overlaps an existing node");
        }
        if (next_node_it != m_touched_nodes.begin()) {
            const auto prev_node_it = std::prev(next_node_it);
            const auto prev_node_end = prev_node_it->first + (UINT64_C(1) << prev_node_it->second.log2_size);
            // Reject if the previous node's range extends into this node's range.
            if (prev_node_end > address) {
                throw std::runtime_error("node overlaps an existing node");
            }
        }
        // get first page with starting address >= address or end of map
        auto next_page_it = m_touched_pages.lower_bound(address);
        // Reject if any existing page lies inside the node's range.
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
        slices_type slices;
        uint64_t slices_bytes = 0;
        for (const auto &[address, page] : m_touched_pages) {
            const auto [offset, log2_size] = select_page_slice(page.touched, m_log2_floor);
            slices.push_back({address + offset, static_cast<uint64_t>(log2_size)});
            slices_bytes += sizeof(slice_entry_header) + (UINT64_C(1) << log2_size) + sizeof(machine_hash);
        }
        auto sibling_hashes = get_sibling_hashes(slices);

        const step_log_header header{
            .signature = STEP_LOG_SIGNATURE,
            .hash_function = static_cast<uint64_t>(m_hash_function),
            .page_count = m_touched_pages.size(),
            .node_count = m_touched_nodes.size(),
            .sibling_count = sibling_hashes.size(),
        };
        step_log_data log;
        log.reserve(sizeof(header) + slices_bytes + (m_touched_nodes.size() * sizeof(node_entry)) +
            (sibling_hashes.size() * sizeof(machine_hash)));
        const auto append = [&log](const void *data, size_t size) {
            const auto *bytes = static_cast<const unsigned char *>(data);
            log.insert(log.end(), bytes, bytes + size);
        };
        append(&header, sizeof(header));
        for (const auto &slice : slices) {
            const auto page = slice.address & ~PAGE_OFFSET_MASK;
            const auto offset = slice.address & PAGE_OFFSET_MASK;
            const machine_hash zero{};
            append(&slice, sizeof(slice));
            append(m_touched_pages.at(page).data.data() + offset, UINT64_C(1) << slice.log2_size);
            append(&zero, sizeof(zero));
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
    sibling_hashes_type get_sibling_hashes(const slices_type &slices) {
        sibling_hashes_type hashes;
        size_t next_slice = 0;
        auto next_node = m_touched_nodes.cbegin();
        get_sibling_hashes_impl(0, HASH_TREE_LOG2_ROOT_SIZE, slices, next_slice, next_node, hashes);
        if (next_slice != slices.size() || next_node != m_touched_nodes.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all slices or nodes");
        }
        return hashes;
    }

    /// Whole-tree walk; intra-page siblings come from the saved preimage.
    void get_sibling_hashes_impl(uint64_t address, int log2_size, const slices_type &slices, size_t &next_slice,
        nodes_type::const_iterator &next_node, sibling_hashes_type &hashes) {
        const uint128_t end = static_cast<uint128_t>(address) + (static_cast<uint128_t>(1) << log2_size);
        const bool slice_in = next_slice < slices.size() && slices[next_slice].address < end;
        const bool node_in = next_node != m_touched_nodes.cend() && next_node->first < end;
        if (!slice_in && !node_in) {
            if (log2_size < HASH_TREE_LOG2_PAGE_SIZE) {
                const auto &page = m_touched_pages.at(address & ~PAGE_OFFSET_MASK);
                machine_hash hash{};
                merkle_tree_hash(m_hash_function, page.data.data() + (address & PAGE_OFFSET_MASK),
                    UINT64_C(1) << log2_size, reinterpret_cast<hash_type>(&hash));
                hashes.push_back(hash);
            } else {
                hashes.push_back(m_m.get_node_hash(address, log2_size, skip_hash_tree_update));
            }
        } else if (node_in && next_node->first == address && std::cmp_equal(next_node->second.log2_size, log2_size)) {
            ++next_node;
        } else if (slice_in && slices[next_slice].address == address &&
            std::cmp_equal(slices[next_slice].log2_size, log2_size)) {
            ++next_slice;
        } else {
            get_sibling_hashes_impl(address, log2_size - 1, slices, next_slice, next_node, hashes);
            get_sibling_hashes_impl(address + (UINT64_C(1) << (log2_size - 1)), log2_size - 1, slices, next_slice,
                next_node, hashes);
        }
    }
};

} // namespace cartesi

#endif
