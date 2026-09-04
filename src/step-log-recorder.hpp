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
#include "step-log.hpp"

namespace cartesi {

/// \class step_log_recorder
/// \brief Collects the pages, nodes and sibling hashes a recorded step touches and writes them as a
/// binary step log. The recording state accessors adapt their interface calls onto it.
class step_log_recorder {
    using page_data_type = std::array<uint8_t, HASH_TREE_PAGE_SIZE>;
    using pages_type = std::map<uint64_t, page_data_type>;
    using nodes_type = std::map<uint64_t, node_entry>;
    using sibling_hashes_type = hash_tree::sibling_hashes_type;
    using page_indices_type = std::vector<uint64_t>;

    hash_function_type m_hash_function; ///< Hash function type to use for the log
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m;               ///< Machine being recorded
    pages_type m_touched_pages; ///< Copy of all pages touched during execution
    nodes_type m_touched_nodes; ///< Subtrees touched during execution

public:
    /// \brief Constructor
    /// \param hash_function hash function type to use for the log
    /// \param m machine being recorded
    /// \details The log is serialized when finish() is called
    step_log_recorder(hash_function_type hash_function, machine &m) : m_hash_function(hash_function), m_m(m) {
        ;
    }

    /// \brief Mark a page as touched and save its contents
    /// \param address address inside the page
    void touch_page(uint64_t address) {
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
        auto [it, _] = m_touched_pages.emplace(page, page_data_type());
        m_m.read_memory(page, it->second.data(), it->second.size());
    }

    /// \brief Record that the subtree at (address, log2_size) is being touched.
    /// \param address Subtree start address, must be aligned to 2^log2_size
    /// \param log2_size Log2 of the subtree size. Must be > PAGE_SIZE and < ROOT_SIZE.
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
    std::vector<unsigned char> finish() {
        auto sibling_hashes = get_sibling_hashes();

        const step_log_header header{
            .signature = STEP_LOG_SIGNATURE,
            .hash_function = static_cast<uint64_t>(m_hash_function),
            .page_count = m_touched_pages.size(),
            .node_count = m_touched_nodes.size(),
            .sibling_count = sibling_hashes.size(),
        };
        std::vector<unsigned char> log;
        log.reserve(sizeof(header) + (m_touched_pages.size() * sizeof(page_entry)) +
            (m_touched_nodes.size() * sizeof(node_entry)) + (sibling_hashes.size() * sizeof(machine_hash)));
        const auto append = [&log](const void *data, size_t size) {
            const auto *bytes = static_cast<const unsigned char *>(data);
            log.insert(log.end(), bytes, bytes + size);
        };
        append(&header, sizeof(header));
        for (const auto &[address, data] : m_touched_pages) {
            page_entry entry{
                .index = address >> HASH_TREE_LOG2_PAGE_SIZE,
                .data = {},
                .hash = {}, // scratch; replayer fills this in from the data
            };
            std::copy_n(data.data(), data.size(), entry.data);
            append(&entry, sizeof(entry));
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
    /// \brief Collect the sibling hashes needed to reconstruct the root hash from touched pages and nodes.
    /// \details Walks the tree with three cursors (pages, nodes, siblings).
    /// A subtree whose range exactly matches a recorded node is consumed as a node
    /// (no sibling emitted). Subtrees with no touched content emit one sibling hash.
    /// Recursion descends into subtrees that contain at least one touched page or node.
    sibling_hashes_type get_sibling_hashes() {
        sibling_hashes_type sibling_hashes{};
        page_indices_type page_indices{};
        for (const auto &[address, _] : m_touched_pages) {
            page_indices.push_back(address >> HASH_TREE_LOG2_PAGE_SIZE);
        }
        auto next_page_index = page_indices.cbegin();
        auto next_node_it = m_touched_nodes.cbegin();
        get_sibling_hashes_impl(0, HASH_TREE_LOG2_ROOT_SIZE - HASH_TREE_LOG2_PAGE_SIZE, page_indices, next_page_index,
            next_node_it, sibling_hashes);
        if (next_page_index != page_indices.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all pages");
        }
        if (next_node_it != m_touched_nodes.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all nodes");
        }
        return sibling_hashes;
    }

    /// \brief Recursively collect sibling hashes for the subtree rooted at page_index
    /// \param page_index Index of the first page in the subtree
    /// \param page_count_log2_size Log2 of the number of pages in the subtree
    /// \param page_indices All touched page indices, sorted ascending
    /// \param next_page_index Cursor into page_indices; advances past each page consumed during recursion
    /// \param next_node_it Cursor into touched nodes; advances past each node consumed during recursion
    /// \param sibling_hashes Accumulates sibling hashes for untouched subtrees
    void get_sibling_hashes_impl(uint64_t page_index, int page_count_log2_size, page_indices_type &page_indices,
        page_indices_type::const_iterator &next_page_index, nodes_type::const_iterator &next_node_it,
        sibling_hashes_type &sibling_hashes) {
        const auto subtree_start_addr = page_index << HASH_TREE_LOG2_PAGE_SIZE;
        const auto subtree_log2_size = page_count_log2_size + HASH_TREE_LOG2_PAGE_SIZE;
        const auto page_count = UINT64_C(1) << page_count_log2_size;
        const auto subtree_end_page_index = page_index + page_count;

        // next unconsumed page / node is inside this subtree?
        const bool page_in = next_page_index != page_indices.cend() && *next_page_index < subtree_end_page_index;
        // shift node address into page-index units to compare with subtree_end_page_index
        const bool node_in = next_node_it != m_touched_nodes.cend() &&
            (next_node_it->first >> HASH_TREE_LOG2_PAGE_SIZE) < subtree_end_page_index;

        if (!page_in && !node_in) {
            sibling_hashes.push_back(m_m.get_node_hash(subtree_start_addr, subtree_log2_size, skip_hash_tree_update));
        } else if (node_in && next_node_it->first == subtree_start_addr &&
            std::cmp_equal(next_node_it->second.log2_size, subtree_log2_size)) {
            ++next_node_it;
        } else if (page_count_log2_size > 0) {
            get_sibling_hashes_impl(page_index, page_count_log2_size - 1, page_indices, next_page_index, next_node_it,
                sibling_hashes);
            get_sibling_hashes_impl(page_index + (UINT64_C(1) << (page_count_log2_size - 1)), page_count_log2_size - 1,
                page_indices, next_page_index, next_node_it, sibling_hashes);
        } else {
            ++next_page_index;
        }
    }
};

} // namespace cartesi

#endif
