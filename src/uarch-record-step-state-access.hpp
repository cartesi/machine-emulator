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

#ifndef UARCH_RECORD_STEP_STATE_ACCESS_HPP
#define UARCH_RECORD_STEP_STATE_ACCESS_HPP

/// \file
/// \brief State access that records a uarch step into a binary step log file

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
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-uarch-state.hpp"
#include "i-uarch-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "machine.hpp"
#include "os-filesystem.hpp"
#include "os.hpp"
#include "scoped-note.hpp"
#include "shadow-tlb.hpp"
#include "shadow-uarch-state.hpp"
#include "step-log.hpp"
#include "uarch-constants.hpp"
#include "unique-c-ptr.hpp"

namespace cartesi {

/// \class uarch_record_step_state_access
/// \brief Records a single uarch step into a binary step log file
class uarch_record_step_state_access :
    public i_uarch_state_access<uarch_record_step_state_access>,
    public i_accept_scoped_notes<uarch_record_step_state_access>,
    public i_prefer_shadow_uarch_state<uarch_record_step_state_access> {

    using page_data_type = std::array<uint8_t, HASH_TREE_PAGE_SIZE>;
    using pages_type = std::map<uint64_t, page_data_type>;
    using sibling_hashes_type = hash_tree::sibling_hashes_type;
    using page_indices_type = std::vector<uint64_t>;
    using nodes_type = std::map<uint64_t, node_entry>;

public:
    struct context {
        /// \brief Constructor of uarch record step state access context
        /// \param filename where to save the log
        /// \param hash_function hash function type to use for the log
        explicit context(std::string filename, hash_function_type hash_function) :
            filename(std::move(filename)),
            hash_function(hash_function) {
            ;
        }
        std::string filename;             ///< Where to save the log
        hash_function_type hash_function; ///< Hash function type to use for the log
        mutable pages_type touched_pages; ///< Copy of all pages touched during execution
        mutable nodes_type touched_nodes; ///< Subtrees touched during execution
    };

private:
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    context &m_context; ///< Context for the recording
    machine &m_m;       ///< Reference to machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor of uarch record step state access
    /// \param context Context for the recording with the log filename
    /// \param m reference to machine
    /// \details The log file is saved when finish() is called
    uarch_record_step_state_access(context &context, machine &m) : m_context(context), m_m(m) {
        if (os::exists(m_context.filename)) {
            throw std::runtime_error("file already exists");
        }
    }

    /// \brief Finish recording and save the log file
    /// \param root_hash_before Root hash before the step
    /// \param requested_cycle_count Cycles requested by the caller (uarch_cycle delta for log_step_uarch,
    ///        0 for log_reset_uarch which is not a cycle-running operation)
    /// \param root_hash_after Root hash after the step
    void finish(const machine_hash &root_hash_before, uint64_t requested_cycle_count,
        const machine_hash &root_hash_after) {
        // Fill in hash_after for each node. The machine's hash tree was refreshed
        // by the outer get_root_hash call, so skip_hash_tree_update is safe.
        for (auto &[address, entry] : m_context.touched_nodes) {
            entry.hash_after = m_m.get_node_hash(address, static_cast<int>(entry.log2_size), skip_hash_tree_update);
        }
        auto sibling_hashes = get_sibling_hashes();

        const step_log_header header{
            .signature = STEP_LOG_SIGNATURE,
            .root_hash_before = root_hash_before,
            .requested_cycle_count = requested_cycle_count,
            .root_hash_after = root_hash_after,
            .hash_function = static_cast<uint64_t>(m_context.hash_function),
            .page_count = m_context.touched_pages.size(),
            .node_count = m_context.touched_nodes.size(),
            .sibling_count = sibling_hashes.size(),
        };
        auto fp = make_unique_fopen(m_context.filename.c_str(), "wb");
        if (fwrite(&header, sizeof(header), 1, fp.get()) != 1) {
            throw std::runtime_error("Could not write header to log file");
        }
        for (const auto &[address, data] : m_context.touched_pages) {
            page_entry entry{
                .index = address >> HASH_TREE_LOG2_PAGE_SIZE,
                .data = {},
                .hash = {}, // scratch; replayer fills this in from the data
            };
            std::copy_n(data.data(), data.size(), entry.data);
            if (fwrite(&entry, sizeof(entry), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page entry to log file");
            }
        }
        for (const auto &[_, node] : m_context.touched_nodes) {
            if (fwrite(&node, sizeof(node), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write node entry to log file");
            }
        }
        if (!sibling_hashes.empty() &&
            fwrite(sibling_hashes.data(), sizeof(machine_hash), sibling_hashes.size(), fp.get()) !=
                sibling_hashes.size()) {
            throw std::runtime_error("Could not write sibling hashes to log file");
        }
    }

private:
    /// \brief Mark a page as touched and save its contents
    /// \param address address inside the page
    void touch_page(uint64_t address) const {
        auto page = address & ~PAGE_OFFSET_MASK;
        if (m_context.touched_pages.contains(page)) {
            return;
        }

        // get first node with starting address > page or end of map
        auto node_it = m_context.touched_nodes.upper_bound(page);
        if (node_it != m_context.touched_nodes.begin()) {
            const auto prev_node_it = std::prev(node_it);
            const auto prev_node_end = prev_node_it->first + (UINT64_C(1) << prev_node_it->second.log2_size);
            // Reject if the page falls inside a previously recorded node's range.
            if (prev_node_end > page) {
                throw std::runtime_error("page falls inside a recorded node's range");
            }
        }
        auto [it, _] = m_context.touched_pages.emplace(page, page_data_type());
        m_m.read_memory(page, it->second.data(), it->second.size());
    }

    /// \brief Record that the subtree at (address, log2_size) is being touched.
    /// \param address subtree start address (must be aligned to 2^log2_size)
    /// \param log2_size log2 of the subtree size (must be > page size and <= root size)
    /// \details Captures the subtree's current hash as hash_before. hash_after is
    /// filled in during finish() once the machine's tree has been refreshed.
    void touch_node(uint64_t address, int log2_size) const {
        if (log2_size <= HASH_TREE_LOG2_PAGE_SIZE || log2_size > HASH_TREE_LOG2_ROOT_SIZE) {
            throw std::runtime_error("node log2 size is out of range");
        }
        const auto node_size = UINT64_C(1) << log2_size;
        if ((address & (node_size - 1)) != 0) {
            throw std::runtime_error("node address is not aligned to its size");
        }
        const auto node_end = address + node_size;
        // get first node with starting address >= address or end of map
        auto next_node_it = m_context.touched_nodes.lower_bound(address);
        // Reject if the next node starts inside this node's range.
        if (next_node_it != m_context.touched_nodes.end() && next_node_it->first < node_end) {
            throw std::runtime_error("node overlaps an existing node");
        }
        if (next_node_it != m_context.touched_nodes.begin()) {
            const auto prev_node_it = std::prev(next_node_it);
            const auto prev_node_end = prev_node_it->first + (UINT64_C(1) << prev_node_it->second.log2_size);
            // Reject if the previous node's range extends into this node's range.
            if (prev_node_end > address) {
                throw std::runtime_error("node overlaps an existing node");
            }
        }
        // get first page with starting address >= address or end of map
        auto next_page_it = m_context.touched_pages.lower_bound(address);
        // Reject if any existing page lies inside the node's range.
        if (next_page_it != m_context.touched_pages.end() && next_page_it->first < node_end) {
            throw std::runtime_error("node would enclose an existing page");
        }
        m_context.touched_nodes.emplace(address,
            node_entry{
                .address = address,
                .log2_size = static_cast<uint64_t>(log2_size),
                .hash_before = m_m.get_node_hash(address, log2_size, skip_hash_tree_update),
                .hash_after = {}, // filled in by finish() after the outer get_root_hash() refreshes the tree
            });
    }

    /// \brief Get the sibling hashes of all touched pages and nodes
    /// \details Walks the tree with three cursors (pages, nodes, siblings).
    /// A subtree that exactly matches a recorded node is consumed as a node
    /// (no sibling emitted). Subtrees with no touched content emit one sibling.
    sibling_hashes_type get_sibling_hashes() {
        sibling_hashes_type sibling_hashes{};
        page_indices_type page_indices{};
        for (const auto &[address, _] : m_context.touched_pages) {
            page_indices.push_back(address >> HASH_TREE_LOG2_PAGE_SIZE);
        }
        auto next_page_index = page_indices.cbegin();
        auto next_node_it = m_context.touched_nodes.cbegin();
        get_sibling_hashes_impl(0, HASH_TREE_LOG2_ROOT_SIZE - HASH_TREE_LOG2_PAGE_SIZE, page_indices, next_page_index,
            next_node_it, sibling_hashes);
        if (next_page_index != page_indices.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all pages");
        }
        if (next_node_it != m_context.touched_nodes.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all nodes");
        }
        return sibling_hashes;
    }

    /// \brief Recursively collect sibling hashes for the subtree rooted at page_index
    /// \param page_index Index of the first page in the subtree
    /// \param page_count_log2_size Log2 of the number of pages in the subtree
    /// \param page_indices All touched page indices, sorted ascending
    /// \param next_page_index Cursor into page_indices; advances past each page consumed during recursion
    /// \param next_node_it Cursor into touched_nodes; advances past each node consumed during recursion
    /// \param sibling_hashes Accumulates sibling hashes for untouched subtrees
    void get_sibling_hashes_impl(uint64_t page_index, int page_count_log2_size, page_indices_type &page_indices,
        page_indices_type::const_iterator &next_page_index, nodes_type::const_iterator &next_node_it,
        sibling_hashes_type &sibling_hashes) {
        const auto page_count = UINT64_C(1) << page_count_log2_size;
        const auto subtree_start_addr = page_index << HASH_TREE_LOG2_PAGE_SIZE;
        const auto subtree_log2_size = page_count_log2_size + HASH_TREE_LOG2_PAGE_SIZE;
        const auto subtree_end_page_index = page_index + page_count;

        // is the next unconsumed page inside this subtree?
        const bool page_in = next_page_index != page_indices.cend() && *next_page_index < subtree_end_page_index;
        // is the next unconsumed node inside this subtree?
        const bool node_in = next_node_it != m_context.touched_nodes.cend() &&
            (next_node_it->first >> HASH_TREE_LOG2_PAGE_SIZE) < subtree_end_page_index;

        if (!page_in && !node_in) {
            sibling_hashes.push_back(m_m.get_node_hash(subtree_start_addr, subtree_log2_size, skip_hash_tree_update));
        } else if (node_in && next_node_it->first == subtree_start_addr &&
            next_node_it->second.log2_size == static_cast<uint64_t>(subtree_log2_size)) {
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

    // -----
    // i_prefer_shadow_uarch_state interface implementation
    // -----
    friend i_prefer_shadow_uarch_state<uarch_record_step_state_access>;

    uint64_t do_read_shadow_uarch_state(shadow_uarch_state_what what) const {
        touch_page(static_cast<uint64_t>(what));
        return m_m.read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) const {
        touch_page(static_cast<uint64_t>(what));
        m_m.write_reg(machine_reg_enum(what), val);
    }

    // -----
    // i_uarch_state_access interface implementation
    // -----
    friend i_uarch_state_access<uarch_record_step_state_access>;

    uint64_t do_read_word(uint64_t paddr) const {
        touch_page(paddr);
        return m_m.read_word(paddr);
    }

    void do_write_word(uint64_t paddr, uint64_t val) const {
        touch_page(paddr);
        m_m.write_word(paddr, val);
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) const {
        touch_page(shadow_tlb_get_abs_addr(set_index, slot_index));
        m_m.write_unverified_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
    }

    void do_reset_uarch() const {
        touch_node(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE);
        m_m.reset_uarch();
    }

    void do_revert_state() const {
        // Witness the revert root hash leaf so the replayer can recover the canonical post-state
        // hash from its page. The substitution into root_hash_after happens in machine::log_reset_uarch.
        touch_page(AR_SHADOW_REVERT_ROOT_HASH_START);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_putchar(uint8_t /*c*/) const {
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "uarch_record_step_state_access";
    }

    // -----
    // i_accept_scoped_notes interface implementation
    // -----
    friend i_accept_scoped_notes<uarch_record_step_state_access>;

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_begin_bracket(const char * /*text*/) const {
        ;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_end_bracket(const char * /*text*/) const {
        ;
    }

    auto do_make_scoped_note(const char *text) const {
        return scoped_note{*this, text};
    }
};

} // namespace cartesi

#endif
