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

#ifndef RECORD_STEP_STATE_ACCESS_HPP
#define RECORD_STEP_STATE_ACCESS_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "address-range.hpp"
#include "assert-printf.hpp"
#include "hash-tree-constants.hpp"
#include "hash-tree.hpp"
#include "host-addr.hpp"
#include "i-accept-dirty-pages.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "machine.hpp"
#include "os-filesystem.hpp"
#include "os.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"
#include "riscv-constants.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"
#include "step-log.hpp"
#include "unique-c-ptr.hpp"
#include "variant-hasher.hpp"

namespace cartesi {

class record_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<record_step_state_access> {
    using type = host_addr;
};

/// \class record_step_state_access
/// \brief Records machine state access into a step log file
// NOLINTNEXTLINE(misc-multiple-inheritance)
class record_step_state_access :
    public i_state_access<record_step_state_access>,
    public i_accept_scoped_notes<record_step_state_access>,
    public i_accept_dirty_pages<record_step_state_access>,
    public i_prefer_shadow_state<record_step_state_access> {

    using page_data_type = std::array<uint8_t, HASH_TREE_PAGE_SIZE>;
    using pages_type = std::map<uint64_t, page_data_type>;
    using sibling_hashes_type = hash_tree::sibling_hashes_type;
    using page_indices_type = std::vector<uint64_t>;
    using nodes_type = std::map<uint64_t, node_entry>;

public:
    struct context {
        /// \brief Constructor of record step state access context
        /// \param filename where to save the log
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
    /// \brief Constructor of record step state access
    /// \param context Context for the recording with the log filename
    /// \param m reference to machine
    /// \details The log file is saved when finish() is called
    record_step_state_access(context &context, machine &m) : m_context(context), m_m(m) {
        if (os::exists(m_context.filename)) {
            throw std::runtime_error("file already exists");
        }
    }

    /// \brief Finish recording and save the log file
    void finish() {
        auto sibling_hashes = get_sibling_hashes();

        const step_log_header header{
            .signature = STEP_LOG_SIGNATURE,
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
    using fast_addr_type = host_addr;

    /// \brief Mark a page as touched and save its contents
    /// \param address address of the page
    void touch_page(uint64_t address) const {
        auto page = address & ~PAGE_OFFSET_MASK;
        if (m_context.touched_pages.contains(page)) {
            return; // already saved
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
    /// \param address Subtree start address, must be aligned to 2^log2_size
    /// \param log2_size Log2 of the subtree size. Must be > PAGE_SIZE and <= ROOT_SIZE.
    /// \details Captures the subtree's current hash.
    /// Rejects overlaps with existing nodes and enclosure of touched pages so
    /// the "pages and nodes are pairwise disjoint" invariant holds at replay.
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
                .hash = m_m.get_node_hash(address, log2_size, skip_hash_tree_update),
            });
    }

    /// \brief Collect the sibling hashes needed to reconstruct the root hash from touched_pages and touched_nodes.
    /// \details Walks the tree with three cursors (pages, nodes, siblings).
    /// A subtree whose range exactly matches a recorded node is consumed as a node
    /// (no sibling emitted). Subtrees with no touched content emit one sibling hash.
    /// Recursion descends into subtrees that contain at least one touched page or node.
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
        const auto subtree_start_addr = page_index << HASH_TREE_LOG2_PAGE_SIZE;
        const auto subtree_log2_size = page_count_log2_size + HASH_TREE_LOG2_PAGE_SIZE;
        const auto page_count = UINT64_C(1) << page_count_log2_size;
        const auto subtree_end_page_index = page_index + page_count;

        // next unconsumed page / node is inside this subtree?
        const bool page_in = next_page_index != page_indices.cend() && *next_page_index < subtree_end_page_index;
        // shift node address into page-index units to compare with subtree_end_page_index
        const bool node_in = next_node_it != m_context.touched_nodes.cend() &&
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

    uint64_t log_read_reg(machine_reg reg) const {
        touch_page(machine_reg_address(reg));
        return m_m.read_reg(reg);
    }

    void log_write_reg(machine_reg reg, uint64_t val) const {
        touch_page(machine_reg_address(reg));
        m_m.write_reg(reg, val);
    }

    uint64_t log_read_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) const {
        touch_page(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        return m_m.read_shadow_tlb(set_index, slot_index, what);
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<record_step_state_access>;

    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        return log_read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        log_write_reg(machine_reg_enum(what), val);
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<record_step_state_access>;

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("unexpected call to record_step_state_access::read_memory");
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("unexpected call to record_step_state_access::write_memory");
    }

    address_range &do_read_pma(uint64_t index) const {
        if (index >= PMA_MAX) [[unlikely]] {
            static address_range sentinel{"sentinel"};
            return sentinel;
        }
        // replay_step_state_access reconstructs a mock_address_range from the
        // corresponding istart and ilength fields in the shadow pmas
        // so we mark the page where they live here
        touch_page(pmas_get_abs_addr(index, pmas_what::istart));
        touch_page(pmas_get_abs_addr(index, pmas_what::ilength));
        return m_m.read_pma(index);
    }

    template <typename T, typename A>
    void do_read_memory_word(host_addr haddr, uint64_t pma_index, T *pval) const {
        touch_page(m_m.get_paddr(haddr, pma_index));
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t pma_index, T val) const {
        touch_page(m_m.get_paddr(haddr, pma_index));
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        // Must read from the hot TLB (not shadow) so that TLB_UNVERIFIED_PAGE sentinels
        // set by init_hot_tlb_contents() are visible and force init_hot_tlb_slot() to run,
        // which populates vh_offset and touches the shadow page.
        return m_m.get_state().penumbra.tlb[SET][slot_index].vaddr_page;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return log_read_tlb(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <TLB_set_index SET>
    host_addr do_read_tlb_vf_offset(uint64_t slot_index) const {
        // Touch the shadow page so replay has the TLB slot data
        touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // Return the vh_offset from the hot entry
        return m_m.get_state().penumbra.tlb[SET][slot_index].vh_offset;
    }

    template <TLB_set_index SET>
    uint64_t do_init_hot_tlb_slot(uint64_t slot_index) const {
        // Touch the shadow page so replay has the TLB slot data
        touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // Touch PMA page so replay's do_read_pma can validate the entry (even if corrupt)
        const auto pma_index = m_m.read_shadow_tlb(SET, slot_index, shadow_tlb_what::pma_index);
        touch_page(pmas_get_abs_addr(pma_index, pmas_what::istart));
        // Validate and promote the slot; corrupt entries return TLB_INVALID_PAGE
        const auto validated_vaddr_page = m_m.init_hot_tlb_slot(SET, slot_index);
        // Only touch target page itself after validation confirms the entry is sound
        if (validated_vaddr_page != TLB_INVALID_PAGE) {
            const auto vp_offset = m_m.read_shadow_tlb(SET, slot_index, shadow_tlb_what::vp_offset);
            const auto paddr_page = validated_vaddr_page + vp_offset;
            // replay's do_init_hot_tlb_slot needs the page there so promote the hot entry
            touch_page(paddr_page);
        }
        return validated_vaddr_page;
    }

    template <TLB_set_index SET>
    bool do_verify_cold_tlb_slot(uint64_t /* slot_index */) const {
        return true;
    }

    //??D This is still a bit too complicated for my taste
    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) const {
        // replay_step_state_access needs the TLB slot page and the target page data
        // vaddr_page, vp_offset, and pma_index are on the same page, so we only need touch one of them.
        touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // We still need to touch the page data
        if (vaddr_page != TLB_INVALID_PAGE) {
            const auto haddr_page = vaddr_page + vh_offset;
            const auto paddr_page = m_m.get_paddr(haddr_page, pma_index);
            touch_page(paddr_page);
        }
        m_m.write_verified_tlb(SET, slot_index, vaddr_page, vh_offset, pma_index);
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        // replay_step_state_access needs the corresponding page to perform a
        // translation between paddr and its own haddr, so we touch the page here
        touch_page(paddr);
        return m_m.get_host_addr(paddr, pma_index);
    }

    /// \brief Record a cmio response write into the cmio rx buffer.
    /// \param paddr Destination physical address; must be aligned to (1 << write_length_log2_size).
    /// \param data Pointer to source bytes.
    /// \param data_length Number of valid bytes at \p data.
    /// \param write_length_log2_size Log2 of the full write length (data + zero padding).
    /// \details Writes spanning more than a page are recorded as a single subtree
    /// node (touch_node); writes fitting within a page fall back to page-level
    /// recording (touch_page). In either case the actual memory write is delegated
    /// to the machine, and the padding zeros are written via fill_memory.
    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) const {
        if (data == nullptr) {
            throw std::invalid_argument("data is null");
        }
        const uint64_t write_length = UINT64_C(1) << write_length_log2_size;
        if (write_length < data_length) {
            throw std::invalid_argument("write_length is less than data_length");
        }
        if (write_length_log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
            touch_node(paddr, write_length_log2_size);
        } else {
            touch_page(paddr);
        }
        m_m.write_memory(paddr, data, data_length);
        if (write_length > data_length) {
            m_m.fill_memory(paddr + data_length, 0, write_length - data_length);
        }
    }

    bool do_putchar(uint8_t /*c*/) const { // NOLINT(readability-convert-member-functions-to-static)
        return false;
    }

    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "record_step_state_access";
    }

    // -----
    // i_accept_dirty_pages interface implementation
    // -----
    friend i_accept_dirty_pages<record_step_state_access>;

    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) const {
        m_m.mark_dirty_page(paddr, pma_index);
    }
};

} // namespace cartesi

#endif
