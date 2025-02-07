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

#ifndef RECORD_STEP_STATE_ACCESS_H
#define RECORD_STEP_STATE_ACCESS_H

#include <map>
#include <optional>
#include <vector>

#include "compiler-defines.h"
#include "i-accept-scoped-note.h"
#include "i-prefer-shadow-state.h"
#include "i-state-access.h"
#include "machine.h"
#include "shadow-pmas.h"
#include "shadow-tlb.h"
#include "unique-c-ptr.h"

namespace cartesi {

class record_step_state_access;

// Type trait that should return the pma_entry type for a state access class
template <>
struct i_state_access_pma_entry<record_step_state_access> {
    using type = pma_entry;
};
// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<record_step_state_access> {
    using type = host_addr;
};

/// \class record_step_state_access
/// \brief Records machine state access into a step log file
class record_step_state_access :
    public i_state_access<record_step_state_access>,
    public i_accept_scoped_note<record_step_state_access>,
    public i_prefer_shadow_state<record_step_state_access> {
    constexpr static int TREE_LOG2_ROOT_SIZE = machine_merkle_tree::get_log2_root_size();
    constexpr static int TREE_LOG2_PAGE_SIZE = machine_merkle_tree::get_log2_page_size();
    constexpr static uint64_t TREE_PAGE_SIZE = UINT64_C(1) << LOG2_PAGE_SIZE;

    using address_type = machine_merkle_tree::address_type;
    using page_data_type = std::array<uint8_t, TREE_PAGE_SIZE>;
    using pages_type = std::map<address_type, page_data_type>;
    using hash_type = machine_merkle_tree::hash_type;
    using sibling_hashes_type = std::vector<hash_type>;
    using page_indices_type = std::vector<address_type>;

public:
    struct context {
        /// \brief Constructor of record step state access context
        /// \param filename where to save the log
        explicit context(std::string filename) : filename(std::move(filename)) {
            ;
        }
        std::string filename;             ///<  where to save the log
        mutable pages_type touched_pages; ///<  copy of all pages touched during execution
    };

private:
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    context &m_context; ///<  context for the recording
    machine &m_m;       ///<  reference to machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor of record step state access
    /// \param context Context for the recording with the log filename
    /// \param m reference to machine
    /// \details The log file is saved when finish() is called
    record_step_state_access(context &context, machine &m) : m_context(context), m_m(m) {
        if (os_file_exists(m_context.filename.c_str())) {
            throw std::runtime_error("file already exists");
        }
    }

    /// \brief Finish recording and save the log file
    void finish() {
        // get sibling hashes of all touched pages
        auto sibling_hashes = get_sibling_hashes();
        uint64_t page_count = m_context.touched_pages.size();
        uint64_t sibling_count = sibling_hashes.size();

        // Write log file.
        // The log format is as follows:
        // page_count, [(page_index, data, scratch_area), ...], sibling_count, [sibling_hash, ...]
        // We store the page index, instead of the page address.
        // Scratch area is used by the replay to store page hashes, which change during replay
        // This is to work around the lack of dynamic memory allocation when replaying the log in microarchitectures
        auto fp = unique_fopen(m_context.filename.c_str(), "wb");
        if (fwrite(&page_count, sizeof(page_count), 1, fp.get()) != 1) {
            throw std::runtime_error("Could not write page count to log file");
        }
        for (auto &[address, data] : m_context.touched_pages) {
            const auto page_index = address >> TREE_LOG2_PAGE_SIZE;
            if (fwrite(&page_index, sizeof(page_index), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page index to log file");
            }
            if (fwrite(data.data(), data.size(), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page data to log file");
            }
            static const hash_type all_zeros{};
            if (fwrite(all_zeros.data(), sizeof(all_zeros), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page hash scratch to log file");
            }
        }
        if (fwrite(&sibling_count, sizeof(sibling_count), 1, fp.get()) != 1) {
            throw std::runtime_error("Could not write sibling count to log file");
        }
        for (auto &hash : sibling_hashes) {
            if (fwrite(hash.data(), sizeof(hash), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write sibling hash to log file");
            }
        }
    }

private:
    using pma_entry_type = pma_entry;
    using fast_addr_type = host_addr;

    /// \brief Mark a page as touched and save its contents
    /// \param address address of the page
    void touch_page(address_type address) const {
        auto page = address & ~PAGE_OFFSET_MASK;
        if (m_context.touched_pages.find(page) != m_context.touched_pages.end()) {
            return; // already saved
        }
        auto [it, _] = m_context.touched_pages.emplace(page, page_data_type());
        m_m.read_memory(page, it->second.data(), it->second.size());
    }

    /// \brief Get the sibling hashes of all touched pages
    sibling_hashes_type get_sibling_hashes() {
        sibling_hashes_type sibling_hashes{};
        // page address are converted to page indices, in order to avoid overflows
        page_indices_type page_indices{};
        // iterate in ascending order of page addresses (the container is ordered by key)
        for (const auto &[address, _] : m_context.touched_pages) {
            page_indices.push_back(address >> TREE_LOG2_PAGE_SIZE);
        }
        auto next_page_index = page_indices.cbegin();
        get_sibling_hashes_impl(0, TREE_LOG2_ROOT_SIZE - TREE_LOG2_PAGE_SIZE, page_indices, next_page_index,
            sibling_hashes);
        if (next_page_index != page_indices.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all pages");
        }
        return sibling_hashes;
    }

    /// \brief Recursively get the sibling hashes of all touched pages
    /// \param page_index index of 1st page in range
    /// \param page_count_log2_size log2 of the number of pages in range
    /// \param page_indices indices of all pages
    /// \param next_page_index smallest page index not visited yet
    /// \param sibling_hashes stores the collected sibling hashes during the recursion
    void get_sibling_hashes_impl(address_type page_index, int page_count_log2_size, page_indices_type &page_indices,
        page_indices_type::const_iterator &next_page_index, sibling_hashes_type &sibling_hashes) {
        auto page_count = UINT64_C(1) << page_count_log2_size;
        if (next_page_index == page_indices.cend() || page_index + page_count <= *next_page_index) {
            // we can skip the merkle tree update, because a full update was done before the recording started
            sibling_hashes.push_back(m_m.get_merkle_tree_node_hash(page_index << TREE_LOG2_PAGE_SIZE,
                page_count_log2_size + TREE_LOG2_PAGE_SIZE, skip_merkle_tree_update));
        } else if (page_count_log2_size > 0) {
            get_sibling_hashes_impl(page_index, page_count_log2_size - 1, page_indices, next_page_index,
                sibling_hashes);
            get_sibling_hashes_impl(page_index + (UINT64_C(1) << (page_count_log2_size - 1)), page_count_log2_size - 1,
                page_indices, next_page_index, sibling_hashes);
        } else {
            ++next_page_index;
        }
    }

    uint64_t log_read_reg(machine_reg reg) const {
        touch_page(machine_reg_address(reg));
        return m_m.read_reg(reg);
    }

    void log_write_reg(machine_reg reg, uint64_t val) {
        touch_page(machine_reg_address(reg));
        m_m.write_reg(reg, val);
    }

    uint64_t log_read_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) {
        touch_page(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        return m_m.read_shadow_tlb(set_index, slot_index, what);
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<record_step_state_access>;

    uint64_t do_read_shadow_state(shadow_state_what what) {
        return log_read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_state(shadow_state_what what, uint64_t val) {
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
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("unexpected call to record_step_state_access::write_memory");
    }

    pma_entry &do_read_pma_entry(uint64_t index) {
        assert(index < PMA_MAX);
        // replay_step_state_access reconstructs a mock_pma_entry from the
        // corresponding istart and ilength fields in the shadow pmas
        // so we mark the page where they live here
        touch_page(shadow_pmas_get_pma_abs_addr(index, shadow_pmas_what::istart));
        touch_page(shadow_pmas_get_pma_abs_addr(index, shadow_pmas_what::ilength));
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        return m_m.get_state().pmas[static_cast<int>(index)];
    }

    template <typename T, typename A>
    void do_read_memory_word(host_addr haddr, uint64_t pma_index, T *pval) {
        touch_page(m_m.get_paddr(haddr, pma_index));
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t pma_index, T val) {
        touch_page(m_m.get_paddr(haddr, pma_index));
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) {
        return log_read_tlb(SET, slot_index, shadow_tlb_what::vaddr_page);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) {
        return log_read_tlb(SET, slot_index, shadow_tlb_what::pma_index);
    }

    //??D This is still a bit too complicated for my taste
    template <TLB_set_index SET>
    host_addr do_read_tlb_vp_offset(uint64_t slot_index) {
        // During initialization, replay_step_state_access translates all vp_offset to corresponding vh_offset
        // At deinitialization, it translates them back
        // To do that, it needs the corresponding paddr_page = vaddr_page + vp_offset, and page data itself
        // It will only do the translation if the slot is valid and the log has all required fields
        // Obviously, the slot we are reading will be needed during replay
        // vaddr_page, vp_offset, and pma_index are on the same page, so we only need touch one of them.
        touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // We still need to touch the page data
        // Writes to the TLB slot are atomic, so we know the values in a slot are ALWAYS internally consistent.
        // This means we can safely use all other fields to find paddr_page.
        const auto vaddr_page = m_m.get_state().tlb.hot[SET][slot_index].vaddr_page;
        const auto vh_offset = m_m.get_state().tlb.hot[SET][slot_index].vh_offset;
        if (vaddr_page != TLB_INVALID_PAGE) {
            const auto pma_index = m_m.get_state().tlb.cold[SET][slot_index].pma_index;
            const auto haddr_page = vaddr_page + vh_offset;
            auto paddr_page = m_m.get_paddr(haddr_page, pma_index);
            touch_page(paddr_page);
        }
        return vh_offset;
    }

    //??D This is still a bit too complicated for my taste
    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) {
        // During initialization, replay_step_state_access translates all vp_offset to corresponding vh_offset
        // At deinitialization, it translates them back
        // To do that, it needs the corresponding paddr_page = vaddr_page + vp_offset, and page data itself
        // It will only do the translation if the slot is valid and the log has all required fields
        // Obviously, the slot we are writing will be needed during replay
        // vaddr_page, vp_offset, and pma_index are on the same page, so we only need touch one of them.
        touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // We still need to touch the page data
        if (vaddr_page != TLB_INVALID_PAGE) {
            const auto haddr_page = vaddr_page + vh_offset;
            auto paddr_page = m_m.get_paddr(haddr_page, pma_index);
            touch_page(paddr_page);
        }
        m_m.get_state().tlb.hot[SET][slot_index].vaddr_page = vaddr_page;
        m_m.get_state().tlb.hot[SET][slot_index].vh_offset = vh_offset;
        m_m.get_state().tlb.cold[SET][slot_index].pma_index = pma_index;
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        // replay_step_state_access needs the corresponding page to perform a
        // translation between paddr and its own haddr, so we touch the page here
        touch_page(paddr);
        return m_m.get_host_addr(paddr, pma_index);
    }

    void do_mark_dirty_page(host_addr haddr, uint64_t pma_index) {
        // this is a noop in replay_step_state_access, so we do nothing else
        m_m.mark_dirty_page(haddr, pma_index);
    }

    void do_putchar(uint8_t c) { // NOLINT(readability-convert-member-functions-to-static)
        os_putchar(c);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "record_step_state_access";
    }
};

} // namespace cartesi

#endif
