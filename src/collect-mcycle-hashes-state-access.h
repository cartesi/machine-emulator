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

#ifndef COLLECT_MCYCLE_HASHES_STATE_ACCESS_H
#define COLLECT_MCYCLE_HASHES_STATE_ACCESS_H

#include <cassert>
#include <stdexcept>
#include <unordered_set>

#include "hash-tree.h"
#include "i-accept-scoped-notes.h"
#include "i-prefer-shadow-state.h"
#include "i-state-access.h"
#include "machine.h"
#include "pmas.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"

namespace cartesi {

class collect_mcycle_hashes_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<collect_mcycle_hashes_state_access> {
    using type = host_addr;
};

/// \class collect_mcycle_hashes_state_access
/// \brief Records machine state access into a step log file
class collect_mcycle_hashes_state_access :
    public i_state_access<collect_mcycle_hashes_state_access>,
    public i_prefer_shadow_state<collect_mcycle_hashes_state_access>,
    public i_accept_scoped_notes<collect_mcycle_hashes_state_access> {

public:
    struct context {
        hash_tree::dirty_words_type dirty_words;
    };

private:
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    context &m_c; ///< context for dirty words
    machine &m_m; ///< reference to machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor of record step state access
    /// \param context Context for the recording with the log filename
    /// \param m reference to machine
    /// \details The log file is saved when finish() is called
    collect_mcycle_hashes_state_access(context &c, machine &m) : m_c(c), m_m(m) {}

private:
    using fast_addr_type = host_addr;

    void mark_dirty_word(uint64_t address) const {
        constexpr uint64_t word_mask = ~(HASH_TREE_WORD_SIZE - 1);
        m_c.dirty_words.insert(address & word_mask);
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<collect_mcycle_hashes_state_access>;

    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        return m_m.read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        auto reg = machine_reg_enum(what);
        mark_dirty_word(machine_reg_address(reg));
        m_m.write_reg(reg, val);
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<collect_mcycle_hashes_state_access>;

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("unexpected call to collect_mcycle_hashes_state_access::read_memory");
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("unexpected call to collect_mcycle_hashes_state_access::write_memory");
    }

    address_range &do_read_pma(uint64_t index) const {
        assert(index < PMA_MAX);
        return m_m.read_pma(index);
    }

    template <typename T, typename A>
    void do_read_memory_word(host_addr haddr, uint64_t pma_index, T *pval) const {
        (void) pma_index;
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t pma_index, T val) const {
        mark_dirty_word(m_m.get_paddr(haddr, pma_index));
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return m_m.get_state().penumbra.tlb[SET][slot_index].vaddr_page;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return m_m.get_state().shadow.tlb[SET][slot_index].pma_index;
    }

    //??D This is still a bit too complicated for my taste
    template <TLB_set_index SET>
    host_addr do_read_tlb_vf_offset(uint64_t slot_index) const {
        return m_m.get_state().penumbra.tlb[SET][slot_index].vh_offset;
    }

    //??D This is still a bit too complicated for my taste
    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) const {
        mark_dirty_word(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        mark_dirty_word(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vp_offset));
        mark_dirty_word(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::pma_index));
        m_m.write_tlb(SET, slot_index, vaddr_page, vh_offset, pma_index);
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        return m_m.get_host_addr(paddr, pma_index);
    }

    void do_mark_dirty_page(host_addr /* haddr */, uint64_t /* pma_index */) const {}

    void do_putchar(uint8_t c) const { // NOLINT(readability-convert-member-functions-to-static)
        os_putchar(c);
    }

    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "collect_mcycle_hashes_state_access";
    }
};

} // namespace cartesi

#endif
