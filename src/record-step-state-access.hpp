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

#include <cstdint>
#include <stdexcept>

#include "address-range.hpp"
#include "assert-printf.hpp"
#include "hash-tree-constants.hpp"
#include "host-addr.hpp"
#include "i-accept-dirty-pages.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "machine.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"
#include "riscv-constants.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"
#include "step-log-recorder.hpp"
#include "variant-hasher.hpp"

namespace cartesi {

class record_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<record_step_state_access> {
    using type = host_addr;
};

/// \class record_step_state_access
/// \brief Records machine state access into a step log through a step_log_recorder
// NOLINTNEXTLINE(misc-multiple-inheritance)
class record_step_state_access :
    public i_state_access<record_step_state_access>,
    public i_accept_scoped_notes<record_step_state_access>,
    public i_accept_dirty_pages<record_step_state_access>,
    public i_prefer_shadow_state<record_step_state_access> {

    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    step_log_recorder &m_recorder; ///< Collects the witness of the recording
    machine &m_m;                  ///< Reference to machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor of record step state access
    /// \param recorder Collects the witness and writes the log on finish()
    /// \param m reference to machine
    record_step_state_access(step_log_recorder &recorder, machine &m) : m_recorder(recorder), m_m(m) {
        ;
    }

private:
    using fast_addr_type = host_addr;

    uint64_t log_read_reg(machine_reg reg) const {
        m_recorder.touch_page(machine_reg_address(reg));
        return m_m.read_reg(reg);
    }

    void log_write_reg(machine_reg reg, uint64_t val) const {
        m_recorder.touch_page(machine_reg_address(reg));
        m_m.write_reg(reg, val);
    }

    uint64_t log_read_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) const {
        m_recorder.touch_page(shadow_tlb_get_abs_addr(set_index, slot_index, what));
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
        m_recorder.touch_page(pmas_get_abs_addr(index, pmas_what::istart));
        m_recorder.touch_page(pmas_get_abs_addr(index, pmas_what::ilength));
        return m_m.read_pma(index);
    }

    template <typename T, typename A>
    void do_read_memory_word(host_addr haddr, uint64_t pma_index, T *pval) const {
        m_recorder.touch_page(m_m.get_paddr(haddr, pma_index));
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t pma_index, T val) const {
        m_recorder.touch_page(m_m.get_paddr(haddr, pma_index));
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
        m_recorder.touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // Return the vh_offset from the hot entry
        return m_m.get_state().penumbra.tlb[SET][slot_index].vh_offset;
    }

    template <TLB_set_index SET>
    uint64_t do_init_hot_tlb_slot(uint64_t slot_index) const {
        // Touch the shadow page so replay has the TLB slot data
        m_recorder.touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // Touch PMA page so replay's do_read_pma can validate the entry (even if corrupt)
        const auto pma_index = m_m.read_shadow_tlb(SET, slot_index, shadow_tlb_what::pma_index);
        m_recorder.touch_page(pmas_get_abs_addr(pma_index, pmas_what::istart));
        // Validate and promote the slot; corrupt entries return TLB_INVALID_PAGE
        const auto validated_vaddr_page = m_m.init_hot_tlb_slot(SET, slot_index);
        // Only touch target page itself after validation confirms the entry is sound
        if (validated_vaddr_page != TLB_INVALID_PAGE) {
            const auto vp_offset = m_m.read_shadow_tlb(SET, slot_index, shadow_tlb_what::vp_offset);
            const auto paddr_page = validated_vaddr_page + vp_offset;
            // replay's do_init_hot_tlb_slot needs the page there so promote the hot entry
            m_recorder.touch_page(paddr_page);
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
        m_recorder.touch_page(shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page));
        // We still need to touch the page data
        if (vaddr_page != TLB_INVALID_PAGE) {
            const auto haddr_page = vaddr_page + vh_offset;
            const auto paddr_page = m_m.get_paddr(haddr_page, pma_index);
            m_recorder.touch_page(paddr_page);
        }
        m_m.write_verified_tlb(SET, slot_index, vaddr_page, vh_offset, pma_index);
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        // replay_step_state_access needs the corresponding page to perform a
        // translation between paddr and its own haddr, so we touch the page here
        m_recorder.touch_page(paddr);
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
            m_recorder.touch_node(paddr, write_length_log2_size);
        } else {
            m_recorder.touch_page(paddr);
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
