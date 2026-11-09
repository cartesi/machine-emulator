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
/// \brief State access that records a uarch step through a step_log_recorder

#include <cstdint>

#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-uarch-state.hpp"
#include "i-uarch-state-access.hpp"
#include "machine-reg.hpp"
#include "machine.hpp"
#include "scoped-note.hpp"
#include "shadow-tlb.hpp"
#include "shadow-uarch-state.hpp"
#include "step-log-recorder.hpp"
#include "uarch-constants.hpp"

namespace cartesi {

/// \class uarch_record_step_state_access
/// \brief Records a uarch step or reset through a step_log_recorder
// NOLINTNEXTLINE(misc-multiple-inheritance)
class uarch_record_step_state_access :
    public i_uarch_state_access<uarch_record_step_state_access>,
    public i_accept_scoped_notes<uarch_record_step_state_access>,
    public i_prefer_shadow_uarch_state<uarch_record_step_state_access> {

    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    step_log_recorder &m_recorder; ///< Collects the witness of the recording
    machine &m_m;                  ///< Reference to machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor of uarch record step state access
    /// \param recorder Collects the witness and writes the log on finish()
    /// \param m reference to machine
    uarch_record_step_state_access(step_log_recorder &recorder, machine &m) : m_recorder(recorder), m_m(m) {
        ;
    }

private:
    // The 35 uarch registers are contiguous at the start of their page, with nothing else on it,
    // and every register access witnesses all of them. The slice that covers one register
    // therefore covers them all, so a replayer can locate that slice once, load the registers
    // into a cache, run the step against the cache and flush it back, instead of looking a slice
    // up on every register access. The on-chain replayer does exactly that (StepLog.sol,
    // loadUarchRegisters). At the default 512-byte minimum slice size the rule changes nothing,
    // since the registers are the first 280 bytes of the page; it is what keeps a smaller
    // minimum from breaking the bulk load. The format rule is stated in step-log.hpp.
    void touch_uarch_registers() const {
        m_recorder.touch_range(AR_SHADOW_UARCH_STATE_START, sizeof(shadow_uarch_state));
    }

    // -----
    // i_prefer_shadow_uarch_state interface implementation
    // -----
    friend i_prefer_shadow_uarch_state<uarch_record_step_state_access>;

    uint64_t do_read_shadow_uarch_state(shadow_uarch_state_what what) const {
        touch_uarch_registers();
        return m_m.read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) const {
        touch_uarch_registers();
        m_m.write_reg(machine_reg_enum(what), val);
    }

    // -----
    // i_uarch_state_access interface implementation
    // -----
    friend i_uarch_state_access<uarch_record_step_state_access>;

    uint64_t do_read_word(uint64_t paddr) const {
        m_recorder.touch_range(paddr, sizeof(uint64_t));
        return m_m.read_word(paddr);
    }

    void do_write_word(uint64_t paddr, uint64_t val) const {
        m_recorder.touch_range(paddr, sizeof(uint64_t));
        m_m.write_word(paddr, val);
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) const {
        m_recorder.touch_range(shadow_tlb_get_abs_addr(set_index, slot_index), SHADOW_TLB_SLOT_SIZE);
        m_m.write_unverified_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
    }

    void do_reset_uarch() const {
        m_recorder.touch_node(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE);
        m_m.reset_uarch();
    }

    void do_revert_state() const {
        // Witness the revert root hash leaf so the replayer can recover the canonical post-state
        // hash from its page and return it from finish().
        m_recorder.touch_range(AR_SHADOW_REVERT_ROOT_HASH_START, sizeof(machine_hash));
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
