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

#ifndef COLLECT_UARCH_CYCLE_HASHES_STATE_ACCESS_H
#define COLLECT_UARCH_CYCLE_HASHES_STATE_ACCESS_H

/// \file
/// \brief State access implementation that record and logs all accesses
#include <cstdint>
#include <stdexcept>

#include "address-range-constants.h"
#include "compiler-defines.h"
#include "hash-tree-constants.h"
#include "hash-tree.h"
#include "i-accept-scoped-notes.h"
#include "i-prefer-shadow-uarch-state.h"
#include "i-uarch-state-access.h"
#include "machine.h"
#include "os.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"

namespace cartesi {

/// \details The collect_uarch_cycle_hashes_state_access logs all access to the machine state.
class collect_uarch_cycle_hashes_state_access :
    public i_uarch_state_access<collect_uarch_cycle_hashes_state_access>,
    public i_prefer_shadow_uarch_state<collect_uarch_cycle_hashes_state_access>,
    public i_accept_scoped_notes<collect_uarch_cycle_hashes_state_access> {

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
    /// \brief Constructor from machine and uarch states.
    /// \param m Reference to machine state.
    /// \param log Reference to log.
    collect_uarch_cycle_hashes_state_access(context &c, machine &m) : m_c(c), m_m(m) {}

private:
    NO_INLINE void mark_dirty_word(uint64_t address) const {
        constexpr uint64_t word_mask = ~(HASH_TREE_WORD_SIZE - 1);
        m_c.dirty_words.insert(address & word_mask);
    }

    // -----
    // i_prefer_shadow_uarch_state interface implementation
    // -----
    friend i_prefer_shadow_uarch_state<collect_uarch_cycle_hashes_state_access>;

    uint64_t do_read_shadow_uarch_state(shadow_uarch_state_what what) const {
        // Code assumes we only attempt to read valid registers
        static_assert(shadow_uarch_state_get_what(AR_SHADOW_UARCH_STATE_START) ==
                shadow_uarch_state_what::uarch_halt_flag,
            "code assumes halt_flag is the first shadow uarch register");
        const auto *regs = &m_m.get_uarch_state().registers.halt_flag;
        return regs[(static_cast<uint64_t>(what) - AR_SHADOW_UARCH_STATE_START) / sizeof(uint64_t)];
    }

    void do_write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) const {
        // Code assumes we only attempt to write valid and writeable registers
        static_assert(shadow_uarch_state_get_what(AR_SHADOW_UARCH_STATE_START) ==
                shadow_uarch_state_what::uarch_halt_flag,
            "code assumes halt_flag is the first shadow uarch register");
        auto *regs = &m_m.get_uarch_state().registers.halt_flag;
        regs[(static_cast<uint64_t>(what) - AR_SHADOW_UARCH_STATE_START) / sizeof(uint64_t)] = val;
        mark_dirty_word(static_cast<uint64_t>(what));
    }

    // -----
    // i_uarch_state_access interface implementation
    // -----
    friend i_uarch_state_access<collect_uarch_cycle_hashes_state_access>;

    uint64_t do_read_word(uint64_t paddr) const {
        return m_m.read_word(paddr);
    }

    void do_write_word(uint64_t paddr, uint64_t val) const {
        m_m.write_word(paddr, val);
        mark_dirty_word(paddr);
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) const {
        mark_dirty_word(shadow_tlb_get_abs_addr(set_index, slot_index, shadow_tlb_what::vaddr_page));
        mark_dirty_word(shadow_tlb_get_abs_addr(set_index, slot_index, shadow_tlb_what::vp_offset));
        mark_dirty_word(shadow_tlb_get_abs_addr(set_index, slot_index, shadow_tlb_what::pma_index));
        m_m.write_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_reset_uarch() const {
        throw std::runtime_error("unexpected call to collect_uarch_cycle_hashes_state_access::reset_uarch");
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_putchar(uint8_t c) const {
        os_putchar(c);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) const {
        (void) paddr;
        (void) pma_index;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "collect_uarch_cycle_hashes_state_access";
    }
};

} // namespace cartesi

#endif
