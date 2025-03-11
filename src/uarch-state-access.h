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

#ifndef UARCH_STATE_ACCESS_H
#define UARCH_STATE_ACCESS_H

#include <cassert>
#include <cstdint>
#include <stdexcept>

#include "host-addr.h"
#include "i-accept-scoped-notes.h"
#include "i-uarch-state-access.h"
#include "machine.h"
#include "os.h"
#include "riscv-constants.h"
#include "strict-aliasing.h"
#include "uarch-pristine.h"

namespace cartesi {

class uarch_state_access :
    public i_uarch_state_access<uarch_state_access>,
    public i_accept_scoped_notes<uarch_state_access> {
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    host_addr m_uram_ph_offset;

public:
    /// \brief Constructor from machine and uarch states.
    /// \param um Reference to uarch state.
    /// \param m Reference to machine state.
    explicit uarch_state_access(machine &m) : m_m(m) {
        const auto &uram = m_m.get_uarch_state().ram;
        const auto haddr = cast_ptr_to_host_addr(uram->get_host_memory());
        const auto paddr = uram->get_start();
        // initialize translation cache from paddr in uarch RAM to host address
        m_uram_ph_offset = haddr - paddr;
    }

private:
    // -----
    // i_uarch_state_access interface implementation
    // -----
    friend i_uarch_state_access<uarch_state_access>;

    uint64_t do_read_uarch_x(int i) const {
        return m_m.get_uarch_state().x[i];
    }

    void do_write_uarch_x(int i, uint64_t val) const {
        assert(i != 0);
        m_m.get_uarch_state().x[i] = val;
    }

    uint64_t do_read_uarch_pc() const {
        return m_m.get_uarch_state().pc;
    }

    void do_write_uarch_pc(uint64_t val) const {
        m_m.get_uarch_state().pc = val;
    }

    uint64_t do_read_uarch_cycle() const {
        return m_m.get_uarch_state().cycle;
    }

    void do_write_uarch_cycle(uint64_t val) const {
        m_m.get_uarch_state().cycle = val;
    }

    uint64_t do_read_uarch_halt_flag() const {
        return m_m.get_uarch_state().halt_flag;
    }

    void do_write_uarch_halt_flag(uint64_t v) const {
        m_m.get_uarch_state().halt_flag = v;
    }

    uint64_t do_read_word(uint64_t paddr) const {
        // Forward to machine
        return m_m.read_word(paddr);
    }

    void do_write_word(uint64_t paddr, uint64_t val) const {
        // Forward to machine
        m_m.write_word(paddr, val);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_putchar(uint8_t c) const {
        os_putchar(c);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) const {
        // Forward to machine
        m_m.mark_dirty_page(paddr, pma_index);
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) const {
        // Forward to machine
        m_m.write_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
    }

    void do_reset_uarch() const {
        // Forward to machine
        m_m.reset_uarch();
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "uarch_state_access";
    }

    // -----
    // i_accept_scoped_notes interface implementation
    // -----
    friend i_accept_scoped_notes<uarch_state_access>;
};

} // namespace cartesi

#endif
