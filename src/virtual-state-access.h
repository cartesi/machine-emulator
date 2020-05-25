// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef VIRTUAL_STATE_ACCESS
#define VIRTUAL_STATE_ACCESS

/// \file
/// \brief Virtual state access implementation

#include <cstdint>

#include "i-virtual-state-access.h"
#include "machine.h"

namespace cartesi {

/// \details The virtual_state_access class implements a
/// virtual interface to the state on top of the static
/// interface provided by any class implementing the
/// i_state_access interface.
/// \tparam STATE_ACCESS Class implementing the
/// i_state_access interface.
template <typename STATE_ACCESS>
class virtual_state_access: public i_virtual_state_access {
public:

    explicit virtual_state_access(STATE_ACCESS &a): m_a(a) {
        static_assert(is_an_i_state_access<STATE_ACCESS>::value, "not an i_state_access");
    }

    /// \brief No copy constructor
    virtual_state_access(const virtual_state_access &) = delete;
    /// \brief No copy assignment
    virtual_state_access& operator=(const virtual_state_access &) = delete;
    /// \brief No move constructor
    virtual_state_access(virtual_state_access &&) = delete;
    /// \brief No move assignment
    virtual_state_access& operator=(virtual_state_access &&) = delete;

private:

    STATE_ACCESS &m_a;

    void do_set_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip();
        mip |= mask;
        m_a.write_mip(mip);
        m_a.reset_iflags_I();
        // Tell inner loop mip/mie have been modified, so it
        // may break out if need be
        m_a.get_naked_state().or_brk_with_mip_mie();
    }

    void do_reset_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip();
        mip &= ~mask;
        m_a.write_mip(mip);
        // Tell inner loop mip/mie have been modified, so whatever
        // reason it had to break may not exist anymore
        m_a.get_naked_state().set_brk_from_all();
    }

    uint32_t do_read_mip(void) override {
        return m_a.read_mip();
    }

    uint64_t do_read_mcycle(void) override {
        return m_a.read_mcycle();
    }

    void do_set_iflags_H(void) override {
        m_a.set_iflags_H();
        // Tell inner loop H has been set, so it must break out
        m_a.get_naked_state().set_brk();
    }

    void do_set_iflags_Y(void) override {
        m_a.set_iflags_Y();
        // Tell inner loop Y has been set, so it can break out
        m_a.get_naked_state().set_brk();
    }

    uint64_t do_read_clint_mtimecmp(void) override {
        return m_a.read_clint_mtimecmp();
    }

    void do_write_clint_mtimecmp(uint64_t val) override {
        return m_a.write_clint_mtimecmp(val);
    }

    uint64_t do_read_htif_fromhost(void) override {
        return m_a.read_htif_fromhost();
    }

    void do_write_htif_fromhost(uint64_t val) override {
        return m_a.write_htif_fromhost(val);
    }

    uint64_t do_read_htif_tohost(void) override {
        return m_a.read_htif_tohost();
    }

    void do_write_htif_tohost(uint64_t val) override {
        return m_a.write_htif_tohost(val);
    }

    uint64_t do_read_htif_halt(void) override {
        return m_a.read_htif_halt();
    }

    uint64_t do_read_htif_console(void) override {
        return m_a.read_htif_console();
    }

    uint64_t do_read_htif_yield(void) override {
        return m_a.read_htif_yield();
    }

    uint64_t do_read_pma_istart(int p) override {
        return m_a.read_pma_istart(p);
    }

    uint64_t do_read_pma_ilength(int p) override {
        return m_a.read_pma_ilength(p);
    }

};

} // namespace cartesi

#endif
