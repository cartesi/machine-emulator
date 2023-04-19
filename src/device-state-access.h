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

#ifndef DEVICE_STATE_ACCESS
#define DEVICE_STATE_ACCESS

/// \file
/// \brief Virtual state access implementation

#include <cstdint>

#include "i-device-state-access.h"
#include "i-state-access.h"

namespace cartesi {

/// \details The device_state_access class implements a
/// virtual interface to the state on top of the static
/// interface provided by any class implementing the
/// i_state_access interface.
/// \tparam STATE_ACCESS Class implementing the
/// i_state_access interface.
template <typename STATE_ACCESS>
class device_state_access : public i_device_state_access {
public:
    explicit device_state_access(STATE_ACCESS &a, uint64_t mcycle) : m_a(a), m_mcycle(mcycle) {
        static_assert(is_an_i_state_access<STATE_ACCESS>::value, "not an i_state_access");
    }

    /// \brief No copy constructor
    device_state_access(const device_state_access &) = delete;
    /// \brief No copy assignment
    device_state_access &operator=(const device_state_access &) = delete;
    /// \brief No move constructor
    device_state_access(device_state_access &&) = delete;
    /// \brief No move assignment
    device_state_access &operator=(device_state_access &&) = delete;
    /// \brief Default destructor
    ~device_state_access() override = default;

private:
    STATE_ACCESS &m_a;
    uint64_t m_mcycle;

    void do_set_mip(uint64_t mask) override {
        uint64_t mip = m_a.read_mip();
        mip |= mask;
        m_a.write_mip(mip);
    }

    void do_reset_mip(uint64_t mask) override {
        uint64_t mip = m_a.read_mip();
        mip &= ~mask;
        m_a.write_mip(mip);
    }

    uint64_t do_read_mip(void) override {
        return m_a.read_mip();
    }

    uint64_t do_read_mcycle(void) override {
        return m_mcycle;
    }

    void do_set_iflags_H(void) override {
        m_a.set_iflags_H();
    }

    void do_set_iflags_Y(void) override {
        m_a.set_iflags_Y();
    }

    void do_set_iflags_X(void) override {
        m_a.set_iflags_X();
    }

    uint64_t do_read_clint_mtimecmp(void) override {
        return m_a.read_clint_mtimecmp();
    }

    void do_write_clint_mtimecmp(uint64_t val) override {
        return m_a.write_clint_mtimecmp(val);
    }

    uint64_t do_read_plic_girqpend(void) override {
        return m_a.read_plic_girqpend();
    }

    void do_write_plic_girqpend(uint64_t val) override {
        return m_a.write_plic_girqpend(val);
    }

    uint64_t do_read_plic_girqsrvd(void) override {
        return m_a.read_plic_girqsrvd();
    }

    void do_write_plic_girqsrvd(uint64_t val) override {
        return m_a.write_plic_girqsrvd(val);
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

    uint64_t do_read_htif_ihalt(void) override {
        return m_a.read_htif_ihalt();
    }

    uint64_t do_read_htif_iconsole(void) override {
        return m_a.read_htif_iconsole();
    }

    uint64_t do_read_htif_iyield(void) override {
        return m_a.read_htif_iyield();
    }

    // LCOV_EXCL_START
    void do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_length) override {
        return m_a.write_memory(paddr, data, log2_length);
    }
    // LCOV_EXCL_STOP

    uint64_t do_read_pma_istart(int p) override {
        return m_a.read_pma_istart(p);
    }

    uint64_t do_read_pma_ilength(int p) override {
        return m_a.read_pma_ilength(p);
    }
};

} // namespace cartesi

#endif
