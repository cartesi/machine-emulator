#ifndef DEVICE_STATE_ACCESS
#define DEVICE_STATE_ACCESS

/// \file
/// \brief Device state access implementation

#include <cstdint>

#include "i-device-state-access.h"
#include "machine.h"

/// \class device_state_access
/// \details The device_state_access class implements a
/// virtual interface to the state on top of the static
/// interface provided by any class implementing the
/// i_state_access interface.
/// \tparam STATE_ACCESS Class implementing the
/// i_state_access interface.
template <typename STATE_ACCESS>
class device_state_access: public i_device_state_access {
public:

    device_state_access(STATE_ACCESS &a): m_a(a) {
        static_assert(is_an_i_state_access<STATE_ACCESS>::value, "not an i_state_access");
    }

private:

    STATE_ACCESS &m_a;

    void do_set_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip();
        mip |= mask;
        m_a.write_mip(mip);
        m_a.reset_iflags_I();
        // Tell inner loop mip/mie have been modified, so it
        // may break out if need be
        machine_set_brk_from_mip_mie(m_a.naked());
    }

    void do_reset_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip();
        mip &= ~mask;
        m_a.write_mip(mip);
        // Tell inner loop mip/mie have been modified, so it
        // may break out if need be
        machine_set_brk_from_mip_mie(m_a.naked());
    }

    uint32_t do_read_mip(void) override {
        return m_a.read_mip();
    }

    uint64_t do_read_mcycle(void) override {
        return m_a.read_mcycle();
    }

    void do_set_iflags_H(void) override {
        m_a.set_iflags_H();
        // Tell inner loop H has been modified, so it
        // may break out if need be
        machine_set_brk_from_iflags_H(m_a.naked());
    }

    uint64_t do_read_mtimecmp(void) override {
        return m_a.read_mtimecmp();
    }

    void do_write_mtimecmp(uint64_t val) override {
        return m_a.write_mtimecmp(val);
    }

    uint64_t do_read_fromhost(void) override {
        return m_a.read_fromhost();
    }

    void do_write_fromhost(uint64_t val) override {
        return m_a.write_fromhost(val);
    }

    uint64_t do_read_tohost(void) override {
        return m_a.read_tohost();
    }

    void do_write_tohost(uint64_t val) override {
        return m_a.write_tohost(val);
    }
};

#endif
