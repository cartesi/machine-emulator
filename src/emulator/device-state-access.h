#ifndef DEVICE_STATE_ACCESS
#define DEVICE_STATE_ACCESS

#include "processor.h"

template <typename STATE_ACCESS>
class device_state_access: public i_device_state_access {
public:

    device_state_access(STATE_ACCESS a, processor_state *s): m_a(a), m_s(s) {
        ;
    }

private:

    STATE_ACCESS m_a;
    processor_state *m_s;

    void do_set_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip(m_s);
        mip |= mask;
        m_a.write_mip(m_s, mip);
        m_a.reset_iflags_I(m_s);
        processor_set_brk_from_mip_mie(m_s);
    }

    void do_reset_mip(uint32_t mask) override {
        uint32_t mip = m_a.read_mip(m_s);
        mip &= ~mask;
        m_a.write_mip(m_s, mip);
        processor_set_brk_from_mip_mie(m_s);
    }

    uint32_t do_read_mip(void) override {
        return m_a.read_mip(m_s);
    }

    uint64_t do_read_mcycle(void) override {
        return m_a.read_mcycle(m_s);
    }

    void do_set_iflags_H(void) override {
        m_a.set_iflags_H(m_s);
        processor_set_brk_from_iflags_H(m_s);
    }

    uint64_t do_read_mtimecmp(void) override {
        return m_a.read_mtimecmp(m_s);
    }

    void do_write_mtimecmp(uint64_t val) override {
        return m_a.write_mtimecmp(m_s, val);
    }

    uint64_t do_read_fromhost(void) override {
        return m_a.read_fromhost(m_s);
    }

    void do_write_fromhost(uint64_t val) override {
        return m_a.write_fromhost(m_s, val);
    }

    uint64_t do_read_tohost(void) override {
        return m_a.read_tohost(m_s);
    }

    void do_write_tohost(uint64_t val) override {
        return m_a.write_tohost(m_s, val);
    }
};

#endif
