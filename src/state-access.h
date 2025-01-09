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

#ifndef STATE_ACCESS_H
#define STATE_ACCESS_H

/// \file
/// \brief Fast state access implementation

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <utility>

#include "compiler-defines.h"
#include "device-state-access.h"
#include "i-state-access.h"
#include "interpret.h"
#include "machine-haddr.h"
#include "machine-state.h"
#include "machine.h"
#include "os.h"
#include "pma-constants.h"
#include "pma.h"
#include "riscv-constants.h"
#include "rtc.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"

namespace cartesi {

class state_access;

// Type trait that should return the pma_entry type for a state access class
template <>
struct i_state_access_pma_entry<state_access> {
    using type = pma_entry;
};
// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<state_access> {
    using type = machine_haddr;
};

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access : public i_state_access<state_access> {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Associated machine

public:
    /// \brief Constructor from machine state.
    /// \param m Pointer to machine state.
    explicit state_access(machine &m) : m_m(m) {
        ;
    }

    /// \brief No copy constructor
    state_access(const state_access &) = delete;
    /// \brief No copy assignment
    state_access &operator=(const state_access &) = delete;
    /// \brief No move constructor
    state_access(state_access &&) = delete;
    /// \brief No move assignment
    state_access &operator=(state_access &&) = delete;
    /// \brief Default destructor
    ~state_access() = default;

    const machine &get_naked_machine() const {
        return m_m;
    }

    machine &get_naked_machine() {
        return m_m;
    }

private:
    friend i_state_access<state_access>;

    machine_state &do_get_naked_state() {
        return m_m.get_state();
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_bracket(bracket_type /*type*/, const char * /*text*/) {}

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    int do_make_scoped_note(const char * /*text*/) {
        return 0;
    }

    uint64_t do_read_x(int reg) const {
        return m_m.get_state().x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        m_m.get_state().x[reg] = val;
    }

    uint64_t do_read_f(int reg) const {
        return m_m.get_state().f[reg];
    }

    void do_write_f(int reg, uint64_t val) {
        m_m.get_state().f[reg] = val;
    }

    uint64_t do_read_pc() const {
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        m_m.get_state().pc = val;
    }

    uint64_t do_read_fcsr() const {
        return m_m.get_state().fcsr;
    }

    void do_write_fcsr(uint64_t val) {
        m_m.get_state().fcsr = val;
    }

    uint64_t do_read_icycleinstret() const {
        return m_m.get_state().icycleinstret;
    }

    void do_write_icycleinstret(uint64_t val) {
        m_m.get_state().icycleinstret = val;
    }

    uint64_t do_read_mvendorid() const { // NOLINT(readability-convert-member-functions-to-static)
        return MVENDORID_INIT;
    }

    uint64_t do_read_marchid() const { // NOLINT(readability-convert-member-functions-to-static)
        return MARCHID_INIT;
    }

    uint64_t do_read_mimpid() const { // NOLINT(readability-convert-member-functions-to-static)
        return MIMPID_INIT;
    }

    uint64_t do_read_mcycle() const {
        return m_m.get_state().mcycle;
    }

    void do_write_mcycle(uint64_t val) {
        m_m.get_state().mcycle = val;
    }

    uint64_t do_read_mstatus() const {
        return m_m.get_state().mstatus;
    }

    void do_write_mstatus(uint64_t val) {
        m_m.get_state().mstatus = val;
    }

    uint64_t do_read_menvcfg() const {
        return m_m.get_state().menvcfg;
    }

    void do_write_menvcfg(uint64_t val) {
        m_m.get_state().menvcfg = val;
    }

    uint64_t do_read_mtvec() const {
        return m_m.get_state().mtvec;
    }

    void do_write_mtvec(uint64_t val) {
        m_m.get_state().mtvec = val;
    }

    uint64_t do_read_mscratch() const {
        return m_m.get_state().mscratch;
    }

    void do_write_mscratch(uint64_t val) {
        m_m.get_state().mscratch = val;
    }

    uint64_t do_read_mepc() const {
        return m_m.get_state().mepc;
    }

    void do_write_mepc(uint64_t val) {
        m_m.get_state().mepc = val;
    }

    uint64_t do_read_mcause() const {
        return m_m.get_state().mcause;
    }

    void do_write_mcause(uint64_t val) {
        m_m.get_state().mcause = val;
    }

    uint64_t do_read_mtval() const {
        return m_m.get_state().mtval;
    }

    void do_write_mtval(uint64_t val) {
        m_m.get_state().mtval = val;
    }

    uint64_t do_read_misa() const {
        return m_m.get_state().misa;
    }

    void do_write_misa(uint64_t val) {
        m_m.get_state().misa = val;
    }

    uint64_t do_read_mie() const {
        return m_m.get_state().mie;
    }

    void do_write_mie(uint64_t val) {
        m_m.get_state().mie = val;
    }

    uint64_t do_read_mip() const {
        return m_m.get_state().mip;
    }

    void do_write_mip(uint64_t val) {
        m_m.get_state().mip = val;
    }

    uint64_t do_read_medeleg() const {
        return m_m.get_state().medeleg;
    }

    void do_write_medeleg(uint64_t val) {
        m_m.get_state().medeleg = val;
    }

    uint64_t do_read_mideleg() const {
        return m_m.get_state().mideleg;
    }

    void do_write_mideleg(uint64_t val) {
        m_m.get_state().mideleg = val;
    }

    uint64_t do_read_mcounteren() const {
        return m_m.get_state().mcounteren;
    }

    void do_write_mcounteren(uint64_t val) {
        m_m.get_state().mcounteren = val;
    }

    uint64_t do_read_senvcfg() const {
        return m_m.get_state().senvcfg;
    }

    void do_write_senvcfg(uint64_t val) {
        m_m.get_state().senvcfg = val;
    }

    uint64_t do_read_stvec() const {
        return m_m.get_state().stvec;
    }

    void do_write_stvec(uint64_t val) {
        m_m.get_state().stvec = val;
    }

    uint64_t do_read_sscratch() const {
        return m_m.get_state().sscratch;
    }

    void do_write_sscratch(uint64_t val) {
        m_m.get_state().sscratch = val;
    }

    uint64_t do_read_sepc() const {
        return m_m.get_state().sepc;
    }

    void do_write_sepc(uint64_t val) {
        m_m.get_state().sepc = val;
    }

    uint64_t do_read_scause() const {
        return m_m.get_state().scause;
    }

    void do_write_scause(uint64_t val) {
        m_m.get_state().scause = val;
    }

    uint64_t do_read_stval() const {
        return m_m.get_state().stval;
    }

    void do_write_stval(uint64_t val) {
        m_m.get_state().stval = val;
    }

    uint64_t do_read_satp() const {
        return m_m.get_state().satp;
    }

    void do_write_satp(uint64_t val) {
        m_m.get_state().satp = val;
    }

    uint64_t do_read_scounteren() const {
        return m_m.get_state().scounteren;
    }

    void do_write_scounteren(uint64_t val) {
        m_m.get_state().scounteren = val;
    }

    uint64_t do_read_ilrsc() const {
        return m_m.get_state().ilrsc;
    }

    void do_write_ilrsc(uint64_t val) {
        m_m.get_state().ilrsc = val;
    }

    uint64_t do_read_iprv() const {
        return m_m.get_state().iprv;
    }

    void do_write_iprv(uint64_t val) {
        m_m.get_state().iprv = val;
    }

    uint64_t do_read_iflags_X() const {
        return m_m.get_state().iflags.X;
    }

    void do_write_iflags_X(uint64_t val) {
        m_m.get_state().iflags.X = val;
    }

    uint64_t do_read_iflags_Y() const {
        return m_m.get_state().iflags.Y;
    }

    void do_write_iflags_Y(uint64_t val) {
        m_m.get_state().iflags.Y = val;
    }

    uint64_t do_read_iflags_H() const {
        return m_m.get_state().iflags.H;
    }

    void do_write_iflags_H(uint64_t val) {
        m_m.get_state().iflags.H = val;
    }

    uint64_t do_read_iunrep() const {
        return m_m.get_state().iunrep;
    }

    void do_write_iunrep(uint64_t val) {
        m_m.get_state().iunrep = val;
    }

    uint64_t do_read_clint_mtimecmp() const {
        return m_m.get_state().clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        m_m.get_state().clint.mtimecmp = val;
    }

    uint64_t do_read_plic_girqpend() const {
        return m_m.get_state().plic.girqpend;
    }

    void do_write_plic_girqpend(uint64_t val) {
        m_m.get_state().plic.girqpend = val;
    }

    uint64_t do_read_plic_girqsrvd() const {
        return m_m.get_state().plic.girqsrvd;
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        m_m.get_state().plic.girqsrvd = val;
    }

    uint64_t do_read_htif_fromhost() const {
        return m_m.get_state().htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        m_m.get_state().htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost() const {
        return m_m.get_state().htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        m_m.get_state().htif.tohost = val;
    }

    uint64_t do_read_htif_ihalt() const {
        return m_m.get_state().htif.ihalt;
    }

    uint64_t do_read_htif_iconsole() const {
        return m_m.get_state().htif.iconsole;
    }

    uint64_t do_read_htif_iyield() const {
        return m_m.get_state().htif.iyield;
    }

    bool do_read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
        //??(edubart): Treating exceptions here is not ideal, we should probably
        // move read_memory() method implementation inside state access later
        try {
            m_m.read_memory(paddr, data, length);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        //??(edubart): Treating exceptions here is not ideal, we should probably
        // move write_memory() method implementation inside state access later
        try {
            m_m.write_memory(paddr, data, length);
            return true;
        } catch (...) {
            return false;
        }
    }

    pma_entry &do_read_pma_entry(uint64_t index) {
        assert(index < PMA_MAX);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        return m_m.get_state().pmas[static_cast<int>(index)];
    }

    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) {
        if (data == nullptr) {
            throw std::runtime_error("data is null");
        }
        const uint64_t write_length = static_cast<uint64_t>(1) << write_length_log2_size;
        if (write_length < data_length) {
            throw std::runtime_error("write_length is less than data_length");
        }
        m_m.write_memory(paddr, data, data_length);
        if (write_length > data_length) {
            m_m.fill_memory(paddr + data_length, 0, write_length - data_length);
        }
    }

    template <typename T, typename A = T>
    void do_read_memory_word(machine_haddr haddr, uint64_t /* pma_index */, T *pval) {
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A = T>
    void do_write_memory_word(machine_haddr haddr, uint64_t /* pma_index */, T val) {
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_use USE>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) {
        return m_m.get_state().tlb.hot[USE][slot_index].vaddr_page;
    }

    template <TLB_set_use USE>
    machine_haddr do_read_tlb_vp_offset(uint64_t slot_index) {
        return m_m.get_state().tlb.hot[USE][slot_index].vh_offset;
    }

    template <TLB_set_use USE>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) {
        return m_m.get_state().tlb.cold[USE][slot_index].pma_index;
    }

    template <TLB_set_use USE>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, machine_haddr vh_offset, uint64_t pma_index) {
        m_m.get_state().tlb.hot[USE][slot_index].vaddr_page = vaddr_page;
        m_m.get_state().tlb.hot[USE][slot_index].vh_offset = vh_offset;
        m_m.get_state().tlb.cold[USE][slot_index].pma_index = pma_index;
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        return m_m.get_haddr(paddr, pma_index);
    }

    void do_mark_dirty_page(machine_haddr haddr, uint64_t pma_index) {
        m_m.mark_dirty_page(haddr, pma_index);
    }

    NO_INLINE std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        const bool interrupt_raised = false;
        // Only poll external interrupts if we are in unreproducible mode
        if (unlikely(do_read_iunrep())) {
            // Convert the relative interval of cycles we can wait to the interval of host time we can wait
            uint64_t timeout_us = (mcycle_max - mcycle) / RTC_CYCLES_PER_US;
            int64_t start_us = 0;
            if (timeout_us > 0) {
                start_us = os_now_us();
            }
            device_state_access da(*this, mcycle);
            // Poll virtio for events (e.g console stdin, network sockets)
            // Timeout may be decremented in case a device has deadline timers (e.g network device)
            if (m_m.has_virtio_devices() && m_m.has_virtio_console()) { // VirtIO + VirtIO console
                m_m.poll_virtio_devices(&timeout_us, &da);
                // VirtIO console device will poll TTY
            } else if (m_m.has_virtio_devices()) { // VirtIO without a console
                m_m.poll_virtio_devices(&timeout_us, &da);
                if (m_m.has_htif_console()) { // VirtIO + HTIF console
                    // Poll tty without waiting more time, because the pool above should have waited enough time
                    os_poll_tty(0);
                }
            } else if (m_m.has_htif_console()) { // Only HTIF console
                os_poll_tty(timeout_us);
            } else if (timeout_us > 0) { // No interrupts to check, just keep the CPU idle
                os_sleep_us(timeout_us);
            }
            // If timeout is greater than zero, we should also increment mcycle relative to the elapsed time
            if (timeout_us > 0) {
                const int64_t end_us = os_now_us();
                const uint64_t elapsed_us = static_cast<uint64_t>(std::max(end_us - start_us, INT64_C(0)));
                const uint64_t next_mcycle = mcycle + (elapsed_us * RTC_CYCLES_PER_US);
                mcycle = std::min(std::max(next_mcycle, mcycle), mcycle_max);
            }
        }
        return {mcycle, interrupt_raised};
    }

    bool do_get_soft_yield() {
        return m_m.get_state().soft_yield;
    }

#ifdef DUMP_COUNTERS
    machine_statistics &do_get_statistics() {
        return m_m.get_state().stats;
    }
#endif
};

} // namespace cartesi

#endif
