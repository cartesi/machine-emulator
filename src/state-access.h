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

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access : public i_state_access<state_access, pma_entry> {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Associated machine

public:
    /// \brief Constructor from machine state.
    /// \param m Pointer to machine state.
    explicit state_access(machine &m) : m_m(m) {
        ;
    }

    const machine &get_naked_machine() const {
        return m_m;
    }

    machine &get_naked_machine() {
        return m_m;
    }

private:
    // Declare interface as friend to it can forward calls to the "overridden" methods.
    friend i_state_access<state_access, pma_entry>;

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

    uint64_t do_read_mtime() const {
        return m_m.get_state().mtime;
    }

    void do_write_mtime(uint64_t val) {
        m_m.get_state().mtime = val;
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

    NO_INLINE std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        bool interrupt_raised = false;
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
                interrupt_raised |= m_m.poll_virtio_devices(&timeout_us, &da);
                // VirtIO console device will poll TTY
            } else if (m_m.has_virtio_devices()) { // VirtIO without a console
                interrupt_raised |= m_m.poll_virtio_devices(&timeout_us, &da);
                if (m_m.has_htif_console()) { // VirtIO + HTIF console
                    // Poll tty without waiting more time, because the pool above should have waited enough time
                    interrupt_raised |= os_poll_tty(0);
                }
            } else if (m_m.has_htif_console()) { // Only HTIF console
                interrupt_raised |= os_poll_tty(timeout_us);
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

    template <typename T>
    void do_read_memory_word(uint64_t /*paddr*/, const unsigned char *hpage, uint64_t hoffset, T *pval) const {
        *pval = aliased_aligned_read<T>(hpage + hoffset);
    }

    template <typename T>
    void do_write_memory_word(uint64_t /*paddr*/, unsigned char *hpage, uint64_t hoffset, T val) {
        aliased_aligned_write(hpage + hoffset, val);
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

    static unsigned char *do_get_host_memory(pma_entry &pma) {
        return pma.get_memory_noexcept().get_host_memory();
    }

    pma_entry &do_read_pma_entry(uint64_t index) {
        assert(index < PMA_MAX);
        return m_m.get_state().pmas[index];
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        *phptr = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        const auto *h = cast_addr_to_ptr<const unsigned char *>(tlbhe.vh_offset + vaddr);
        *pval = aliased_aligned_read<T>(h);
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        auto *h = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        aliased_aligned_write(h, val);
        return true;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, pma_entry &pma) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                pma_entry &pma = do_read_pma_entry(tlbce.pma_index);
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            }
        }
        const uint64_t vaddr_page = vaddr & ~PAGE_OFFSET_MASK;
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        unsigned char *hpage = pma.get_memory_noexcept().get_host_memory() + (paddr_page - pma.get_start());
        tlbhe.vaddr_page = vaddr_page;
        tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - vaddr_page;
        tlbce.paddr_page = paddr_page;
        tlbce.pma_index = static_cast<uint64_t>(pma.get_index());
        return hpage;
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_entry(uint64_t eidx) {
        tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
                const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
                pma_entry &pma = do_read_pma_entry(tlbce.pma_index);
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            } else {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
            }
        } else {
            tlbhe.vaddr_page = TLB_INVALID_PAGE;
        }
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_type() {
        for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
            do_flush_tlb_entry<ETYPE>(i);
        }
    }

    void do_flush_tlb_vaddr(uint64_t /*vaddr*/) {
        // We can't flush just one TLB entry for that specific virtual address,
        // because megapages/gigapages may be in use while this TLB implementation ignores it,
        // so we have to flush all addresses.
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

    bool do_get_soft_yield() {
        return m_m.get_state().soft_yield;
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

#ifdef DUMP_COUNTERS
    machine_statistics &do_get_statistics() {
        return m_m.get_state().stats;
    }
#endif
};

} // namespace cartesi

#endif
