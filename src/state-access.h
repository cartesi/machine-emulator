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

#include <cassert>
#include <sys/time.h>

#include "device-state-access.h"
#include "i-state-access.h"
#include "machine.h"
#include "pma.h"
#include "rtc.h"
#include "strict-aliasing.h"
#include "tty.h"

namespace cartesi {

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access : public i_state_access<state_access, pma_entry> {

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

    const machine &get_naked_machine(void) const {
        return m_m;
    }

    machine &get_naked_machine(void) {
        return m_m;
    }

private:
    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<state_access, pma_entry>;

    machine_state &do_get_naked_state(void) {
        return m_m.get_state();
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    int do_make_scoped_note(const char *text) {
        (void) text;
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

    uint64_t do_read_pc(void) const {
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        m_m.get_state().pc = val;
    }

    uint64_t do_read_fcsr(void) const {
        return m_m.get_state().fcsr;
    }

    void do_write_fcsr(uint64_t val) {
        m_m.get_state().fcsr = val;
    }

    uint64_t do_read_icycleinstret(void) const {
        return m_m.get_state().icycleinstret;
    }

    void do_write_icycleinstret(uint64_t val) {
        m_m.get_state().icycleinstret = val;
    }

    uint64_t do_read_mvendorid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        return MVENDORID_INIT;
    }

    uint64_t do_read_marchid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        return MARCHID_INIT;
    }

    uint64_t do_read_mimpid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        return MIMPID_INIT;
    }

    uint64_t do_read_mcycle(void) const {
        return m_m.get_state().mcycle;
    }

    void do_write_mcycle(uint64_t val) {
        m_m.get_state().mcycle = val;
    }

    uint64_t do_read_mstatus(void) const {
        return m_m.get_state().mstatus;
    }

    void do_write_mstatus(uint64_t val) {
        m_m.get_state().mstatus = val;
    }

    uint64_t do_read_menvcfg(void) const {
        return m_m.get_state().menvcfg;
    }

    void do_write_menvcfg(uint64_t val) {
        m_m.get_state().menvcfg = val;
    }

    uint64_t do_read_mtvec(void) const {
        return m_m.get_state().mtvec;
    }

    void do_write_mtvec(uint64_t val) {
        m_m.get_state().mtvec = val;
    }

    uint64_t do_read_mscratch(void) const {
        return m_m.get_state().mscratch;
    }

    void do_write_mscratch(uint64_t val) {
        m_m.get_state().mscratch = val;
    }

    uint64_t do_read_mepc(void) const {
        return m_m.get_state().mepc;
    }

    void do_write_mepc(uint64_t val) {
        m_m.get_state().mepc = val;
    }

    uint64_t do_read_mcause(void) const {
        return m_m.get_state().mcause;
    }

    void do_write_mcause(uint64_t val) {
        m_m.get_state().mcause = val;
    }

    uint64_t do_read_mtval(void) const {
        return m_m.get_state().mtval;
    }

    void do_write_mtval(uint64_t val) {
        m_m.get_state().mtval = val;
    }

    uint64_t do_read_misa(void) const {
        return m_m.get_state().misa;
    }

    void do_write_misa(uint64_t val) {
        m_m.get_state().misa = val;
    }

    uint64_t do_read_mie(void) const {
        return m_m.get_state().mie;
    }

    void do_write_mie(uint64_t val) {
        m_m.get_state().mie = val;
    }

    uint64_t do_read_mip(void) const {
        return m_m.get_state().mip;
    }

    void do_write_mip(uint64_t val) {
        m_m.get_state().mip = val;
    }

    uint64_t do_read_medeleg(void) const {
        return m_m.get_state().medeleg;
    }

    void do_write_medeleg(uint64_t val) {
        m_m.get_state().medeleg = val;
    }

    uint64_t do_read_mideleg(void) const {
        return m_m.get_state().mideleg;
    }

    void do_write_mideleg(uint64_t val) {
        m_m.get_state().mideleg = val;
    }

    uint64_t do_read_mcounteren(void) const {
        return m_m.get_state().mcounteren;
    }

    void do_write_mcounteren(uint64_t val) {
        m_m.get_state().mcounteren = val;
    }

    uint64_t do_read_senvcfg(void) const {
        return m_m.get_state().senvcfg;
    }

    void do_write_senvcfg(uint64_t val) {
        m_m.get_state().senvcfg = val;
    }

    uint64_t do_read_stvec(void) const {
        return m_m.get_state().stvec;
    }

    void do_write_stvec(uint64_t val) {
        m_m.get_state().stvec = val;
    }

    uint64_t do_read_sscratch(void) const {
        return m_m.get_state().sscratch;
    }

    void do_write_sscratch(uint64_t val) {
        m_m.get_state().sscratch = val;
    }

    uint64_t do_read_sepc(void) const {
        return m_m.get_state().sepc;
    }

    void do_write_sepc(uint64_t val) {
        m_m.get_state().sepc = val;
    }

    uint64_t do_read_scause(void) const {
        return m_m.get_state().scause;
    }

    void do_write_scause(uint64_t val) {
        m_m.get_state().scause = val;
    }

    uint64_t do_read_stval(void) const {
        return m_m.get_state().stval;
    }

    void do_write_stval(uint64_t val) {
        m_m.get_state().stval = val;
    }

    uint64_t do_read_satp(void) const {
        return m_m.get_state().satp;
    }

    void do_write_satp(uint64_t val) {
        m_m.get_state().satp = val;
    }

    uint64_t do_read_scounteren(void) const {
        return m_m.get_state().scounteren;
    }

    void do_write_scounteren(uint64_t val) {
        m_m.get_state().scounteren = val;
    }

    uint64_t do_read_ilrsc(void) const {
        return m_m.get_state().ilrsc;
    }

    void do_write_ilrsc(uint64_t val) {
        m_m.get_state().ilrsc = val;
    }

    void do_set_iflags_H(void) {
        m_m.get_state().iflags.H = true;
    }

    bool do_read_iflags_H(void) const {
        return m_m.get_state().iflags.H;
    }

    void do_set_iflags_X(void) {
        m_m.get_state().iflags.X = true;
    }

    void do_reset_iflags_X(void) {
        m_m.get_state().iflags.X = false;
    }

    bool do_read_iflags_X(void) const {
        return m_m.get_state().iflags.X;
    }

    void do_set_iflags_Y(void) {
        m_m.get_state().iflags.Y = true;
    }

    void do_reset_iflags_Y(void) {
        m_m.get_state().iflags.Y = false;
    }

    bool do_read_iflags_Y(void) const {
        return m_m.get_state().iflags.Y;
    }

    uint8_t do_read_iflags_PRV(void) const {
        return m_m.get_state().iflags.PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        m_m.get_state().iflags.PRV = val;
    }

    uint64_t do_read_clint_mtimecmp(void) const {
        return m_m.get_state().clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        m_m.get_state().clint.mtimecmp = val;
    }

    uint64_t do_read_htif_fromhost(void) const {
        return m_m.get_state().htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        m_m.get_state().htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost(void) const {
        return m_m.get_state().htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        m_m.get_state().htif.tohost = val;
    }

    uint64_t do_read_htif_ihalt(void) const {
        return m_m.get_state().htif.ihalt;
    }

    uint64_t do_read_htif_iconsole(void) const {
        return m_m.get_state().htif.iconsole;
    }

    uint64_t do_read_htif_iyield(void) const {
        return m_m.get_state().htif.iyield;
    }

    NO_INLINE uint64_t do_poll_console(uint64_t mcycle) {
        const bool htif_console_getchar = static_cast<bool>(read_htif_iconsole() & (1 << HTIF_CONSOLE_GETCHAR));
        if (htif_console_getchar) {
            const uint64_t warp_cycle = rtc_time_to_cycle(read_clint_mtimecmp());
            if (warp_cycle > mcycle) {
                constexpr uint64_t cycles_per_us = RTC_CLOCK_FREQ / 1000000; // CLOCK_FREQ / 10^6
                const uint64_t wait = (warp_cycle - mcycle) / cycles_per_us;
                timeval start{};
                timeval end{};
                gettimeofday(&start, nullptr);
                tty_poll_console(wait);
                gettimeofday(&end, nullptr);
                const uint64_t elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
                const uint64_t tty_cycle = mcycle + (elapsed_us * cycles_per_us);
                mcycle = std::min(std::max(tty_cycle, mcycle), warp_cycle);
            }
        }
        return mcycle;
    }

    uint64_t do_read_pma_istart(int i) const {
        assert(i >= 0 && i < (int) PMA_MAX);
        const auto &pmas = m_m.get_pmas();
        uint64_t istart = 0;
        if (i >= 0 && i < static_cast<int>(pmas.size())) {
            istart = pmas[i].get_istart();
        }
        return istart;
    }

    uint64_t do_read_pma_ilength(int i) const {
        assert(i >= 0 && i < (int) PMA_MAX);
        const auto &pmas = m_m.get_pmas();
        uint64_t ilength = 0;
        if (i >= 0 && i < static_cast<int>(pmas.size())) {
            ilength = pmas[i].get_ilength();
        }
        return ilength;
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) const {
        (void) paddr;
        *pval = aliased_aligned_read<T>(hpage + hoffset);
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        (void) paddr;
        aliased_aligned_write(hpage + hoffset, val);
    }

    void do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) {
        m_m.write_memory(paddr, data, UINT64_C(1) << log2_size);
    }

    template <typename T>
    pma_entry &do_find_pma_entry(uint64_t paddr) {
        int i = 0;
        while (true) {
            auto &pma = m_m.get_state().pmas[i];
            // The pmas array always contain a sentinel. It is an entry with
            // zero length. If we hit it, return it
            if (pma.get_length() == 0) {
                return pma;
            }
            // Otherwise, if we found an entry where the access fits, return it
            // Note the "strange" order of arithmetic operations.
            // This is to ensure there is no overflow.
            // Since we know paddr >= start, there is no chance of overflow
            // in the first subtraction.
            // Since length is at least 4096 (an entire page), there is no
            // chance of overflow in the second subtraction.
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
            i++;
        }
    }

    static unsigned char *do_get_host_memory(pma_entry &pma) {
        return pma.get_memory_noexcept().get_host_memory();
    }

    pma_entry &do_get_pma_entry(int index) {
        auto &pmas = m_m.get_state().pmas;
        if (index >= static_cast<int>(pmas.size())) {
            return pmas[pmas.size() - 1];
        }
        return pmas[index];
    }

    uint64_t do_read_iflags(void) {
        return m_m.get_state().read_iflags();
    }

    void do_write_iflags(uint64_t val) {
        m_m.get_state().write_iflags(val);
    }

    bool do_read_device(pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_noexcept().get_driver()->read(pma.get_device_noexcept().get_context(), &da, offset, pval,
            log2_size);
    }

    execute_status do_write_device(pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t val, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_noexcept().get_driver()->write(pma.get_device_noexcept().get_context(), &da, offset, val,
            log2_size);
    }

    template <TLB_entry_type ETYPE, typename T>
    inline bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        *phptr = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    inline bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
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
    inline bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
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
                pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
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
                pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
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

    void do_flush_tlb_vaddr(uint64_t vaddr) {
        (void) vaddr;
        // We can't flush just one TLB entry for that specific virtual address,
        // because megapages/gigapages may be in use while this TLB implementation ignores it,
        // so we have to flush all addresses.
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

#ifdef DUMP_COUNTERS
    machine_statistics &do_get_statistics() {
        return m_m.get_state().stats;
    }
#endif
};

} // namespace cartesi

#endif
