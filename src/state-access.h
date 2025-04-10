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
#include "host-addr.h"
#include "i-accept-counters.h"
#include "i-accept-scoped-notes.h"
#include "i-interactive-state-access.h"
#include "i-state-access.h"
#include "interpret.h"
#include "machine.h"
#include "os.h"
#include "pmas-constants.h"
#include "processor-state.h"
#include "riscv-constants.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"

namespace cartesi {

class state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<state_access> {
    using type = host_addr;
};

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access :
    public i_state_access<state_access>,
    public i_interactive_state_access<state_access>,
    public i_accept_scoped_notes<state_access>,
    public i_accept_counters<state_access> {

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Associated machine

public:
    /// \brief Constructor from machine state.
    /// \param m Pointer to machine state.
    explicit state_access(machine &m) : m_m(m) {
        ;
    }

private:
    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<state_access>;

    uint64_t do_read_x(int i) const {
        return m_m.get_state().registers.x[i];
    }

    void do_write_x(int i, uint64_t val) const {
        assert(i != 0);
        m_m.get_state().registers.x[i] = val;
    }

    uint64_t do_read_f(int i) const {
        return m_m.get_state().registers.f[i];
    }

    void do_write_f(int i, uint64_t val) const {
        m_m.get_state().registers.f[i] = val;
    }

    uint64_t do_read_pc() const {
        return m_m.get_state().registers.pc;
    }

    void do_write_pc(uint64_t val) const {
        m_m.get_state().registers.pc = val;
    }

    uint64_t do_read_fcsr() const {
        return m_m.get_state().registers.fcsr;
    }

    void do_write_fcsr(uint64_t val) const {
        m_m.get_state().registers.fcsr = val;
    }

    uint64_t do_read_icycleinstret() const {
        return m_m.get_state().registers.icycleinstret;
    }

    void do_write_icycleinstret(uint64_t val) const {
        m_m.get_state().registers.icycleinstret = val;
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
        return m_m.get_state().registers.mcycle;
    }

    void do_write_mcycle(uint64_t val) const {
        m_m.get_state().registers.mcycle = val;
    }

    uint64_t do_read_mstatus() const {
        return m_m.get_state().registers.mstatus;
    }

    void do_write_mstatus(uint64_t val) const {
        m_m.get_state().registers.mstatus = val;
    }

    uint64_t do_read_menvcfg() const {
        return m_m.get_state().registers.menvcfg;
    }

    void do_write_menvcfg(uint64_t val) const {
        m_m.get_state().registers.menvcfg = val;
    }

    uint64_t do_read_mtvec() const {
        return m_m.get_state().registers.mtvec;
    }

    void do_write_mtvec(uint64_t val) const {
        m_m.get_state().registers.mtvec = val;
    }

    uint64_t do_read_mscratch() const {
        return m_m.get_state().registers.mscratch;
    }

    void do_write_mscratch(uint64_t val) const {
        m_m.get_state().registers.mscratch = val;
    }

    uint64_t do_read_mepc() const {
        return m_m.get_state().registers.mepc;
    }

    void do_write_mepc(uint64_t val) const {
        m_m.get_state().registers.mepc = val;
    }

    uint64_t do_read_mcause() const {
        return m_m.get_state().registers.mcause;
    }

    void do_write_mcause(uint64_t val) const {
        m_m.get_state().registers.mcause = val;
    }

    uint64_t do_read_mtval() const {
        return m_m.get_state().registers.mtval;
    }

    void do_write_mtval(uint64_t val) const {
        m_m.get_state().registers.mtval = val;
    }

    uint64_t do_read_misa() const {
        return m_m.get_state().registers.misa;
    }

    void do_write_misa(uint64_t val) const {
        m_m.get_state().registers.misa = val;
    }

    uint64_t do_read_mie() const {
        return m_m.get_state().registers.mie;
    }

    void do_write_mie(uint64_t val) const {
        m_m.get_state().registers.mie = val;
    }

    uint64_t do_read_mip() const {
        return m_m.get_state().registers.mip;
    }

    void do_write_mip(uint64_t val) const {
        m_m.get_state().registers.mip = val;
    }

    uint64_t do_read_medeleg() const {
        return m_m.get_state().registers.medeleg;
    }

    void do_write_medeleg(uint64_t val) const {
        m_m.get_state().registers.medeleg = val;
    }

    uint64_t do_read_mideleg() const {
        return m_m.get_state().registers.mideleg;
    }

    void do_write_mideleg(uint64_t val) const {
        m_m.get_state().registers.mideleg = val;
    }

    uint64_t do_read_mcounteren() const {
        return m_m.get_state().registers.mcounteren;
    }

    void do_write_mcounteren(uint64_t val) const {
        m_m.get_state().registers.mcounteren = val;
    }

    uint64_t do_read_senvcfg() const {
        return m_m.get_state().registers.senvcfg;
    }

    void do_write_senvcfg(uint64_t val) const {
        m_m.get_state().registers.senvcfg = val;
    }

    uint64_t do_read_stvec() const {
        return m_m.get_state().registers.stvec;
    }

    void do_write_stvec(uint64_t val) const {
        m_m.get_state().registers.stvec = val;
    }

    uint64_t do_read_sscratch() const {
        return m_m.get_state().registers.sscratch;
    }

    void do_write_sscratch(uint64_t val) const {
        m_m.get_state().registers.sscratch = val;
    }

    uint64_t do_read_sepc() const {
        return m_m.get_state().registers.sepc;
    }

    void do_write_sepc(uint64_t val) const {
        m_m.get_state().registers.sepc = val;
    }

    uint64_t do_read_scause() const {
        return m_m.get_state().registers.scause;
    }

    void do_write_scause(uint64_t val) const {
        m_m.get_state().registers.scause = val;
    }

    uint64_t do_read_stval() const {
        return m_m.get_state().registers.stval;
    }

    void do_write_stval(uint64_t val) const {
        m_m.get_state().registers.stval = val;
    }

    uint64_t do_read_satp() const {
        return m_m.get_state().registers.satp;
    }

    void do_write_satp(uint64_t val) const {
        m_m.get_state().registers.satp = val;
    }

    uint64_t do_read_scounteren() const {
        return m_m.get_state().registers.scounteren;
    }

    void do_write_scounteren(uint64_t val) const {
        m_m.get_state().registers.scounteren = val;
    }

    uint64_t do_read_ilrsc() const {
        return m_m.get_state().registers.ilrsc;
    }

    void do_write_ilrsc(uint64_t val) const {
        m_m.get_state().registers.ilrsc = val;
    }

    uint64_t do_read_iprv() const {
        return m_m.get_state().registers.iprv;
    }

    void do_write_iprv(uint64_t val) const {
        m_m.get_state().registers.iprv = val;
    }

    uint64_t do_read_iflags_X() const {
        return m_m.get_state().registers.iflags.X;
    }

    void do_write_iflags_X(uint64_t val) const {
        m_m.get_state().registers.iflags.X = val;
    }

    uint64_t do_read_iflags_Y() const {
        return m_m.get_state().registers.iflags.Y;
    }

    void do_write_iflags_Y(uint64_t val) const {
        m_m.get_state().registers.iflags.Y = val;
    }

    uint64_t do_read_iflags_H() const {
        return m_m.get_state().registers.iflags.H;
    }

    void do_write_iflags_H(uint64_t val) const {
        m_m.get_state().registers.iflags.H = val;
    }

    uint64_t do_read_iunrep() const {
        return m_m.get_state().registers.iunrep;
    }

    void do_write_iunrep(uint64_t val) const {
        m_m.get_state().registers.iunrep = val;
    }

    uint64_t do_read_clint_mtimecmp() const {
        return m_m.get_state().registers.clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) const {
        m_m.get_state().registers.clint.mtimecmp = val;
    }

    uint64_t do_read_plic_girqpend() const {
        return m_m.get_state().registers.plic.girqpend;
    }

    void do_write_plic_girqpend(uint64_t val) const {
        m_m.get_state().registers.plic.girqpend = val;
    }

    uint64_t do_read_plic_girqsrvd() const {
        return m_m.get_state().registers.plic.girqsrvd;
    }

    void do_write_plic_girqsrvd(uint64_t val) const {
        m_m.get_state().registers.plic.girqsrvd = val;
    }

    uint64_t do_read_htif_fromhost() const {
        return m_m.get_state().registers.htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) const {
        m_m.get_state().registers.htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost() const {
        return m_m.get_state().registers.htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) const {
        m_m.get_state().registers.htif.tohost = val;
    }

    uint64_t do_read_htif_ihalt() const {
        return m_m.get_state().registers.htif.ihalt;
    }

    uint64_t do_read_htif_iconsole() const {
        return m_m.get_state().registers.htif.iconsole;
    }

    uint64_t do_read_htif_iyield() const {
        return m_m.get_state().registers.htif.iyield;
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

    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        //??(edubart): Treating exceptions here is not ideal, we should probably
        // move write_memory() method implementation inside state access later
        try {
            m_m.write_memory(paddr, data, length);
            return true;
        } catch (...) {
            return false;
        }
    }

    address_range &do_read_pma(uint64_t index) const {
        return m_m.read_pma(index);
    }

    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) const {
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
    void do_read_memory_word(host_addr haddr, uint64_t /* pma_index */, T *pval) const {
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A = T>
    void do_write_memory_word(host_addr haddr, uint64_t /* pma_index */, T val) const {
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return m_m.get_state().hot_tlb[SET][slot_index].vaddr_page;
    }

    template <TLB_set_index SET>
    host_addr do_read_tlb_vf_offset(uint64_t slot_index) const {
        return m_m.get_state().hot_tlb[SET][slot_index].vh_offset;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return m_m.get_state().shadow_tlb[SET][slot_index].pma_index;
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) const {
        m_m.write_tlb(SET, slot_index, vaddr_page, vh_offset, pma_index);
    }

    fast_addr do_get_faddr(uint64_t paddr, uint64_t pma_index) const {
        return m_m.get_host_addr(paddr, pma_index);
    }

    void do_mark_dirty_page(host_addr haddr, uint64_t pma_index) const {
        m_m.mark_dirty_page(haddr, pma_index);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_putchar(uint8_t c) const {
        os_putchar(c);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "state_access";
    }

    // -----
    // i_intereactive_state_access interface implementation
    // -----
    friend i_interactive_state_access<state_access>;

    NO_INLINE auto do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) const {
        return m_m.poll_external_interrupts(mcycle, mcycle_max);
    }

    bool do_get_soft_yield() const {
        return m_m.is_soft_yield();
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    int do_getchar() const {
        os_poll_tty(0);
        return os_getchar();
    }

    // -----
    // i_accept_counters interface implementation
    // -----
    friend i_accept_counters<state_access>;

    void do_increment_counter(const char *name, const char *domain) const {
        m_m.increment_counter(name, domain);
    }

    uint64_t do_read_counter(const char *name, const char *domain) const {
        return m_m.read_counter(name, domain);
    }

    void do_write_counter(uint64_t val, const char *name, const char *domain) const {
        m_m.write_counter(val, name, domain);
    }
};

} // namespace cartesi

#endif
