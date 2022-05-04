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

#ifndef STATE_ACCESS_H
#define STATE_ACCESS_H

/// \file
/// \brief Fast state access implementation

#include <cassert>

#include "i-state-access.h"
#include "machine.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access : public i_state_access<state_access> {

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
    friend i_state_access<state_access>;

    const machine_state &do_get_naked_state(void) const {
        return m_m.get_state();
    }

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

    uint64_t do_read_pc(void) const {
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        m_m.get_state().pc = val;
    }

    uint64_t do_read_minstret(void) const {
        return m_m.get_state().minstret;
    }

    void do_write_minstret(uint64_t val) {
        m_m.get_state().minstret = val;
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

    uint64_t do_read_dhd_tstart(void) const {
        return m_m.get_state().dhd.tstart;
    }

    void do_write_dhd_tstart(uint64_t val) {
        m_m.get_state().dhd.tstart = val;
    }

    uint64_t do_read_dhd_tlength(void) const {
        return m_m.get_state().dhd.tlength;
    }

    void do_write_dhd_tlength(uint64_t val) {
        m_m.get_state().dhd.tlength = val;
    }

    uint64_t do_read_dhd_dlength(void) const {
        return m_m.get_state().dhd.dlength;
    }

    void do_write_dhd_dlength(uint64_t val) {
        m_m.get_state().dhd.dlength = val;
    }

    uint64_t do_read_dhd_hlength(void) const {
        return m_m.get_state().dhd.hlength;
    }

    void do_write_dhd_hlength(uint64_t val) {
        m_m.get_state().dhd.hlength = val;
    }

    uint64_t do_read_dhd_h(int i) const {
        return m_m.get_state().dhd.h[i];
    }

    void do_write_dhd_h(int i, uint64_t val) {
        m_m.get_state().dhd.h[i] = val;
    }

    dhd_data do_dehash(const unsigned char *hash, uint64_t hlength, uint64_t &dlength) {
        return m_m.get_state().dehash(hash, hlength, dlength);
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
};

} // namespace cartesi

#endif
