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

#ifndef RECORD_MULTI_STEP_STATE_ACCESS_H
#define RECORD_MULTI_STEP_STATE_ACCESS_H

#include "clint.h"
#include "plic.h"
#include "device-state-access.h"
#include "htif.h"
#include "i-state-access.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "shadow-uarch-state.h"
#include "shadow-pmas.h"
#include "compiler-defines.h"
#include "unique-c-ptr.h"
#include <map>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <optional>

namespace cartesi {

class record_multi_step_state_access : public i_state_access<record_multi_step_state_access, pma_entry> {
    machine &m_m;
    const std::string &m_directory;
    using page_data = std::array<unsigned char, PMA_PAGE_SIZE>;
    mutable std::map<uint64_t, page_data> m_saved_pages;
public:
    record_multi_step_state_access(machine &m, const std::string &directory) : m_m(m), m_directory(directory) {
    }
    record_multi_step_state_access(const record_multi_step_state_access &) = delete;
    record_multi_step_state_access(record_multi_step_state_access &&) = delete;
    record_multi_step_state_access &operator=(const record_multi_step_state_access &) = delete;
    record_multi_step_state_access &operator=(record_multi_step_state_access &&) = delete;
    ~record_multi_step_state_access() = default;

    void finish() {
        auto fp_before = unique_fopen((m_directory + "/" + "pages-before").c_str(), "wb");
        if (!fp_before) {
            throw std::runtime_error("Could not open pages-before file for writing");
        }
        auto fp_after = unique_fopen((m_directory + "/" + "pages-after").c_str(), "wb");
        if (!fp_after) {
            throw std::runtime_error("Could not open pages-after file for writing");
        }
        uint32_t page_count = m_saved_pages.size();
        fwrite(&page_count, 1, sizeof(page_count), fp_before.get());
        fwrite(&page_count, 1, sizeof(page_count), fp_after.get());
        page_data scratch;
        for (auto &p : m_saved_pages) {
            fwrite(&p.first, 1, sizeof(p.first), fp_before.get());
            fwrite(p.second.data(), 1, PMA_PAGE_SIZE, fp_before.get()); 
            m_m.read_memory(p.first, scratch.data(), PMA_PAGE_SIZE);
            fwrite(&p.first, 1, sizeof(p.first), fp_after.get());
            fwrite(scratch.data(), 1, PMA_PAGE_SIZE, fp_after.get());
        }

    }
private:
    friend i_state_access<record_multi_step_state_access, pma_entry>;

    void save_page(uint64_t paddr) const {
        uint64_t page = paddr & ~(PMA_PAGE_SIZE - 1);
        if (m_saved_pages.find(page) != m_saved_pages.end()) {
            return; // already saved
        }
        auto [it, inserted] = m_saved_pages.emplace(page, page_data());
        if (!inserted) {
            throw std::runtime_error("Could not insert page into saved pages");
        }
        m_m.read_memory(page, it->second.data(), PMA_PAGE_SIZE);
    }

    std::string get_page_file_name(uint64_t page, const char* prefix) const {
        std::ostringstream sout;
        sout << m_directory << "/" << prefix << std::hex << std::setw(16) << std::setfill('0') << page;
        return sout.str();
    }

    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    int do_make_scoped_note(const char *text) { // NOLINT(readability-convert-member-functions-to-static)
        (void) text;
        return 0;
    }

    uint64_t do_read_x(int reg) const {
        assert(reg != 0);
        save_page(shadow_state_get_x_abs_addr(reg));
        return m_m.get_state().x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        save_page(shadow_state_get_x_abs_addr(reg));
        m_m.get_state().x[reg] = val;
    }

    uint64_t do_read_f(int reg) const {
        save_page(shadow_state_get_f_abs_addr(reg));
        return m_m.get_state().f[reg];
    }

    void do_write_f(int reg, uint64_t val) {
        save_page(shadow_state_get_f_abs_addr(reg));
        m_m.get_state().f[reg] = val;
    }

    uint64_t do_read_pc(void) const {
        // get phys address of pc in dhadow
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::pc));
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::pc));
        m_m.get_state().pc = val;
    }

    uint64_t do_read_fcsr(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::fcsr));
        return m_m.get_state().fcsr;
    }

    void do_write_fcsr(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::fcsr));
        m_m.get_state().fcsr = val;
    }

    uint64_t do_read_icycleinstret(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::icycleinstret));
        return m_m.get_state().icycleinstret;
    }

    void do_write_icycleinstret(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::icycleinstret));
        m_m.get_state().icycleinstret = val;
    }

    uint64_t do_read_mvendorid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mvendorid));
        return MVENDORID_INIT;
    }

    uint64_t do_read_marchid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::marchid));
        return MARCHID_INIT;
    }

    uint64_t do_read_mimpid(void) const { // NOLINT(readability-convert-member-functions-to-static)
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mimpid));
        return MIMPID_INIT;
    }

    uint64_t do_read_mcycle(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcycle));
        return m_m.get_state().mcycle;
    }

    void do_write_mcycle(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcycle));
        m_m.get_state().mcycle = val;
    }

    uint64_t do_read_mstatus(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mstatus));
        return m_m.get_state().mstatus;
    }

    void do_write_mstatus(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mstatus));
        m_m.get_state().mstatus = val;
    }

    uint64_t do_read_menvcfg(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::menvcfg));
        return m_m.get_state().menvcfg;
    }

    void do_write_menvcfg(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::menvcfg));
        m_m.get_state().menvcfg = val;
    }

    uint64_t do_read_mtvec(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mtvec));
        return m_m.get_state().mtvec;
    }

    void do_write_mtvec(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mtvec));
        m_m.get_state().mtvec = val;
    }

    uint64_t do_read_mscratch(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mscratch));
        return m_m.get_state().mscratch;
    }

    void do_write_mscratch(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mscratch));
        m_m.get_state().mscratch = val;
    }

    uint64_t do_read_mepc(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mepc));
        return m_m.get_state().mepc;
    }

    void do_write_mepc(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mepc));
        m_m.get_state().mepc = val;
    }

    uint64_t do_read_mcause(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcause));
        return m_m.get_state().mcause;
    }

    void do_write_mcause(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcause));
        m_m.get_state().mcause = val;
    }

    uint64_t do_read_mtval(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mtval));
        return m_m.get_state().mtval;
    }

    void do_write_mtval(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mtval));
        m_m.get_state().mtval = val;
    }

    uint64_t do_read_misa(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::misa));
        return m_m.get_state().misa;
    }

    void do_write_misa(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::misa));
        m_m.get_state().misa = val;
    }

    uint64_t do_read_mie(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mie));
        return m_m.get_state().mie;
    }

    void do_write_mie(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mie));
        m_m.get_state().mie = val;
    }

    uint64_t do_read_mip(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mip));
        return m_m.get_state().mip;
    }

    void do_write_mip(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mip));
        m_m.get_state().mip = val;
    }

    uint64_t do_read_medeleg(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::medeleg));
        return m_m.get_state().medeleg;
    }

    void do_write_medeleg(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::medeleg));
        m_m.get_state().medeleg = val;
    }

    uint64_t do_read_mideleg(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mideleg));
        return m_m.get_state().mideleg;
    }

    void do_write_mideleg(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mideleg));
        m_m.get_state().mideleg = val;
    }

    uint64_t do_read_mcounteren(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcounteren));
        return m_m.get_state().mcounteren;
    }

    void do_write_mcounteren(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::mcounteren));
        m_m.get_state().mcounteren = val;
    }

    uint64_t do_read_senvcfg(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::senvcfg));
        return m_m.get_state().senvcfg;
    }

    void do_write_senvcfg(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::senvcfg));
        m_m.get_state().senvcfg = val;
    }

    uint64_t do_read_stvec(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::stvec));
        return m_m.get_state().stvec;
    }

    void do_write_stvec(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::stvec));
        m_m.get_state().stvec = val;
    }

    uint64_t do_read_sscratch(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::sscratch));
        return m_m.get_state().sscratch;
    }

    void do_write_sscratch(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::sscratch));
        m_m.get_state().sscratch = val;
    }

    uint64_t do_read_sepc(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::sepc));
        return m_m.get_state().sepc;
    }

    void do_write_sepc(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::sepc));
        m_m.get_state().sepc = val;
    }

    uint64_t do_read_scause(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::scause));
        return m_m.get_state().scause;
    }

    void do_write_scause(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::scause));
        m_m.get_state().scause = val;
    }

    uint64_t do_read_stval(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::stval));
        return m_m.get_state().stval;
    }

    void do_write_stval(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::stval));
        m_m.get_state().stval = val;
    }

    uint64_t do_read_satp(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::satp));
        return m_m.get_state().satp;
    }

    void do_write_satp(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::satp));
        m_m.get_state().satp = val;
    }

    uint64_t do_read_scounteren(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::scounteren));
        return m_m.get_state().scounteren;
    }

    void do_write_scounteren(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::scounteren));
        m_m.get_state().scounteren = val;
    }

    uint64_t do_read_ilrsc(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::ilrsc));
        return m_m.get_state().ilrsc;
    }

    void do_write_ilrsc(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::ilrsc));
        m_m.get_state().ilrsc = val;
    }

    void do_set_iflags_H(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.H = true;
    }

    bool do_read_iflags_H(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        return m_m.get_state().iflags.H;
    }

    void do_set_iflags_X(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.X = true;
    }

    void do_reset_iflags_X(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.X = false;
    }

    bool do_read_iflags_X(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        return m_m.get_state().iflags.X;
    }

    void do_set_iflags_Y(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.Y = true;
    }

    void do_reset_iflags_Y(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.Y = false;
    }

    bool do_read_iflags_Y(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        return m_m.get_state().iflags.Y;
    }

    uint8_t do_read_iflags_PRV(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        return m_m.get_state().iflags.PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        m_m.get_state().iflags.PRV = val;
    }

    uint64_t do_read_iunrep(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iunrep));
        return m_m.get_state().iunrep;
    }

    void do_write_iunrep(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iunrep));
        m_m.get_state().iunrep = val;
    }

    uint64_t do_read_clint_mtimecmp(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::clint_mtimecmp));
        return m_m.get_state().clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::clint_mtimecmp));
        m_m.get_state().clint.mtimecmp = val;
    }

    uint64_t do_read_plic_girqpend(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::plic_girqpend));
        return m_m.get_state().plic.girqpend;
    }

    void do_write_plic_girqpend(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::plic_girqpend));
        m_m.get_state().plic.girqpend = val;
    }

    uint64_t do_read_plic_girqsrvd(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::plic_girqsrvd));
        return m_m.get_state().plic.girqsrvd;
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::plic_girqsrvd));
        m_m.get_state().plic.girqsrvd = val;
    }

    uint64_t do_read_htif_fromhost(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_fromhost));
        return m_m.get_state().htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_fromhost));
        m_m.get_state().htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_tohost));
        return m_m.get_state().htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_tohost));
        m_m.get_state().htif.tohost = val;
    }

    uint64_t do_read_htif_ihalt(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_ihalt));
        return m_m.get_state().htif.ihalt;
    }

    uint64_t do_read_htif_iconsole(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iconsole));
        return m_m.get_state().htif.iconsole;
    }

    uint64_t do_read_htif_iyield(void) const {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iyield));
        return m_m.get_state().htif.iyield;
    }

    NO_INLINE std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        return {mcycle, false};
    }

    uint64_t do_read_pma_istart(int i) const {
        assert(i >= 0 && i < (int) PMA_MAX);
        save_page(shadow_pmas_get_pma_abs_addr(i));
        const auto &pmas = m_m.get_pmas();
        uint64_t istart = 0;
        if (i >= 0 && i < static_cast<int>(pmas.size())) {
            istart = pmas[i].get_istart();
        }
        return istart;
    }

    uint64_t do_read_pma_ilength(int i) const {
        assert(i >= 0 && i < (int) PMA_MAX);
        save_page(shadow_pmas_get_pma_abs_addr(i));
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
        save_page(paddr);
        *pval = cartesi::aliased_aligned_read<T>(hpage + hoffset);
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        (void) paddr;
        save_page(paddr);
        aliased_aligned_write(hpage + hoffset, val);
    }

    bool do_read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
        throw std::runtime_error("Unexpected call to do_read_memory");
    }

    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        throw std::runtime_error("Unexpected call to do_write_memory");
    }

    template <typename T>
    pma_entry &do_find_pma_entry(uint64_t paddr) {
        int i = 0;
        while (true) {
            save_page(shadow_pmas_get_pma_abs_addr(i));
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
                save_page(paddr);
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
            save_page(shadow_pmas_get_pma_abs_addr(pmas.size() - 1));
            return pmas[pmas.size() - 1];
        }
        save_page(shadow_pmas_get_pma_abs_addr(index));
        return pmas[index];
    }

    uint64_t do_read_iflags(void) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
        return m_m.get_state().read_iflags();
    }

    void do_write_iflags(uint64_t val) {
        save_page(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
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
        //// printf("record: do_translate_vaddr_via_tlb %llx\n", vaddr);
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        save_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        *phptr = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        save_page(tlbce.paddr_page);
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    inline bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        //// printf("record: do_read_memory_word_via_tlb %llx\n", vaddr);
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        save_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx)); // save cold entry to allow reconstruction of paddr during playback
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        const auto *h = cast_addr_to_ptr<const unsigned char *>(tlbhe.vh_offset + vaddr);
        *pval = cartesi::aliased_aligned_read<T>(h);
        save_page(tlbce.paddr_page);
        
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    inline bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
        //// printf("record: do_write_memory_word_via_tlb %llx\n", vaddr);
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        //printf("---> do_write_memory_word_via_tlb  vaddr=%llx, eidx=%d\n", vaddr, eidx);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        save_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx)); // save cold entry to allow reconstruction of paddr during playback
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        save_page(tlbce.paddr_page);

        auto *h = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        aliased_aligned_write(h, val);
        return true;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, pma_entry &pma) {
        //// printf("record: do_replace_tlb_entry %llx\n", vaddr);
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        save_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx)); // save cold entry to allow reconstruction of paddr during playback
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
        save_page(tlbce.paddr_page);
        return hpage;
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_entry(uint64_t eidx) {
        //// printf("record: do_flush_tlb_entry %llx\n", eidx);
        save_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        save_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx)); // save cold entry to allow reconstruction of paddr during playback
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
        //// printf("record: do_flush_tlb_vaddr %llx\n", vaddr);
        (void) vaddr;
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

};

} // namespace cartesi

#endif
