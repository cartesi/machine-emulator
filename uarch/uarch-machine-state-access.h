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

#ifndef UARCH_MACHINE_STATE_ACCESS_H
#define UARCH_MACHINE_STATE_ACCESS_H

#include "uarch-runtime.h" // must be included first, because of assert

#define MOCK_THROW_RUNTIME_ERROR(err) abort()
#include "mock-pma-entry.h"
#include "device-state-access.h"
#include "i-state-access.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "machine-reg.h"
#include "shadow-pmas.h"
#include "uarch-constants.h"
#include "uarch-defines.h"
#include "strict-aliasing.h"
#include "compiler-defines.h"
#include <optional>

namespace cartesi {

template <typename T>
static T raw_read_memory(uint64_t paddr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    volatile T *p = reinterpret_cast<T *>(paddr);
    return *p;
}

template <typename T>
static void raw_write_memory(uint64_t paddr, T val) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    volatile T *p = reinterpret_cast<T *>(paddr);
    *p = val;
}

// Provides access to the state of the big emulator from microcode
class uarch_machine_state_access : public i_state_access<uarch_machine_state_access, mock_pma_entry> {
    std::array<std::optional<mock_pma_entry>, PMA_MAX> m_pmas;

public:
    explicit uarch_machine_state_access(std::array<std::optional<uarch_pma_entry>, PMA_MAX>& pmas) : m_pmas(pmas) {}
    uarch_machine_state_access(const uarch_machine_state_access &other) = default;
    uarch_machine_state_access(uarch_machine_state_access &&other) = default;
    uarch_machine_state_access &operator=(const uarch_machine_state_access &other) = delete;
    uarch_machine_state_access &operator=(uarch_machine_state_access &&other) = delete;
    ~uarch_machine_state_access() = default;

private:
    friend i_state_access<uarch_machine_state_access, mock_pma_entry>;

    // NOLINTBEGIN(readability-convert-member-functions-to-static)

    void do_push_bracket(bracket_type /*type*/, const char */*text*/) {
    }

    int do_make_scoped_note(const char */*text*/) {
        return 0;
    }

    uint64_t do_read_x(int reg) {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::x0, reg));
    }

    void do_write_x(int reg, uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::x0, reg), val);
    }

    uint64_t do_read_f(int reg) {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::f0, reg));
    }

    void do_write_f(int reg, uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::f0, reg), val);
    }

    uint64_t do_read_pc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::pc));
    }

    void do_write_pc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::pc), val);
    }

    uint64_t do_read_fcsr() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::fcsr));
    }

    void do_write_fcsr(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::fcsr), val);
    }

    uint64_t do_read_icycleinstret() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::icycleinstret));
    }

    void do_write_icycleinstret(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::icycleinstret), val);
    }

    uint64_t do_read_mvendorid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mvendorid));
    }

    uint64_t do_read_marchid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::marchid));
    }

    uint64_t do_read_mimpid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mimpid));
    }

    uint64_t do_read_mcycle() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcycle));
    }

    void do_write_mcycle(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcycle), val);
    }

    uint64_t do_read_mstatus() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mstatus));
    }

    void do_write_mstatus(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mstatus), val);
    }

    uint64_t do_read_mtvec() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mtvec));
    }

    void do_write_mtvec(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mtvec), val);
    }

    uint64_t do_read_mscratch() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mscratch));
    }

    void do_write_mscratch(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mscratch), val);
    }

    uint64_t do_read_mepc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mepc));
    }

    void do_write_mepc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mepc), val);
    }

    uint64_t do_read_mcause() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcause));
    }

    void do_write_mcause(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcause), val);
    }

    uint64_t do_read_mtval() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mtval));
    }

    void do_write_mtval(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mtval), val);
    }

    uint64_t do_read_misa() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::misa));
    }

    void do_write_misa(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::misa), val);
    }

    uint64_t do_read_mie() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mie));
    }

    void do_write_mie(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mie), val);
    }

    uint64_t do_read_mip() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mip));
    }

    void do_write_mip(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mip), val);
    }

    uint64_t do_read_medeleg() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::medeleg));
    }

    void do_write_medeleg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::medeleg), val);
    }

    uint64_t do_read_mideleg() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mideleg));
    }

    void do_write_mideleg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mideleg), val);
    }

    uint64_t do_read_mcounteren() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcounteren));
    }

    void do_write_mcounteren(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcounteren), val);
    }

    uint64_t do_read_senvcfg() const {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::senvcfg));
    }

    void do_write_senvcfg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::senvcfg), val);
    }

    uint64_t do_read_menvcfg() const {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::menvcfg));
    }

    void do_write_menvcfg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::menvcfg), val);
    }

    uint64_t do_read_stvec() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::stvec));
    }

    void do_write_stvec(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::stvec), val);
    }

    uint64_t do_read_sscratch() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::sscratch));
    }

    void do_write_sscratch(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::sscratch), val);
    }

    uint64_t do_read_sepc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::sepc));
    }

    void do_write_sepc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::sepc), val);
    }

    uint64_t do_read_scause() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::scause));
    }

    void do_write_scause(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::scause), val);
    }

    uint64_t do_read_stval() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::stval));
    }

    void do_write_stval(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::stval), val);
    }

    uint64_t do_read_satp() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::satp));
    }

    void do_write_satp(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::satp), val);
    }

    uint64_t do_read_scounteren() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::scounteren));
    }

    void do_write_scounteren(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::scounteren), val);
    }

    uint64_t do_read_ilrsc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::ilrsc));
    }

    void do_write_ilrsc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::ilrsc), val);
    }

    uint64_t do_read_iprv() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iprv));
    }

    void do_write_iprv(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iprv), val);
    }

    uint64_t do_read_iflags_X() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_X));
    }

    void do_write_iflags_X(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_X), val);
    }

    uint64_t do_read_iflags_Y() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_Y));
    }

    void do_write_iflags_Y(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_Y), val);
    }

    uint64_t do_read_iflags_H() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_H));
    }

    void do_write_iflags_H(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_H), val);
    }

    uint64_t do_read_iunrep() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iunrep));
    }

    void do_write_iunrep(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iunrep), val);
    }

    uint64_t do_read_clint_mtimecmp() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::clint_mtimecmp));
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::clint_mtimecmp), val);
    }

    uint64_t do_read_plic_girqpend() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqpend));
    }

    void do_write_plic_girqpend(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqpend), val);
    }

    uint64_t do_read_plic_girqsrvd() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqsrvd));
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqsrvd), val);
    }

    uint64_t do_read_htif_fromhost() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_fromhost));
    }

    void do_write_htif_fromhost(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::htif_fromhost), val);
    }

    uint64_t do_read_htif_tohost() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_tohost));
    }

    void do_write_htif_tohost(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::htif_tohost), val);
    }

    uint64_t do_read_htif_ihalt() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_ihalt));
    }

    uint64_t do_read_htif_iconsole() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_iconsole));
    }

    uint64_t do_read_htif_iyield() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_iyield));
    }

    std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t /*mcycle_max*/) {
        return {mcycle, false};
    }

    uint64_t read_pma_istart(uint64_t i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i));
    }

    uint64_t read_pma_ilength(uint64_t i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i) + sizeof(uint64_t));
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char */*hpage*/, uint64_t /*hoffset*/, T *pval) {
        *pval = raw_read_memory<T>(paddr);
    }

    bool do_read_memory(uint64_t /*paddr*/, unsigned char */*data*/, uint64_t /*length*/) {
        // This is not implemented yet because it's not being used
        abort();
        return false;
    }

    bool do_write_memory(uint64_t /*paddr*/, const unsigned char */*data*/, uint64_t /*length*/) {
        // This is not implemented yet because it's not being used
        abort();
        return false;
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, const unsigned char */*hpage*/, uint64_t /*hoffset*/, T val) {
        raw_write_memory(paddr, val);
    }

    mock_pma_entry &do_read_pma_entry(uint64_t index) {
        const uint64_t istart = read_pma_istart(index);
        const uint64_t ilength = read_pma_ilength(index);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        int i = static_cast<int>(index);
        if (!m_pmas[i]) {
            m_pmas[i] = make_mock_pma_entry(index, istart, ilength, [](const char * /*err*/) {
                abort();
            });
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return m_pmas[index].value();
    }

    unsigned char *do_get_host_memory(mock_pma_entry &/*pma*/) {
        return nullptr;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_hot_entry& do_get_tlb_hot_entry(uint64_t eidx) {
        // Volatile is used, so the compiler does not optimize out, or do of order writes.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
        volatile tlb_hot_entry *tlbe = reinterpret_cast<tlb_hot_entry *>(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_cold_entry& do_get_tlb_entry_cold(uint64_t eidx) {
        // Volatile is used, so the compiler does not optimize out, or do of order writes.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
        volatile tlb_cold_entry *tlbe = reinterpret_cast<tlb_cold_entry *>(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            const uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            *phptr = cast_addr_to_ptr<unsigned char *>(tlbce.paddr_page + poffset);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            const uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            *pval = raw_read_memory<T>(tlbce.paddr_page + poffset);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            const uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            raw_write_memory(tlbce.paddr_page + poffset, val);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, mock_pma_entry &pma) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                mock_pma_entry &pma = do_read_pma_entry(tlbce.pma_index);
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            }
        }
        const uint64_t vaddr_page = vaddr & ~PAGE_OFFSET_MASK;
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        // Both pma_index and paddr_page MUST BE written while its state is invalidated,
        // otherwise TLB entry may be read in an incomplete state when computing root hash
        // while stepping over this function.
        // To do this we first invalidate TLB state before these fields are written to "lock",
        // and "unlock" by writing a valid vaddr_page.
        tlbhe.vaddr_page = TLB_INVALID_PAGE; // "lock", DO NOT OPTIMIZE OUT THIS LINE
        tlbce.pma_index = pma.get_index();
        tlbce.paddr_page = paddr_page;
        // The write to vaddr_page MUST BE the last TLB entry write.
        tlbhe.vaddr_page = vaddr_page; // "unlock"
        // Note that we can't write here the correct vh_offset value, because it depends in a host pointer,
        // however the uarch memory bridge will take care of updating it.
        return cast_addr_to_ptr<unsigned char*>(paddr_page);
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_entry(uint64_t eidx) {
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
                const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
                mock_pma_entry &pma = do_read_pma_entry(tlbce.pma_index);
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
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

    bool do_get_soft_yield() {
        // Soft yield is meaningless in microarchitecture
        return false;
    }

    // NOLINTEND(readability-convert-member-functions-to-static)
};

} // namespace cartesi

#endif
