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

#ifndef MACHINE_UARCH_BRIDGE_STATE_ACCESS_H
#define MACHINE_UARCH_BRIDGE_STATE_ACCESS_H

#include "uarch-runtime.h" // must be included first, because of assert

#include <optional>

#include "compiler-defines.h"
#include "device-state-access.h"
#include "i-state-access.h"
#include "machine-reg.h"
#include "mock-pma-entry.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "shadow-pmas.h"
#include "uarch-constants.h"
#include "uarch-defines.h"
#include "uarch-ecall.h"
#include "uarch-strict-aliasing.h"

#if DUMP_UARCH_STATE_ACCESS
#include "scoped-note.h"
#endif

namespace cartesi {

class machine_uarch_bridge_state_access;

// Type trait that should return the pma_entry type for a state access class
template <>
struct i_state_access_pma_entry<machine_uarch_bridge_state_access> {
    using type = mock_pma_entry;
};
// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<machine_uarch_bridge_state_access> {
    using type = uint64_t;
};

// Provides access to the state of the big emulator from microcode
class machine_uarch_bridge_state_access : public i_state_access<machine_uarch_bridge_state_access> {

    //NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::array<std::optional<mock_pma_entry>, PMA_MAX> &m_pmas;

public:
    machine_uarch_bridge_state_access(std::array<std::optional<mock_pma_entry>, PMA_MAX> &pmas): m_pmas(pmas) {}
    machine_uarch_bridge_state_access(const machine_uarch_bridge_state_access &other) = default;
    machine_uarch_bridge_state_access(machine_uarch_bridge_state_access &&other) = default;
    machine_uarch_bridge_state_access &operator=(const machine_uarch_bridge_state_access &other) = delete;
    machine_uarch_bridge_state_access &operator=(machine_uarch_bridge_state_access &&other) = delete;
    ~machine_uarch_bridge_state_access() = default;

private:
    friend i_state_access<machine_uarch_bridge_state_access>;

#ifdef DUMP_UARCH_STATE_ACCESS
    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    auto do_make_scoped_note([[maybe_unused]] const char *text) {
        return scoped_note<machine_uarch_bridge_state_access>{*this, text};
    }
#endif

    uint64_t bridge_read_reg(machine_reg reg) {
        return ua_aliased_aligned_read<uint64_t>(machine_reg_address(reg));
    }

    void bridge_write_reg(machine_reg reg, uint64_t val) {
        ua_aliased_aligned_write<uint64_t>(machine_reg_address(reg), val);
    }

    uint64_t do_read_x(int i) {
        return bridge_read_reg(machine_reg_enum(machine_reg::x0, i));
    }

    void do_write_x(int i, uint64_t val) {
        bridge_write_reg(machine_reg_enum(machine_reg::x0, i), val);
    }

    uint64_t do_read_f(int i) {
        return bridge_read_reg(machine_reg_enum(machine_reg::f0, i));
    }

    void do_write_f(int i, uint64_t val) {
        bridge_write_reg(machine_reg_enum(machine_reg::f0, i), val);
    }

    uint64_t do_read_pc() {
        return bridge_read_reg(machine_reg::pc);
    }

    void do_write_pc(uint64_t val) {
        bridge_write_reg(machine_reg::pc, val);
    }

    uint64_t do_read_fcsr() {
        return bridge_read_reg(machine_reg::fcsr);
    }

    void do_write_fcsr(uint64_t val) {
        bridge_write_reg(machine_reg::fcsr, val);
    }

    uint64_t do_read_icycleinstret() {
        return bridge_read_reg(machine_reg::icycleinstret);
    }

    void do_write_icycleinstret(uint64_t val) {
        bridge_write_reg(machine_reg::icycleinstret, val);
    }

    uint64_t do_read_mvendorid() {
        return bridge_read_reg(machine_reg::mvendorid);
    }

    uint64_t do_read_marchid() {
        return bridge_read_reg(machine_reg::marchid);
    }

    uint64_t do_read_mimpid() {
        return bridge_read_reg(machine_reg::mimpid);
    }

    uint64_t do_read_mcycle() {
        return bridge_read_reg(machine_reg::mcycle);
    }

    void do_write_mcycle(uint64_t val) {
        bridge_write_reg(machine_reg::mcycle, val);
    }

    uint64_t do_read_mstatus() {
        return bridge_read_reg(machine_reg::mstatus);
    }

    void do_write_mstatus(uint64_t val) {
        bridge_write_reg(machine_reg::mstatus, val);
    }

    uint64_t do_read_mtvec() {
        return bridge_read_reg(machine_reg::mtvec);
    }

    void do_write_mtvec(uint64_t val) {
        bridge_write_reg(machine_reg::mtvec, val);
    }

    uint64_t do_read_mscratch() {
        return bridge_read_reg(machine_reg::mscratch);
    }

    void do_write_mscratch(uint64_t val) {
        bridge_write_reg(machine_reg::mscratch, val);
    }

    uint64_t do_read_mepc() {
        return bridge_read_reg(machine_reg::mepc);
    }

    void do_write_mepc(uint64_t val) {
        bridge_write_reg(machine_reg::mepc, val);
    }

    uint64_t do_read_mcause() {
        return bridge_read_reg(machine_reg::mcause);
    }

    void do_write_mcause(uint64_t val) {
        bridge_write_reg(machine_reg::mcause, val);
    }

    uint64_t do_read_mtval() {
        return bridge_read_reg(machine_reg::mtval);
    }

    void do_write_mtval(uint64_t val) {
        bridge_write_reg(machine_reg::mtval, val);
    }

    uint64_t do_read_misa() {
        return bridge_read_reg(machine_reg::misa);
    }

    void do_write_misa(uint64_t val) {
        bridge_write_reg(machine_reg::misa, val);
    }

    uint64_t do_read_mie() {
        return bridge_read_reg(machine_reg::mie);
    }

    void do_write_mie(uint64_t val) {
        bridge_write_reg(machine_reg::mie, val);
    }

    uint64_t do_read_mip() {
        return bridge_read_reg(machine_reg::mip);
    }

    void do_write_mip(uint64_t val) {
        bridge_write_reg(machine_reg::mip, val);
    }

    uint64_t do_read_medeleg() {
        return bridge_read_reg(machine_reg::medeleg);
    }

    void do_write_medeleg(uint64_t val) {
        bridge_write_reg(machine_reg::medeleg, val);
    }

    uint64_t do_read_mideleg() {
        return bridge_read_reg(machine_reg::mideleg);
    }

    void do_write_mideleg(uint64_t val) {
        bridge_write_reg(machine_reg::mideleg, val);
    }

    uint64_t do_read_mcounteren() {
        return bridge_read_reg(machine_reg::mcounteren);
    }

    void do_write_mcounteren(uint64_t val) {
        bridge_write_reg(machine_reg::mcounteren, val);
    }

    uint64_t do_read_senvcfg() {
        return bridge_read_reg(machine_reg::senvcfg);
    }

    void do_write_senvcfg(uint64_t val) {
        bridge_write_reg(machine_reg::senvcfg, val);
    }

    uint64_t do_read_menvcfg() {
        return bridge_read_reg(machine_reg::menvcfg);
    }

    void do_write_menvcfg(uint64_t val) {
        bridge_write_reg(machine_reg::menvcfg, val);
    }

    uint64_t do_read_stvec() {
        return bridge_read_reg(machine_reg::stvec);
    }

    void do_write_stvec(uint64_t val) {
        bridge_write_reg(machine_reg::stvec, val);
    }

    uint64_t do_read_sscratch() {
        return bridge_read_reg(machine_reg::sscratch);
    }

    void do_write_sscratch(uint64_t val) {
        bridge_write_reg(machine_reg::sscratch, val);
    }

    uint64_t do_read_sepc() {
        return bridge_read_reg(machine_reg::sepc);
    }

    void do_write_sepc(uint64_t val) {
        bridge_write_reg(machine_reg::sepc, val);
    }

    uint64_t do_read_scause() {
        return bridge_read_reg(machine_reg::scause);
    }

    void do_write_scause(uint64_t val) {
        bridge_write_reg(machine_reg::scause, val);
    }

    uint64_t do_read_stval() {
        return bridge_read_reg(machine_reg::stval);
    }

    void do_write_stval(uint64_t val) {
        bridge_write_reg(machine_reg::stval, val);
    }

    uint64_t do_read_satp() {
        return bridge_read_reg(machine_reg::satp);
    }

    void do_write_satp(uint64_t val) {
        bridge_write_reg(machine_reg::satp, val);
    }

    uint64_t do_read_scounteren() {
        return bridge_read_reg(machine_reg::scounteren);
    }

    void do_write_scounteren(uint64_t val) {
        bridge_write_reg(machine_reg::scounteren, val);
    }

    uint64_t do_read_ilrsc() {
        return bridge_read_reg(machine_reg::ilrsc);
    }

    void do_write_ilrsc(uint64_t val) {
        bridge_write_reg(machine_reg::ilrsc, val);
    }

    uint64_t do_read_iprv() {
        return bridge_read_reg(machine_reg::iprv);
    }

    void do_write_iprv(uint64_t val) {
        bridge_write_reg(machine_reg::iprv, val);
    }

    uint64_t do_read_iflags_X() {
        return bridge_read_reg(machine_reg::iflags_X);
    }

    void do_write_iflags_X(uint64_t val) {
        bridge_write_reg(machine_reg::iflags_X, val);
    }

    uint64_t do_read_iflags_Y() {
        return bridge_read_reg(machine_reg::iflags_Y);
    }

    void do_write_iflags_Y(uint64_t val) {
        bridge_write_reg(machine_reg::iflags_Y, val);
    }

    uint64_t do_read_iflags_H() {
        return bridge_read_reg(machine_reg::iflags_H);
    }

    void do_write_iflags_H(uint64_t val) {
        bridge_write_reg(machine_reg::iflags_H, val);
    }

    uint64_t do_read_iunrep() {
        return bridge_read_reg(machine_reg::iunrep);
    }

    void do_write_iunrep(uint64_t val) {
        bridge_write_reg(machine_reg::iunrep, val);
    }

    uint64_t do_read_clint_mtimecmp() {
        return bridge_read_reg(machine_reg::clint_mtimecmp);
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        bridge_write_reg(machine_reg::clint_mtimecmp, val);
    }

    uint64_t do_read_plic_girqpend() {
        return bridge_read_reg(machine_reg::plic_girqpend);
    }

    void do_write_plic_girqpend(uint64_t val) {
        bridge_write_reg(machine_reg::plic_girqpend, val);
    }

    uint64_t do_read_plic_girqsrvd() {
        return bridge_read_reg(machine_reg::plic_girqsrvd);
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        bridge_write_reg(machine_reg::plic_girqsrvd, val);
    }

    uint64_t do_read_htif_fromhost() {
        return bridge_read_reg(machine_reg::htif_fromhost);
    }

    void do_write_htif_fromhost(uint64_t val) {
        bridge_write_reg(machine_reg::htif_fromhost, val);
    }

    uint64_t do_read_htif_tohost() {
        return bridge_read_reg(machine_reg::htif_tohost);
    }

    void do_write_htif_tohost(uint64_t val) {
        bridge_write_reg(machine_reg::htif_tohost, val);
    }

    uint64_t do_read_htif_ihalt() {
        return bridge_read_reg(machine_reg::htif_ihalt);
    }

    uint64_t do_read_htif_iconsole() {
        return bridge_read_reg(machine_reg::htif_iconsole);
    }

    uint64_t do_read_htif_iyield() {
        return bridge_read_reg(machine_reg::htif_iyield);
    }

    template <typename T, typename A>
    void do_read_memory_word(uint64_t paddr, uint64_t /* pma_index */, T *pval) {
        *pval = ua_aliased_aligned_read<T, A>(paddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(uint64_t paddr, uint64_t /* pma_index */, T val) {
        ua_aliased_aligned_write<T, A>(paddr, val);
    }

    bool do_read_memory(uint64_t /*paddr*/, unsigned char * /*data*/, uint64_t /*length*/) {
        // This is not implemented yet because it's not being used
        abort();
        return false;
    }

    bool do_write_memory(uint64_t /*paddr*/, const unsigned char * /*data*/, uint64_t /*length*/) {
        // This is not implemented yet because it's not being used
        abort();
        return false;
    }

    uint64_t read_pma_istart(int i) {
        return ua_aliased_aligned_read<uint64_t>(shadow_pmas_get_pma_abs_addr(i, shadow_pmas_what::istart));
    }

    uint64_t read_pma_ilength(int i) {
        return ua_aliased_aligned_read<uint64_t>(shadow_pmas_get_pma_abs_addr(i, shadow_pmas_what::ilength));
    }

    mock_pma_entry &do_read_pma_entry(uint64_t index) {
        const uint64_t istart = read_pma_istart(index);
        const uint64_t ilength = read_pma_ilength(index);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        int i = static_cast<int>(index);
        if (!m_pmas[i]) {
            m_pmas[i] = make_mock_pma_entry(index, istart, ilength, [](const char * /*err*/) { abort(); });
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return m_pmas[i].value();
    }

    uint64_t do_get_faddr(uint64_t paddr, uint64_t /* pma_index */) const {
        return paddr;
    }

    uint64_t bridge_read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) {
        return ua_aliased_aligned_read<uint64_t>(shadow_tlb_get_abs_addr(set_index, slot_index, what));
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vaddr_page);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vp_offset(uint64_t slot_index) {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vp_offset);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index) {
        ua_write_tlb_ECALL(SET, slot_index, vaddr_page, vp_offset, pma_index);
    }

    void do_putchar(uint8_t c) {
        ua_putchar_ECALL(c);
    }

    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
        ua_mark_dirty_page_ECALL(paddr, pma_index);
    }

    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "machine_uarch_bridge_state_access";
    }

    // NOLINTEND(readability-convert-member-functions-to-static)
};

} // namespace cartesi

#endif
