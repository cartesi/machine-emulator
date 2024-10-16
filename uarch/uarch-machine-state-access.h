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

#ifndef uarch_machine_state_access_H
#define uarch_machine_state_access_H

#include "uarch-runtime.h" // must be included first, because of assert

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
#include "uarch-constants.h"
#include "uarch-defines.h"
#include "strict-aliasing.h"
#include "compiler-defines.h"
#include <optional>

namespace cartesi {

template <typename T>
static T raw_read_memory(uint64_t paddr) {
    volatile T *p = reinterpret_cast<T *>(paddr);
    return *p;
}

template <typename T>
static void raw_write_memory(uint64_t paddr, T val) {
    volatile T *p = reinterpret_cast<T *>(paddr);
    *p = val;
}

class uarch_pma_entry final {
public:
    struct flags {
        bool M{};
        bool IO{};
        bool E{};
        bool R{};
        bool W{};
        bool X{};
        bool IR{};
        bool IW{};
        PMA_ISTART_DID DID{PMA_ISTART_DID::memory};
    };

private:
    int m_pma_index{-1};
    uint64_t m_start{};
    uint64_t m_length{};
    flags m_flags;
    const pma_driver *m_device_driver{};
    void *m_device_context{};

public:
    uarch_pma_entry(int pma_index, uint64_t start, uint64_t length, flags flags,
        const pma_driver *pma_driver = nullptr, void *device_context = nullptr) :
        m_pma_index{pma_index},
        m_start{start},
        m_length{length},
        m_flags{flags},
        m_device_driver{pma_driver},
        m_device_context{device_context} {}

    uarch_pma_entry() : uarch_pma_entry(-1, 0, 0, {false, false, true /* empty */}) {
        ;
    }

    int get_index() const {
        return m_pma_index;
    }

    flags get_flags() const {
        return m_flags;
    }

    uint64_t get_start() const {
        return m_start;
    }

    uint64_t get_length() const {
        return m_length;
    }

    bool get_istart_M() const {
        return m_flags.M;
    }

    bool get_istart_IO() const {
        return m_flags.IO;
    }

    bool get_istart_E() const {
        return m_flags.E;
    }

    bool get_istart_R() const {
        return m_flags.R;
    }

    bool get_istart_W() const {
        return m_flags.W;
    }

    bool get_istart_X() const {
        return m_flags.X;
    }

    bool get_istart_IR() const {
        return m_flags.IR;
    }

    const pma_driver *get_device_driver() {
        return m_device_driver;
    }

    void *get_device_context() {
        return m_device_context;
    }

    void mark_dirty_page(uint64_t /*address_in_range*/) {
        // Dummy implementation here.
        // This runs in microarchitecture.
        // The Host pages affected by writes will be marked dirty by uarch_bridge.
    }
};

// Provides access to the state of the big emulator from microcode
class uarch_machine_state_access : public i_state_access<uarch_machine_state_access, uarch_pma_entry> {
    std::array<std::optional<uarch_pma_entry>, PMA_MAX> m_pmas;

public:
    uarch_machine_state_access() {}
    uarch_machine_state_access(const uarch_machine_state_access &other) = delete;
    uarch_machine_state_access(uarch_machine_state_access &&other) = delete;
    uarch_machine_state_access &operator=(const uarch_machine_state_access &other) = delete;
    uarch_machine_state_access &operator=(uarch_machine_state_access &&other) = delete;
    ~uarch_machine_state_access() = default;

private:
    friend i_state_access<uarch_machine_state_access, uarch_pma_entry>;

    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    int do_make_scoped_note(const char *text) { // NOLINT(readability-convert-member-functions-to-static)
        (void) text;
        return 0;
    }

    uint64_t do_read_x(int reg) {
        return raw_read_memory<uint64_t>(shadow_state_get_x_abs_addr(reg));
    }

    void do_write_x(int reg, uint64_t val) {
        raw_write_memory(shadow_state_get_x_abs_addr(reg), val);
    }

    uint64_t do_read_f(int reg) {
        return raw_read_memory<uint64_t>(shadow_state_get_f_abs_addr(reg));
    }

    void do_write_f(int reg, uint64_t val) {
        raw_write_memory(shadow_state_get_f_abs_addr(reg), val);
    }

    uint64_t do_read_pc() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::pc));
    }

    void do_write_pc(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::pc), val);
    }

    uint64_t do_read_fcsr() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::fcsr));
    }

    void do_write_fcsr(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::fcsr), val);
    }

    uint64_t do_read_icycleinstret() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::icycleinstret));
    }

    void do_write_icycleinstret(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::icycleinstret), val);
    }

    uint64_t do_read_mvendorid() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mvendorid));
    }

    uint64_t do_read_marchid() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::marchid));
    }

    uint64_t do_read_mimpid() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mimpid));
    }

    uint64_t do_read_mcycle() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mcycle));
    }

    void do_write_mcycle(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mcycle), val);
    }

    uint64_t do_read_mstatus() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mstatus));
    }

    void do_write_mstatus(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mstatus), val);
    }

    uint64_t do_read_mtvec() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mtvec));
    }

    void do_write_mtvec(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mtvec), val);
    }

    uint64_t do_read_mscratch() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mscratch));
    }

    void do_write_mscratch(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mscratch), val);
    }

    uint64_t do_read_mepc() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mepc));
    }

    void do_write_mepc(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mepc), val);
    }

    uint64_t do_read_mcause() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mcause));
    }

    void do_write_mcause(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mcause), val);
    }

    uint64_t do_read_mtval() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mtval));
    }

    void do_write_mtval(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mtval), val);
    }

    uint64_t do_read_misa() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::misa));
    }

    void do_write_misa(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::misa), val);
    }

    uint64_t do_read_mie() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mie));
    }

    void do_write_mie(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mie), val);
    }

    uint64_t do_read_mip() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mip));
    }

    void do_write_mip(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mip), val);
    }

    uint64_t do_read_medeleg() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::medeleg));
    }

    void do_write_medeleg(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::medeleg), val);
    }

    uint64_t do_read_mideleg() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mideleg));
    }

    void do_write_mideleg(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mideleg), val);
    }

    uint64_t do_read_mcounteren() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::mcounteren));
    }

    void do_write_mcounteren(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::mcounteren), val);
    }

    uint64_t do_read_senvcfg() const {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::senvcfg));
    }

    void do_write_senvcfg(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::senvcfg), val);
    }

    uint64_t do_read_menvcfg() const {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::menvcfg));
    }

    void do_write_menvcfg(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::menvcfg), val);
    }

    uint64_t do_read_stvec() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::stvec));
    }

    void do_write_stvec(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::stvec), val);
    }

    uint64_t do_read_sscratch() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::sscratch));
    }

    void do_write_sscratch(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::sscratch), val);
    }

    uint64_t do_read_sepc() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::sepc));
    }

    void do_write_sepc(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::sepc), val);
    }

    uint64_t do_read_scause() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::scause));
    }

    void do_write_scause(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::scause), val);
    }

    uint64_t do_read_stval() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::stval));
    }

    void do_write_stval(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::stval), val);
    }

    uint64_t do_read_satp() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::satp));
    }

    void do_write_satp(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::satp), val);
    }

    uint64_t do_read_scounteren() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::scounteren));
    }

    void do_write_scounteren(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::scounteren), val);
    }

    uint64_t do_read_ilrsc() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::ilrsc));
    }

    void do_write_ilrsc(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::ilrsc), val);
    }

    uint64_t do_read_iflags() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::iflags));
    }

    void do_write_iflags(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::iflags), val);
    }

    void do_set_iflags_H() {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_H_MASK;
        write_iflags(new_iflags);
    }

    bool do_read_iflags_H() {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_H_MASK) != 0;
    }

    void do_set_iflags_X() {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_X_MASK;
        write_iflags(new_iflags);
    }

    void do_reset_iflags_X() {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags & (~IFLAGS_X_MASK);
        write_iflags(new_iflags);
    }

    bool do_read_iflags_X() {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_X_MASK) != 0;
    }

    void do_set_iflags_Y() {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_Y_MASK;
        write_iflags(new_iflags);
    }

    void do_reset_iflags_Y() {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags & (~IFLAGS_Y_MASK);
        write_iflags(new_iflags);
    }

    bool do_read_iflags_Y() {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_Y_MASK) != 0;
    }

    uint8_t do_read_iflags_PRV() {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_PRV_MASK) >> IFLAGS_PRV_SHIFT;
    }

    void do_write_iflags_PRV(uint8_t val) {
        auto old_iflags = read_iflags();
        auto new_iflags =
            (old_iflags & (~IFLAGS_PRV_MASK)) | ((static_cast<uint64_t>(val) << IFLAGS_PRV_SHIFT) & IFLAGS_PRV_MASK);
        write_iflags(new_iflags);
    }

    uint64_t do_read_iunrep() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::iunrep));
    }

    void do_write_iunrep(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::iunrep), val);
    }

    uint64_t do_read_clint_mtimecmp() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::clint_mtimecmp));
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        raw_write_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::clint_mtimecmp), val);
    }

    uint64_t do_read_plic_girqpend() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqpend));
    }

    void do_write_plic_girqpend(uint64_t val) {
        raw_write_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqpend), val);
    }

    uint64_t do_read_plic_girqsrvd() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqsrvd));
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        raw_write_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqsrvd), val);
    }

    uint64_t do_read_htif_fromhost() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_fromhost));
    }

    void do_write_htif_fromhost(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_fromhost), val);
    }

    uint64_t do_read_htif_tohost() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_tohost));
    }

    void do_write_htif_tohost(uint64_t val) {
        raw_write_memory(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_tohost), val);
    }

    uint64_t do_read_htif_ihalt() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_ihalt));
    }

    uint64_t do_read_htif_iconsole() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_iconsole));
    }

    uint64_t do_read_htif_iyield() {
        return raw_read_memory<uint64_t>(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_iyield));
    }

    std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t /*mcycle_max*/) {
        return {mcycle, false};
    }
    
    uint64_t do_read_pma_istart(int i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i));
    }

    uint64_t do_read_pma_ilength(int i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i) + sizeof(uint64_t));
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) {
        (void) hpage;
        (void) hoffset;
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
    void do_write_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T val) {
        (void) hpage;
        (void) hoffset;
        raw_write_memory(paddr, val);
    }

    template <typename T>
    uarch_pma_entry &do_find_pma_entry(uint64_t paddr) {
        for (unsigned int i = 0; i < m_pmas.size(); i++) {
            auto &pma = get_pma_entry(i);
            if (pma.get_istart_E()) {
                return pma;
            }
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
        }
        abort();
    }

    uarch_pma_entry &do_get_pma_entry(int index) {
        uint64_t istart = read_pma_istart(index);
        uint64_t ilength = read_pma_ilength(index);
        if (!m_pmas[index]) {
            m_pmas[index] = build_uarch_pma_entry(index, istart, ilength);
        }
        return m_pmas[index].value();
    }

    unsigned char *do_get_host_memory(uarch_pma_entry &/*pma*/) {
        return nullptr;
    }

    bool do_read_device(uarch_pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_driver()->read(pma.get_device_context(), &da, offset, pval, log2_size);
    }

    execute_status do_write_device(uarch_pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t val, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_driver()->write(pma.get_device_context(), &da, offset, val, log2_size);
    }

    uarch_pma_entry build_uarch_pma_entry(int index, uint64_t istart, uint64_t ilength) {
        uint64_t start;
        uarch_pma_entry::flags flags;
        split_istart(istart, start, flags);
        const pma_driver *driver = nullptr;
        void *device_ctx = nullptr;
        if (flags.IO) {
            switch (flags.DID) {
                case PMA_ISTART_DID::shadow_state:
                    driver = &shadow_state_driver;
                    break;
                case PMA_ISTART_DID::shadow_pmas:
                    driver = &shadow_pmas_driver;
                    break;
                case PMA_ISTART_DID::shadow_TLB:
                    driver = &shadow_tlb_driver;
                    break;
                case PMA_ISTART_DID::CLINT:
                    driver = &clint_driver;
                    break;
                case PMA_ISTART_DID::PLIC:
                    driver = &plic_driver;
                    break;
                case PMA_ISTART_DID::HTIF:
                    driver = &htif_driver;
                    break;
                default:
                    // Other unsupported device in uarch (eg. VirtIO)
                    abort();
                    break;
            }
        }
        return uarch_pma_entry{index, start, ilength, flags, driver, device_ctx};
    }

    static constexpr void split_istart(uint64_t istart, uint64_t &start, uarch_pma_entry::flags &f) {
        f.M = (istart & PMA_ISTART_M_MASK) >> PMA_ISTART_M_SHIFT;
        f.IO = (istart & PMA_ISTART_IO_MASK) >> PMA_ISTART_IO_SHIFT;
        f.E = (istart & PMA_ISTART_E_MASK) >> PMA_ISTART_E_SHIFT;
        f.R = (istart & PMA_ISTART_R_MASK) >> PMA_ISTART_R_SHIFT;
        f.W = (istart & PMA_ISTART_W_MASK) >> PMA_ISTART_W_SHIFT;
        f.X = (istart & PMA_ISTART_X_MASK) >> PMA_ISTART_X_SHIFT;
        f.IR = (istart & PMA_ISTART_IR_MASK) >> PMA_ISTART_IR_SHIFT;
        f.IW = (istart & PMA_ISTART_IW_MASK) >> PMA_ISTART_IW_SHIFT;
        f.DID = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
        start = istart & PMA_ISTART_START_MASK;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_hot_entry& do_get_tlb_hot_entry(uint64_t eidx) {
        // Volatile is used, so the compiler does not optimize out, or do of order writes.
        volatile tlb_hot_entry *tlbe = reinterpret_cast<tlb_hot_entry *>(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_cold_entry& do_get_tlb_entry_cold(uint64_t eidx) {
        // Volatile is used, so the compiler does not optimize out, or do of order writes.
        volatile tlb_cold_entry *tlbe = reinterpret_cast<tlb_cold_entry *>(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
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
            uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
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
            uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            raw_write_memory(tlbce.paddr_page + poffset, val);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, uarch_pma_entry &pma) {
        uint64_t eidx = tlb_get_entry_index(vaddr);
        volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                uarch_pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            }
        }
        uint64_t vaddr_page = vaddr & ~PAGE_OFFSET_MASK;
        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        // Both pma_index and paddr_page MUST BE written while its state is invalidated,
        // otherwise TLB entry may be read in an incomplete state when computing root hash
        // while stepping over this function.
        // To do this we first invalidate TLB state before these fields are written to "lock",
        // and "unlock" by writing a valid vaddr_page.
        tlbhe.vaddr_page = TLB_INVALID_PAGE; // "lock", DO NOT OPTIMIZE OUT THIS LINE
        tlbce.pma_index = static_cast<uint64_t>(pma.get_index());
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
                volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
                uarch_pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
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
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

    bool do_get_soft_yield() {
        // Soft yield is meaningless in microarchitecture
        return false;
    }
};

} // namespace cartesi

#endif
