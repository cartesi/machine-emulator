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


#ifndef uarch_machine_state_access_H
#define uarch_machine_state_access_H

#include "clint.h"
#include "device-state-access.h"
#include "htif.h"
#include "i-state-access.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "shadow.h"
#include "uarch-constants.h"
#include "uarch-defines.h"
#include "uarch-runtime.h"
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
        bool M;
        bool IO;
        bool E;
        bool R;
        bool W;
        bool X;
        bool IR;
        bool IW;
        PMA_ISTART_DID DID;
    };

private:
    int m_pma_index;
    uint64_t m_start;
    uint64_t m_length;
    flags m_flags;
    const device_driver *m_device_driver;
    void *m_device_context;

public:
    uarch_pma_entry(int pma_index, uint64_t start, uint64_t length, flags flags,
        const device_driver *device_driver = nullptr, void *device_context = nullptr) :
        m_pma_index{pma_index},
        m_start{start},
        m_length{length},
        m_flags{flags},
        m_device_driver{device_driver},
        m_device_context{device_context} {}

    uarch_pma_entry(void) : uarch_pma_entry(-1, 0, 0, {false, false, true /* empty */}) {
        ;
    }

    flags get_flags(void) const {
        return m_flags;
    }

    uint64_t get_start(void) const {
        return m_start;
    }

    uint64_t get_length(void) const {
        return m_length;
    }

    bool get_istart_M(void) const {
        return m_flags.M;
    }

    bool get_istart_IO(void) const {
        return m_flags.IO;
    }

    bool get_istart_E(void) const {
        return m_flags.E;
    }

    bool get_istart_R(void) const {
        return m_flags.R;
    }

    bool get_istart_W(void) const {
        return m_flags.W;
    }

    bool get_istart_X(void) const {
        return m_flags.X;
    }

    bool get_istart_IR(void) const {
        return m_flags.IR;
    }

    const device_driver *get_device_driver() {
        return m_device_driver;
    }

    void *get_device_context() {
        return m_device_context;
    }

    void mark_dirty_page(uint64_t address_in_range) {
        uint64_t page_number = address_in_range >> PMA_constants::PMA_PAGE_SIZE_LOG2;
        uint64_t data = (page_number << PMA_constants::PMA_PAGE_SIZE_LOG2) | m_pma_index;
        uint64_t paddr = static_cast<uint64_t>(uarch_mmio::mark_page_dirty);
        raw_write_memory(paddr, data);
    }
};

// Provides access to the state of the big emulator from microcode
class uarch_machine_state_access : public i_state_access<uarch_machine_state_access, uarch_pma_entry> {
    std::array<std::optional<uarch_pma_entry>, PMA_MAX> m_pmas;

public:
    uarch_machine_state_access() {}
    uarch_machine_state_access(const uarch_machine_state_access &) = delete;
    uarch_machine_state_access(uarch_machine_state_access &&) = delete;
    uarch_machine_state_access &operator=(const uarch_machine_state_access &) = delete;
    uarch_machine_state_access &operator=(uarch_machine_state_access &&) = delete;
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

    uint64_t do_read_pc(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::pc));
    }

    void do_write_pc(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::pc), val);
    }

    uint64_t do_read_minstret(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::minstret));
    }

    void do_write_minstret(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::minstret), val);
    }

    uint64_t do_read_mvendorid(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mvendorid));
    }

    uint64_t do_read_marchid(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::marchid));
    }

    uint64_t do_read_mimpid(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mimpid));
    }

    uint64_t do_read_mcycle(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mcycle));
    }

    void do_write_mcycle(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mcycle), val);
    }

    uint64_t do_read_mstatus(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mstatus));
    }

    void do_write_mstatus(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mstatus), val);
    }

    uint64_t do_read_mtvec(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mtvec));
    }

    void do_write_mtvec(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mtvec), val);
    }

    uint64_t do_read_mscratch(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mscratch));
    }

    void do_write_mscratch(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mscratch), val);
    }

    uint64_t do_read_mepc(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mepc));
    }

    void do_write_mepc(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mepc), val);
    }

    uint64_t do_read_mcause(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mcause));
    }

    void do_write_mcause(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mcause), val);
    }

    uint64_t do_read_mtval(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mtval));
    }

    void do_write_mtval(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mtval), val);
    }

    uint64_t do_read_misa(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::misa));
    }

    void do_write_misa(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::misa), val);
    }

    uint64_t do_read_mie(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mie));
    }

    void do_write_mie(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mie), val);
    }

    uint64_t do_read_mip(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mip));
    }

    void do_write_mip(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mip), val);
    }

    uint64_t do_read_medeleg(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::medeleg));
    }

    void do_write_medeleg(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::medeleg), val);
    }

    uint64_t do_read_mideleg(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mideleg));
    }

    void do_write_mideleg(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mideleg), val);
    }

    uint64_t do_read_mcounteren(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::mcounteren));
    }

    void do_write_mcounteren(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::mcounteren), val);
    }

    uint64_t do_read_stvec(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::stvec));
    }

    void do_write_stvec(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::stvec), val);
    }

    uint64_t do_read_sscratch(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::sscratch));
    }

    void do_write_sscratch(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::sscratch), val);
    }

    uint64_t do_read_sepc(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::sepc));
    }

    void do_write_sepc(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::sepc), val);
    }

    uint64_t do_read_scause(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::scause));
    }

    void do_write_scause(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::scause), val);
    }

    uint64_t do_read_stval(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::stval));
    }

    void do_write_stval(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::stval), val);
    }

    uint64_t do_read_satp(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::satp));
    }

    void do_write_satp(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::satp), val);
    }

    uint64_t do_read_scounteren(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::scounteren));
    }

    void do_write_scounteren(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::scounteren), val);
    }

    uint64_t do_read_ilrsc(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::ilrsc));
    }

    void do_write_ilrsc(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::ilrsc), val);
    }

    uint64_t do_read_iflags(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags));
    }

    void do_write_iflags(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::iflags), val);
    }

    void do_set_iflags_H(void) {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_H_MASK;
        write_iflags(new_iflags);
    }

    bool do_read_iflags_H(void) {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_H_MASK) != 0;
    }

    void do_set_iflags_X(void) {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_X_MASK;
        write_iflags(new_iflags);
    }

    void do_reset_iflags_X(void) {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags & (~IFLAGS_X_MASK);
        write_iflags(new_iflags);
    }

    bool do_read_iflags_X(void) {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_X_MASK) != 0;
    }

    void do_set_iflags_Y(void) {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags | IFLAGS_Y_MASK;
        write_iflags(new_iflags);
    }

    void do_reset_iflags_Y(void) {
        auto old_iflags = read_iflags();
        auto new_iflags = old_iflags & (~IFLAGS_Y_MASK);
        write_iflags(new_iflags);
    }

    bool do_read_iflags_Y(void) {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_Y_MASK) != 0;
    }

    uint8_t do_read_iflags_PRV(void) {
        auto iflags = read_iflags();
        return (iflags & IFLAGS_PRV_MASK) >> IFLAGS_PRV_SHIFT;
    }

    void do_write_iflags_PRV(uint8_t val) {
        auto old_iflags = read_iflags();
        auto new_iflags =
            (old_iflags & (~IFLAGS_PRV_MASK)) | ((static_cast<uint64_t>(val) << IFLAGS_PRV_SHIFT) & IFLAGS_PRV_MASK);
        write_iflags(new_iflags);
    }

    uint64_t do_read_clint_mtimecmp(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::clint_mtimecmp));
        
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        raw_write_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::clint_mtimecmp), val);
    }

    uint64_t do_read_htif_fromhost(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_fromhost));
    }

    void do_write_htif_fromhost(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_fromhost), val);
    }

    uint64_t do_read_htif_tohost(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_tohost));
    }

    void do_write_htif_tohost(uint64_t val) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_tohost), val);
    }

    uint64_t do_read_htif_ihalt(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_ihalt));
    }

    uint64_t do_read_htif_iconsole(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iconsole));
    }

    uint64_t do_read_htif_iyield(void) {
        return raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iyield));
    }

    void do_poll_console(void) {
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

    void do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) {}

    template <typename T>
    void do_write_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T val) {
        (void) hpage;
        (void) hoffset;
        raw_write_memory(paddr, val);
    }

    template <typename T>
    uarch_pma_entry &do_find_pma_entry(uint64_t paddr) {
        for (int i = 0; i < m_pmas.size(); i++) {
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

    unsigned char *do_get_host_memory(uarch_pma_entry &pma) {
        return nullptr;
    }

    bool do_read_device(uarch_pma_entry &pma, uint64_t offset, uint64_t *pval, int log2_size) {
        device_state_access da(*this);
        return pma.get_device_driver()->read(pma.get_device_context(), &da, offset, pval, log2_size);
    }

    bool do_write_device(uarch_pma_entry &pma, uint64_t offset, uint64_t val, int log2_size) {
        device_state_access da(*this);
        return pma.get_device_driver()->write(pma.get_device_context(), &da, offset, val, log2_size);
    }

    void do_set_brkflag(void) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::brkflag), static_cast<uint64_t>(uarch_brk_flag_cmd::set));
    }

    void do_set_brk_from_all(void) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::brkflag), static_cast<uint64_t>(uarch_brk_flag_cmd::set_from_all));
    }

    bool do_get_brkflag(void) const {
        auto b =
            static_cast<uarch_brk_flag_cmd>(raw_read_memory<uint64_t>(shadow_state_get_csr_abs_addr(shadow_state_csr::brkflag)));
        if (b == uarch_brk_flag_cmd::not_set) {
            return false;
        } else {
            return true;
        }
    }

    void do_or_brk_with_mip_mie(void) {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::brkflag), static_cast<uint64_t>(uarch_brk_flag_cmd::or_with_mip_mie));
    }

    void do_assert_no_brk(void) const {
        raw_write_memory(shadow_state_get_csr_abs_addr(shadow_state_csr::brkflag), static_cast<uint64_t>(uarch_brk_flag_cmd::assert_no_brk));
    }

    void do_set_brk_from_all(void) {
        write_physical_memory(shadow_get_csr_abs_addr(shadow_csr::brkflag), static_cast<uint64_t>(uarch_brk_ctl::set_from_all));
    }

    uarch_pma_entry build_uarch_pma_entry(int index, uint64_t istart, uint64_t ilength) {
        uint64_t start;
        uarch_pma_entry::flags flags;
        split_istart(istart, start, flags);
        const device_driver *driver = nullptr;
        void *device_ctx = nullptr;
        if (flags.IO) {
            switch (flags.DID) {
                case PMA_ISTART_DID::shadow:
                    driver = &shadow_driver;
                    break;
                case PMA_ISTART_DID::CLINT:
                    driver = &clint_driver;
                    break;
                case PMA_ISTART_DID::HTIF:
                    driver = &htif_driver;
                    break;
                default:
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
};

} // namespace cartesi

#endif
