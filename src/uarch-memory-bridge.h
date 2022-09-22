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

#ifndef UARCH_MEMORY_BRIDGE_H
#define UARCH_MEMORY_BRIDGE_H

#include "clint.h"
#include "htif.h"
#include "shadow.h"
#include "uarch-constants.h"

namespace cartesi {

// Allows the "micro" machine to access the "big" machine via memory reads and writes
template <typename STATE_ACCESS>
class uarch_memory_bridge {
public:
    template <typename T>
    static void write_memory_word(STATE_ACCESS &a, uint64_t paddr, T data) {
        // first, check if the memory address refers to a state register and write to it, if true
        if (write_register(a, paddr, data)) {
            return; // we are done, the register was updated
        }

        // This is a regular memory write, proceed as usual

        auto &pma = a.template find_pma_entry<T>(paddr);

        if (pma.get_istart_E()) {
            throw std::runtime_error("Invalid write memory access");
        }

        if (!pma.get_istart_W()) {
            throw std::runtime_error("Memory is not writable");
        }

        if (!pma.get_istart_M()) {
            // we just allow memory writes
            // writes to device ranges should be handled by write_register(), above, as consequence of
            // executing device driver code compiled to the microarchitecture
            throw std::runtime_error("Write access not supported for non-memory ranges");
        }

        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        unsigned char *hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
        pma.mark_dirty_page(paddr_page - pma.get_start());
        uint64_t hoffset = paddr & PAGE_OFFSET_MASK;
        a.write_memory_word(paddr, hpage, hoffset, data);
    }

    template <typename T>
    static void read_memory_word(STATE_ACCESS &a, uint64_t paddr, T *data) {
        // first, check if the memory address refers to a state register and read it, if true
        if (read_register(a, paddr, data)) {
            return; // we are done reading the register
        }

        // This is a regular memory read, proceed as usual

        auto &pma = a.template find_pma_entry<T>(paddr);
        if (pma.get_istart_E()) {
            throw std::runtime_error("Invalid read memory access");
        }

        if (!pma.get_istart_R()) {
            throw std::runtime_error("Memory is not readable");
        }

        if (!pma.get_istart_M()) {
            // We just allow memory reads.
            // Reads to device ranges should be handled by read_register(), above, as consequence of
            // executing device driver code compiled to the microarchitecture.
            throw std::runtime_error("Read access not supported for non-memory ranges");
        }

        unsigned char *hpage = nullptr;
        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
        uint64_t hoffset = paddr & PAGE_OFFSET_MASK;
        a.template read_memory_word(paddr, hpage, hoffset, data);
    }

private:
    template <typename T>
    static bool write_register(STATE_ACCESS &a, uint64_t paddr, T data) {
        (void) a;
        (void) paddr;
        (void) data;
        return false;
    }

    template <typename T>
    static bool read_register(STATE_ACCESS &a, uint64_t paddr, T *data) {
        (void) a;
        (void) paddr;
        (void) data;
        return false;
    }

    static bool write_register(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        return write_x(a, paddr, data) || write_shadow_csr(a, paddr, data) || write_clint_csr(a, paddr, data) ||
            write_htif_csr(a, paddr, data) || write_uarch_csr(a, paddr, data);
    }

    static bool read_register(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        return read_x(a, paddr, data) || read_pma(a, paddr, data) || read_shadow_csr(a, paddr, data) ||
            read_clint_csr(a, paddr, data) || read_htif_csr(a, paddr, data);
    }

    static bool write_x(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        const uint64_t regs_max = X_REG_COUNT * sizeof(uint64_t);
        if (paddr >= regs_max) {
            return false;
        }
        if (paddr & 3) {
            throw std::runtime_error("Read register value not correctly aligned");
        }

        a.write_x(paddr >> 3, data);
        return true;
    }

    static bool read_x(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        const uint64_t regs_max = X_REG_COUNT * sizeof(uint64_t);
        if (paddr >= regs_max) {
            return false;
        }
        if (paddr & 3) {
            throw std::runtime_error("Read register value not correctly aligned");
        }

        *data = a.read_x(paddr >> 3);
        return true;
    }

    static bool write_shadow_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        switch (static_cast<shadow_csr>(paddr)) {
            case shadow_csr::pc:
                a.write_pc(data);
                return true;
            case shadow_csr::mcycle:
                a.write_mcycle(data);
                return true;
            case shadow_csr::minstret:
                a.write_minstret(data);
                return true;
            case shadow_csr::mstatus:
                a.write_mstatus(data);
                return true;
            case shadow_csr::mtvec:
                a.write_mtvec(data);
                return true;
            case shadow_csr::mscratch:
                a.write_mscratch(data);
                return true;
            case shadow_csr::mepc:
                a.write_mepc(data);
                return true;
            case shadow_csr::mcause:
                a.write_mcause(data);
                return true;
            case shadow_csr::mtval:
                a.write_mtval(data);
                return true;
            case shadow_csr::misa:
                a.write_misa(data);
                return true;
            case shadow_csr::mie:
                a.write_mie(data);
                return true;
            case shadow_csr::mip:
                a.write_mip(data);
                return true;
            case shadow_csr::medeleg:
                a.write_medeleg(data);
                return true;
            case shadow_csr::mideleg:
                a.write_mideleg(data);
                return true;
            case shadow_csr::mcounteren:
                a.write_mcounteren(data);
                return true;
            case shadow_csr::stvec:
                a.write_stvec(data);
                return true;
            case shadow_csr::sscratch:
                a.write_sscratch(data);
                return true;
            case shadow_csr::sepc:
                a.write_sepc(data);
                return true;
            case shadow_csr::scause:
                a.write_scause(data);
                return true;
            case shadow_csr::stval:
                a.write_stval(data);
                return true;
            case shadow_csr::satp:
                a.write_satp(data);
                return true;
            case shadow_csr::scounteren:
                a.write_scounteren(data);
                return true;
            case shadow_csr::ilrsc:
                a.write_ilrsc(data);
                return true;
            case shadow_csr::iflags:
                a.write_iflags(data);
                return true;
            case shadow_csr::brkflag:
                switch (static_cast<uarch_brk_ctl>(data)) {
                    case uarch_brk_ctl::set:
                        a.set_brk();
                        return true;
                    case uarch_brk_ctl::or_with_mip_mie:
                        a.or_brk_with_mip_mie();
                        return true;
                    case uarch_brk_ctl::set_from_all:
                        a.set_brk_from_all();
                        return true;
                    case uarch_brk_ctl::assert_no_brk:
                        a.assert_no_brk();
                        return true;
                    default:
                        return false;
                }
            default:
                return false;
        }
    }

    static bool read_shadow_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        switch (static_cast<shadow_csr>(paddr)) {
            case shadow_csr::pc:
                *data = a.read_pc();
                return true;
            case shadow_csr::mvendorid:
                *data = a.read_mvendorid();
                return true;
            case shadow_csr::marchid:
                *data = a.read_marchid();
                return true;
            case shadow_csr::mimpid:
                *data = a.read_mimpid();
                return true;
            case shadow_csr::mcycle:
                *data = a.read_mcycle();
                return true;
            case shadow_csr::minstret:
                *data = a.read_minstret();
                return true;
            case shadow_csr::mstatus:
                *data = a.read_mstatus();
                return true;
            case shadow_csr::mtvec:
                *data = a.read_mtvec();
                return true;
            case shadow_csr::mscratch:
                *data = a.read_mscratch();
                return true;
            case shadow_csr::mepc:
                *data = a.read_mepc();
                return true;
            case shadow_csr::mcause:
                *data = a.read_mcause();
                return true;
            case shadow_csr::mtval:
                *data = a.read_mtval();
                return true;
            case shadow_csr::misa:
                *data = a.read_misa();
                return true;
            case shadow_csr::mie:
                *data = a.read_mie();
                return true;
            case shadow_csr::mip:
                *data = a.read_mip();
                return true;
            case shadow_csr::medeleg:
                *data = a.read_medeleg();
                return true;
            case shadow_csr::mideleg:
                *data = a.read_mideleg();
                return true;
            case shadow_csr::mcounteren:
                *data = a.read_mcounteren();
                return true;
            case shadow_csr::stvec:
                *data = a.read_stvec();
                return true;
            case shadow_csr::sscratch:
                *data = a.read_sscratch();
                return true;
            case shadow_csr::sepc:
                *data = a.read_sepc();
                return true;
            case shadow_csr::scause:
                *data = a.read_scause();
                return true;
            case shadow_csr::stval:
                *data = a.read_stval();
                return true;
            case shadow_csr::satp:
                *data = a.read_satp();
                return true;
            case shadow_csr::scounteren:
                *data = a.read_scounteren();
                return true;
            case shadow_csr::ilrsc:
                *data = a.read_ilrsc();
                return true;
            case shadow_csr::iflags:
                *data = a.read_iflags();
                return true;
            case shadow_csr::brkflag:
                *data = static_cast<uint64_t>(a.get_brk() ? uarch_brk_ctl::set : uarch_brk_ctl::not_set);
                return true;
            default:
                return false;
        }
    }

    static bool write_clint_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        if (paddr == clint_get_csr_abs_addr(clint_csr::mtimecmp)) {
            a.write_clint_mtimecmp(data);
            return true;
        }
        return false;
    }

    static bool read_clint_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (paddr == clint_get_csr_abs_addr(clint_csr::mtimecmp)) {
            *data = a.read_clint_mtimecmp();
            return true;
        }
        return false;
    }

    static bool write_htif_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        if (paddr == htif::get_csr_abs_addr(htif::csr::fromhost)) {
            a.write_htif_fromhost(data);
            return true;
        }

        if (paddr == htif::get_csr_abs_addr(htif::csr::tohost)) {
            a.write_htif_tohost(data);
            return true;
        }

        return false;
    }

    static bool read_htif_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (paddr == htif::get_csr_abs_addr(htif::csr::fromhost)) {
            *data = a.read_htif_fromhost();
            return true;
        }

        if (paddr == htif::get_csr_abs_addr(htif::csr::tohost)) {
            *data = a.read_htif_tohost();
            return true;
        }

        if (paddr == htif::get_csr_abs_addr(htif::csr::ihalt)) {
            *data = a.read_htif_ihalt();
            return true;
        }

        if (paddr == htif::get_csr_abs_addr(htif::csr::iconsole)) {
            *data = a.read_htif_iconsole();
            return true;
        }

        if (paddr == htif::get_csr_abs_addr(htif::csr::iyield)) {
            *data = a.read_htif_iyield();
            return true;
        }

        return false;
    }

    static bool read_pma(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (paddr < PMA_BOARD_SHADOW_START || paddr >= PMA_BOARD_SHADOW_START + (PMA_MAX * PMA_WORD_SIZE * 2)) {
            return false;
        }
        auto word_index = (paddr - PMA_BOARD_SHADOW_START) >> 3;
        auto pma_index = word_index >> 1;
        auto &pma = a.get_pma_entry(pma_index);
        if ((word_index & 1) == 0) {
            *data = pma.get_istart();
        } else {
            *data = pma.get_ilength();
        }
        return true;
    }

    // uarch "CSR" is not right, but I still don't know what to call it
    static bool write_uarch_csr(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        // Request from the microarchitecture to print a character on the console
        if (paddr == static_cast<uint64_t>(uarch_ctl_addr::putchar)) {
            putchar(static_cast<char>(data));
            return true;
        }

        // Request from the microarchitecture to abort execution
        if (paddr == static_cast<uint64_t>(uarch_ctl_addr::abort)) {
            throw std::runtime_error("Microarchitecture execution aborted");
        }

        // Request from the microarchitecture to mark a dirty pma page
        if (paddr == static_cast<uint64_t>(uarch_ctl_addr::pma_mark_page_dirty)) {
            uint64_t dw = (uint64_t) data;
            int index = (int) (dw & ((1 << PMA_constants::PMA_PAGE_SIZE_LOG2) - 1));
            uint64_t page = dw >> PMA_constants::PMA_PAGE_SIZE_LOG2;
            uint64_t address_in_range = page << PMA_constants::PMA_PAGE_SIZE_LOG2;
            auto &pma = a.get_pma_entry(index);
            // printf("** HOST mark_dirty_page %d, %llx\n", index, address_in_range);
            pma.mark_dirty_page(address_in_range);
            return true;
        }

        return false;
    }
};

} // namespace cartesi

#endif
