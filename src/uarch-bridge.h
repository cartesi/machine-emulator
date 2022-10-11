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

#ifndef UARCH_MEMORY_MAPPED_IO_H
#define UARCH_MEMORY_MAPPED_IO_H

#include "clint.h"
#include "htif.h"
#include "shadow-state.h"
#include "uarch-constants.h"

namespace cartesi {

/// \brief Allows microarchitecture code to access the machine state
/// \tparam STATE_ACCESS Machine state accessor type (i_state_access derived)
template <typename STATE_ACCESS>
class uarch_bridge {
public:
    /// \brief Writes a word to the machine state.
    /// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
    /// \param a Machine state accessor object.
    /// \param paddr Address that identifies the machine state register or memory to be written to
    /// \param data Data to write
    /// \details \{
    /// If the address falls within a device memory range, the respective register is updated.
    /// If the address falls within a memory range, that memory address is updated.
    /// An exception is thrown, otherwise.
    //// \}
    template <typename T>
    static void write_word(STATE_ACCESS &a, uint64_t paddr, T data) {
        // Check if the memory address refers to a machine state field (register, CSR, flag)
        if (try_write_register(a, paddr, data)) {
            return; // The machine state was updated, we are done here
        }

        // Assumes that this is an attempt to write to a memory range
        // Find the pma entry that contains this word
        auto &pma = a.template find_pma_entry<T>(paddr);

        if (pma.get_istart_E()) {
            throw std::runtime_error(
                "write memory attempt from microarchitecture does not reference any registered PMA range");
        }

        if (!pma.get_istart_W()) {
            throw std::runtime_error("Memory range referenced by microarchitecture is not writable");
        }

        if (!pma.get_istart_M()) {
            // we only allow memory writes.
            throw std::runtime_error("Memory write attempt from microarchitecture references a non-memory PMA range");
        }

        // Write to host memory
        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        unsigned char *hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
        pma.mark_dirty_page(paddr_page - pma.get_start());
        uint64_t hoffset = paddr & PAGE_OFFSET_MASK;
        a.write_memory_word(paddr, hpage, hoffset, data);
    }

    /// \brief Reads a word from the machine state.
    /// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
    /// \param a Machine state accessor object.
    /// \param paddr Address that identifies the machine state register or memory to be read from.
    /// \param data Receives the word that was read
    /// \details \{
    /// If the address falls within a device memory range, the respective register is read.
    /// If the address falls within a memory range, that memory address is read.
    /// An exception is thrown, otherwise.
    //// \}
    template <typename T>
    static void read_word(STATE_ACCESS &a, uint64_t paddr, T *data) {
        // Check if the memory address refers to a machine state field (register, CSR, flag)
        if (try_read_register(a, paddr, data)) {
            return; // The machine state was read, we are done here
        }

        // Assumes that this is an attempt to write to a memory range
        // Find the pma entry that contains this word
        auto &pma = a.template find_pma_entry<T>(paddr);
        if (pma.get_istart_E()) {
            throw std::runtime_error(
                "Read memory attempt from microarchitecture does not reference any registered PMA range");
        }

        if (!pma.get_istart_R()) {
            throw std::runtime_error("Memory range referenced by microarchitecture is not readable");
        }

        if (!pma.get_istart_M()) {
            // we only allow memory read.
            throw std::runtime_error("Memory read attempt from microarchitecture references a non-memory PMA range");
        }

        // Read host memory
        unsigned char *hpage = nullptr;
        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
        uint64_t hoffset = paddr & PAGE_OFFSET_MASK;
        a.template read_memory_word(paddr, hpage, hoffset, data);
    }

private:
    template <typename T>
    /// \brief Tries to write a word to a machine state register.
    /// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
    /// \param a Machine state accessor object.
    /// \param paddr Address of the state register to write to.
    /// \param data Data to write
    /// \return true, if paddr identifies a valid machine state register and the register is successfully updated.
    static bool try_write_register(STATE_ACCESS &a, uint64_t paddr, T data) {
        (void) a;
        (void) paddr;
        (void) data;
        return false;
    }

    /// \brief Tries to write a uint64_t word to a machine state register.
    static bool try_write_register(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        if (try_write_x(a, paddr, data)) {
            return true;
        }
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::pc:
                a.write_pc(data);
                return true;
            case shadow_state_csr::mcycle:
                a.write_mcycle(data);
                return true;
            case shadow_state_csr::minstret:
                a.write_minstret(data);
                return true;
            case shadow_state_csr::mstatus:
                a.write_mstatus(data);
                return true;
            case shadow_state_csr::mtvec:
                a.write_mtvec(data);
                return true;
            case shadow_state_csr::mscratch:
                a.write_mscratch(data);
                return true;
            case shadow_state_csr::mepc:
                a.write_mepc(data);
                return true;
            case shadow_state_csr::mcause:
                a.write_mcause(data);
                return true;
            case shadow_state_csr::mtval:
                a.write_mtval(data);
                return true;
            case shadow_state_csr::misa:
                a.write_misa(data);
                return true;
            case shadow_state_csr::mie:
                a.write_mie(data);
                return true;
            case shadow_state_csr::mip:
                a.write_mip(data);
                return true;
            case shadow_state_csr::medeleg:
                a.write_medeleg(data);
                return true;
            case shadow_state_csr::mideleg:
                a.write_mideleg(data);
                return true;
            case shadow_state_csr::mcounteren:
                a.write_mcounteren(data);
                return true;
            case shadow_state_csr::menvcfg:
                a.write_menvcfg(data);
                return true;
            case shadow_state_csr::stvec:
                a.write_stvec(data);
                return true;
            case shadow_state_csr::sscratch:
                a.write_sscratch(data);
                return true;
            case shadow_state_csr::sepc:
                a.write_sepc(data);
                return true;
            case shadow_state_csr::scause:
                a.write_scause(data);
                return true;
            case shadow_state_csr::stval:
                a.write_stval(data);
                return true;
            case shadow_state_csr::satp:
                a.write_satp(data);
                return true;
            case shadow_state_csr::scounteren:
                a.write_scounteren(data);
                return true;
            case shadow_state_csr::senvcfg:
                a.write_senvcfg(data);
                return true;
            case shadow_state_csr::ilrsc:
                a.write_ilrsc(data);
                return true;
            case shadow_state_csr::iflags:
                a.write_iflags(data);
                return true;
            case shadow_state_csr::clint_mtimecmp:
                a.write_clint_mtimecmp(data);
                return true;
            case shadow_state_csr::htif_tohost:
                a.write_htif_tohost(data);
                return true;
            case shadow_state_csr::htif_fromhost:
                a.write_htif_fromhost(data);
                return true;
            case shadow_state_csr::brkflag:
                if (data) {
                    a.set_brkflag();
                } else {
                    a.reset_brkflag();
                }
                return true;
            default:
                break;
        }
        switch (static_cast<uarch_mmio>(paddr)) {
            case uarch_mmio::putchar:
                return uarch_putchar(data);
            case uarch_mmio::abort:
                return uarch_abort();
        }
        return false;
    }

    /// \brief Tries to read a word from a machine state register.
    /// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
    /// \param a Machine state accessor object.
    /// \param paddr Address of the state register to write to.
    /// \param data Receives the data that was read
    /// \return true, if paddr identifies a valid machine state register and the register is successfully read.
    template <typename T>
    static bool try_read_register(STATE_ACCESS &a, uint64_t paddr, T *data) {
        (void) a;
        (void) paddr;
        (void) data;
        return false;
    }

    /// \brief Tries to read a uint64_t word from a machine state register.
    static bool try_read_register(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (try_read_x(a, paddr, data)) {
            return true;
        }
        if (try_read_pma(a, paddr, data)) {
            return true;
        }
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::pc:
                *data = a.read_pc();
                return true;
            case shadow_state_csr::mvendorid:
                *data = a.read_mvendorid();
                return true;
            case shadow_state_csr::marchid:
                *data = a.read_marchid();
                return true;
            case shadow_state_csr::mimpid:
                *data = a.read_mimpid();
                return true;
            case shadow_state_csr::mcycle:
                *data = a.read_mcycle();
                return true;
            case shadow_state_csr::minstret:
                *data = a.read_minstret();
                return true;
            case shadow_state_csr::mstatus:
                *data = a.read_mstatus();
                return true;
            case shadow_state_csr::mtvec:
                *data = a.read_mtvec();
                return true;
            case shadow_state_csr::mscratch:
                *data = a.read_mscratch();
                return true;
            case shadow_state_csr::mepc:
                *data = a.read_mepc();
                return true;
            case shadow_state_csr::mcause:
                *data = a.read_mcause();
                return true;
            case shadow_state_csr::mtval:
                *data = a.read_mtval();
                return true;
            case shadow_state_csr::misa:
                *data = a.read_misa();
                return true;
            case shadow_state_csr::mie:
                *data = a.read_mie();
                return true;
            case shadow_state_csr::mip:
                *data = a.read_mip();
                return true;
            case shadow_state_csr::medeleg:
                *data = a.read_medeleg();
                return true;
            case shadow_state_csr::mideleg:
                *data = a.read_mideleg();
                return true;
            case shadow_state_csr::mcounteren:
                *data = a.read_mcounteren();
                return true;
            case shadow_state_csr::menvcfg:
                *data = a.read_menvcfg();
                return true;
            case shadow_state_csr::stvec:
                *data = a.read_stvec();
                return true;
            case shadow_state_csr::sscratch:
                *data = a.read_sscratch();
                return true;
            case shadow_state_csr::sepc:
                *data = a.read_sepc();
                return true;
            case shadow_state_csr::scause:
                *data = a.read_scause();
                return true;
            case shadow_state_csr::stval:
                *data = a.read_stval();
                return true;
            case shadow_state_csr::satp:
                *data = a.read_satp();
                return true;
            case shadow_state_csr::scounteren:
                *data = a.read_scounteren();
                return true;
            case shadow_state_csr::senvcfg:
                *data = a.read_senvcfg();
                return true;
            case shadow_state_csr::ilrsc:
                *data = a.read_ilrsc();
                return true;
            case shadow_state_csr::iflags:
                *data = a.read_iflags();
                return true;
            case shadow_state_csr::brkflag:
                *data = a.read_brkflag();
                return true;
            case shadow_state_csr::clint_mtimecmp:
                *data = a.read_clint_mtimecmp();
                return true;
            case shadow_state_csr::htif_tohost:
                *data = a.read_htif_tohost();
                return true;
            case shadow_state_csr::htif_fromhost:
                *data = a.read_htif_fromhost();
                return true;
            case shadow_state_csr::htif_ihalt:
                *data = a.read_htif_ihalt();
                return true;
            case shadow_state_csr::htif_iconsole:
                *data = a.read_htif_iconsole();
                return true;
            case shadow_state_csr::htif_iyield:
                *data = a.read_htif_iyield();
                return true;
            case shadow_state_csr::uarch_rom_length:
                *data = a.read_uarch_rom_length();
                return true;
            case shadow_state_csr::uarch_ram_length:
                *data = a.read_uarch_ram_length();
                return true;
            default:
                return false;
        }
    }

    /// \brief Tries to write a general-purpose machine register.
    /// \param a Machine state accessor object.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Data to write
    /// \return true if the register was successfully written.
    static bool try_write_x(STATE_ACCESS &a, uint64_t paddr, uint64_t data) {
        if (paddr < shadow_state_get_x_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_x_abs_addr(X_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 3) {
            throw std::runtime_error("Read register value not correctly aligned");
        }
        paddr -= shadow_state_get_x_abs_addr(0);
        a.write_x(paddr >> 3, data);
        return true;
    }

    /// \brief Tries to read a general-purpose machine register.
    /// \param a Machine state accessor object.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Pointer to word receiving value.
    /// \return true if the register was successfully read
    static bool try_read_x(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (paddr < shadow_state_get_x_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_x_abs_addr(X_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 3) {
            throw std::runtime_error("Read register value not correctly aligned");
        }
        paddr -= shadow_state_get_x_abs_addr(0);
        *data = a.read_x(paddr >> 3);
        return true;
    }

    static bool try_read_pma(STATE_ACCESS &a, uint64_t paddr, uint64_t *data) {
        if (paddr < PMA_SHADOW_PMAS_START || paddr >= PMA_SHADOW_PMAS_START + (PMA_MAX * PMA_WORD_SIZE * 2)) {
            return false;
        }
        auto word_index = (paddr - PMA_SHADOW_PMAS_START) >> 3;
        auto pma_index = word_index >> 1;
        auto &pma = a.get_pma_entry(pma_index);
        if ((word_index & 1) == 0) {
            *data = pma.get_istart();
        } else {
            *data = pma.get_ilength();
        }
        return true;
    }

    static bool uarch_putchar(uint64_t data) {
        putchar(static_cast<char>(data));
        return true;
    }

    static bool uarch_abort() {
        throw std::runtime_error("Microarchitecture execution aborted");
        return true;
    }
};

} // namespace cartesi

#endif
