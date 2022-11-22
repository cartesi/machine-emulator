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

#ifndef UARCH_BRIDGE_H
#define UARCH_BRIDGE_H

#include "clint.h"
#include "htif.h"
#include "machine-state.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "strict-aliasing.h"
#include "uarch-constants.h"
#include "uarch-state.h"

namespace cartesi {

/// \brief Allows microarchitecture code to access the machine state
class uarch_bridge {
public:
    /// \brief Updates the value of a machine state register.
    /// \param s Machine state.
    /// \param paddr Address that identifies the machine register to be written.
    /// \param data Data to write.
    /// \details \{
    /// An exception is thrown if paddr can't me mapped to a valid state register.
    //// \}
    static void write_register(uint64_t paddr, machine_state &s, uint64_t data) {
        if (try_write_x(s, paddr, data)) {
            return;
        }
        if (try_write_f(s, paddr, data)) {
            return;
        }
        if (try_write_tlb(s, paddr, data)) {
            return;
        }
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::pc:
                return success_write(s.pc, data);
            case shadow_state_csr::fcsr:
                return success_write(s.fcsr, data);
            case shadow_state_csr::mcycle:
                return success_write(s.mcycle, data);
            case shadow_state_csr::minstret:
                return success_write(s.minstret, data);
            case shadow_state_csr::mstatus:
                return success_write(s.mstatus, data);
            case shadow_state_csr::mtvec:
                return success_write(s.mtvec, data);
            case shadow_state_csr::mscratch:
                return success_write(s.mscratch, data);
            case shadow_state_csr::mepc:
                return success_write(s.mepc, data);
            case shadow_state_csr::mcause:
                return success_write(s.mcause, data);
            case shadow_state_csr::mtval:
                return success_write(s.mtval, data);
            case shadow_state_csr::misa:
                return success_write(s.misa, data);
            case shadow_state_csr::mie:
                return success_write(s.mie, data);
            case shadow_state_csr::mip:
                return success_write(s.mip, data);
            case shadow_state_csr::medeleg:
                return success_write(s.medeleg, data);
            case shadow_state_csr::mideleg:
                return success_write(s.mideleg, data);
            case shadow_state_csr::mcounteren:
                return success_write(s.mcounteren, data);
            case shadow_state_csr::menvcfg:
                return success_write(s.menvcfg, data);
            case shadow_state_csr::stvec:
                return success_write(s.stvec, data);
            case shadow_state_csr::sscratch:
                return success_write(s.sscratch, data);
            case shadow_state_csr::sepc:
                return success_write(s.sepc, data);
            case shadow_state_csr::scause:
                return success_write(s.scause, data);
            case shadow_state_csr::stval:
                return success_write(s.stval, data);
            case shadow_state_csr::satp:
                return success_write(s.satp, data);
            case shadow_state_csr::scounteren:
                return success_write(s.scounteren, data);
            case shadow_state_csr::senvcfg:
                return success_write(s.senvcfg, data);
            case shadow_state_csr::ilrsc:
                return success_write(s.ilrsc, data);
            case shadow_state_csr::iflags:
                s.write_iflags(data);
                return;
            case shadow_state_csr::clint_mtimecmp:
                return success_write(s.clint.mtimecmp, data);
            case shadow_state_csr::htif_tohost:
                return success_write(s.htif.tohost, data);
            case shadow_state_csr::htif_fromhost:
                return success_write(s.htif.fromhost, data);
            case shadow_state_csr::brkflag:
                s.brkflag = data;
                return;
            default:
                break;
        }
        switch (static_cast<uarch_mmio>(paddr)) {
            case uarch_mmio::putchar:
                return uarch_putchar(data);
            case uarch_mmio::abort:
                return uarch_abort();
        }

        throw std::runtime_error("invalid write memory access from microarchitecture");
    }

    /// \brief Reads a machine state register.
    /// \param s Machine state.
    /// \param us Microarchitecture (uarch) state.
    /// \param paddr Address that identifies the machine register to be read.
    /// \param data Receives the state register value.
    /// \details \{
    /// An exception is thrown if paddr can't me mapped to a valid state register.
    //// \}
    static void read_register(uint64_t paddr, machine_state &s, uarch_state &us, uint64_t *data) {
        if (try_read_x(s, paddr, data)) {
            return;
        }
        if (try_read_f(s, paddr, data)) {
            return;
        }
        if (try_read_tlb(s, paddr, data)) {
            return;
        }
        if (try_read_pma(s, paddr, data)) {
            return;
        }
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::pc:
                return success_read(s.pc, data);
            case shadow_state_csr::fcsr:
                return success_read(s.fcsr, data);
            case shadow_state_csr::mvendorid:
                return success_read(MVENDORID_INIT, data);
            case shadow_state_csr::marchid:
                return success_read(MARCHID_INIT, data);
            case shadow_state_csr::mimpid:
                return success_read(MIMPID_INIT, data);
            case shadow_state_csr::mcycle:
                return success_read(s.mcycle, data);
            case shadow_state_csr::minstret:
                return success_read(s.minstret, data);
            case shadow_state_csr::mstatus:
                return success_read(s.mstatus, data);
            case shadow_state_csr::mtvec:
                return success_read(s.mtvec, data);
            case shadow_state_csr::mscratch:
                return success_read(s.mscratch, data);
            case shadow_state_csr::mepc:
                return success_read(s.mepc, data);
            case shadow_state_csr::mcause:
                return success_read(s.mcause, data);
            case shadow_state_csr::mtval:
                return success_read(s.mtval, data);
            case shadow_state_csr::misa:
                return success_read(s.misa, data);
            case shadow_state_csr::mie:
                return success_read(s.mie, data);
            case shadow_state_csr::mip:
                return success_read(s.mip, data);
            case shadow_state_csr::medeleg:
                return success_read(s.medeleg, data);
            case shadow_state_csr::mideleg:
                return success_read(s.mideleg, data);
            case shadow_state_csr::mcounteren:
                return success_read(s.mcounteren, data);
            case shadow_state_csr::menvcfg:
                return success_read(s.menvcfg, data);
            case shadow_state_csr::stvec:
                return success_read(s.stvec, data);
            case shadow_state_csr::sscratch:
                return success_read(s.sscratch, data);
            case shadow_state_csr::sepc:
                return success_read(s.sepc, data);
            case shadow_state_csr::scause:
                return success_read(s.scause, data);
            case shadow_state_csr::stval:
                return success_read(s.stval, data);
            case shadow_state_csr::satp:
                return success_read(s.satp, data);
            case shadow_state_csr::scounteren:
                return success_read(s.scounteren, data);
            case shadow_state_csr::senvcfg:
                return success_read(s.senvcfg, data);
            case shadow_state_csr::ilrsc:
                return success_read(s.ilrsc, data);
            case shadow_state_csr::iflags:
                *data = s.read_iflags();
                return;
            case shadow_state_csr::brkflag:
                *data = s.brkflag;
                return;
            case shadow_state_csr::clint_mtimecmp:
                return success_read(s.clint.mtimecmp, data);
            case shadow_state_csr::htif_tohost:
                return success_read(s.htif.tohost, data);
            case shadow_state_csr::htif_fromhost:
                return success_read(s.htif.fromhost, data);
            case shadow_state_csr::htif_ihalt:
                return success_read(s.htif.ihalt, data);
            case shadow_state_csr::htif_iconsole:
                return success_read(s.htif.iconsole, data);
            case shadow_state_csr::htif_iyield:
                return success_read(s.htif.iyield, data);
            case shadow_state_csr::uarch_rom_length:
                *data = us.rom.get_length();
                return;
            case shadow_state_csr::uarch_ram_length:
                *data = us.ram.get_length();
                return;
            default:
                break;
        }

        throw std::runtime_error("invalid read memory access from microarchitecture");
    }

    /// \brief Reads the name of a machine state register.
    /// \param paddr Address of the state register.
    /// \returns The register name, if paddr maps to a register, or nullptr otherwise.
    static const char *get_register_name(uint64_t paddr) {
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::pc:
                return "pc";
            case shadow_state_csr::fcsr:
                return "fcsr";
            case shadow_state_csr::mvendorid:
                return "mvendorid";
            case shadow_state_csr::marchid:
                return "marchid";
            case shadow_state_csr::mimpid:
                return "mimpid";
            case shadow_state_csr::mcycle:
                return "mcycle";
            case shadow_state_csr::minstret:
                return "minstret";
            case shadow_state_csr::mstatus:
                return "mstatus";
            case shadow_state_csr::mtvec:
                return "mtvec";
            case shadow_state_csr::mscratch:
                return "mscratch";
            case shadow_state_csr::mepc:
                return "mepc";
            case shadow_state_csr::mcause:
                return "mcause";
            case shadow_state_csr::mtval:
                return "mtval";
            case shadow_state_csr::misa:
                return "misa";
            case shadow_state_csr::mie:
                return "mie";
            case shadow_state_csr::mip:
                return "mip";
            case shadow_state_csr::medeleg:
                return "medeleg";
            case shadow_state_csr::mideleg:
                return "mideleg";
            case shadow_state_csr::mcounteren:
                return "mcounteren";
            case shadow_state_csr::menvcfg:
                return "menvcfg";
            case shadow_state_csr::stvec:
                return "stvec";
            case shadow_state_csr::sscratch:
                return "sscratch";
            case shadow_state_csr::sepc:
                return "sepc";
            case shadow_state_csr::scause:
                return "scause";
            case shadow_state_csr::stval:
                return "stval";
            case shadow_state_csr::satp:
                return "satp";
            case shadow_state_csr::scounteren:
                return "scounteren";
            case shadow_state_csr::senvcfg:
                return "senvcfg";
            case shadow_state_csr::ilrsc:
                return "ilrsc";
            case shadow_state_csr::iflags:
                return "iflags";
            case shadow_state_csr::brkflag:
                return "brkflag";
            case shadow_state_csr::clint_mtimecmp:
                return "clint.mtimecmp";
            case shadow_state_csr::htif_tohost:
                return "htif.tohost";
            case shadow_state_csr::htif_fromhost:
                return "htif.fromhost";
            case shadow_state_csr::htif_ihalt:
                return "htif.ihalt";
            case shadow_state_csr::htif_iconsole:
                return "htif.iconsole";
            case shadow_state_csr::htif_iyield:
                return "htif.iyield";
            case shadow_state_csr::uarch_rom_length:
                return "uarch.rom_length";
            case shadow_state_csr::uarch_ram_length:
                return "uarch.ram_length";
            default:
                break;
        }

        switch (static_cast<uarch_mmio>(paddr)) {
            case uarch_mmio::putchar:
                return "uarch.putchar";
            case uarch_mmio::abort:
                return "uarch.abort";
        }

        if (paddr >= shadow_state_get_x_abs_addr(0) && paddr <= shadow_state_get_x_abs_addr(X_REG_COUNT - 1) &&
            (paddr & 0b111) == 0) {
            return "x";
        }

        if (paddr >= shadow_state_get_f_abs_addr(0) && paddr <= shadow_state_get_f_abs_addr(F_REG_COUNT - 1) &&
            (paddr & 0b111) == 0) {
            return "f";
        }

        if (paddr >= PMA_SHADOW_PMAS_START && paddr < PMA_SHADOW_PMAS_START + (PMA_MAX * PMA_WORD_SIZE * 2)) {
            auto word_index = (paddr - PMA_SHADOW_PMAS_START) >> 3;
            if ((word_index & 1) == 0) {
                return "pma.istart";
            } else {
                return "pma.ilength";
            }
        }

        if (paddr >= PMA_SHADOW_TLB_START && paddr < PMA_SHADOW_TLB_START + PMA_SHADOW_TLB_LENGTH &&
            paddr % sizeof(uint64_t) == 0) {
            uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
            if (tlboff < offsetof(shadow_tlb_state, cold)) {
                return "cold_tlb_entry_field";
            } else if (tlboff < sizeof(shadow_tlb_state)) {
                return "hot_tlb_entry_field";
            }
        }

        return nullptr;
    }

private:
    /// \brief Tries to write a general-purpose machine register.
    /// \param s Machine state.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Data to write
    /// \return true if the register was successfully written.
    static bool try_write_x(machine_state &s, uint64_t paddr, uint64_t data) {
        if (paddr < shadow_state_get_x_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_x_abs_addr(X_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 0b111) {
            throw std::runtime_error("write register value not correctly aligned");
        }
        paddr -= shadow_state_get_x_abs_addr(0);
        s.x[paddr >> 3] = data;
        return true;
    }

    /// \brief Tries to read a general-purpose machine register.
    /// \param s Machine state.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Pointer to word receiving value.
    /// \return true if the register was successfully read
    static bool try_read_x(machine_state &s, uint64_t paddr, uint64_t *data) {
        if (paddr < shadow_state_get_x_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_x_abs_addr(X_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 0b111) {
            throw std::runtime_error("read register value not correctly aligned");
        }
        paddr -= shadow_state_get_x_abs_addr(0);
        *data = s.x[paddr >> 3];
        return true;
    }

    /// \brief Tries to read a PMA entry field.
    /// \param s Machine state.
    /// \param paddr Absolute address of the PMA entry field within shadow PMAs range
    /// \param data Pointer to word receiving value.
    /// \return true if the register was successfully read
    static bool try_read_pma(machine_state &s, uint64_t paddr, uint64_t *data) {
        if (paddr < PMA_SHADOW_PMAS_START || paddr >= PMA_SHADOW_PMAS_START + (PMA_MAX * PMA_WORD_SIZE * 2)) {
            return false;
        }
        auto word_index = (paddr - PMA_SHADOW_PMAS_START) >> 3;
        auto pma_index = word_index >> 1;
        if (pma_index >= s.pmas.size()) {
            *data = 0;
            return true;
        }
        auto &pma = s.pmas[pma_index];
        if ((word_index & 1) == 0) {
            *data = pma.get_istart();
        } else {
            *data = pma.get_ilength();
        }
        return true;
    }

    /// \brief Tries to write a floating-point machine register.
    /// \param s Machine state.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Data to write
    /// \return true if the register was successfully written.
    static bool try_write_f(machine_state &s, uint64_t paddr, uint64_t data) {
        if (paddr < shadow_state_get_f_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_f_abs_addr(F_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 0b111) {
            throw std::runtime_error("read floating-point register value not correctly aligned");
        }
        paddr -= shadow_state_get_f_abs_addr(0);
        s.f[paddr >> 3] = data;
        return true;
    }

    /// \brief Tries to read a floating-point machine register.
    /// \param s Machine state.
    /// \param paddr Absolute address of the register within shadow-state range
    /// \param data Pointer to word receiving value.
    /// \return true if the register was successfully read
    static bool try_read_f(machine_state &s, uint64_t paddr, uint64_t *data) {
        if (paddr < shadow_state_get_f_abs_addr(0)) {
            return false;
        }
        if (paddr > shadow_state_get_f_abs_addr(F_REG_COUNT - 1)) {
            return false;
        }
        if (paddr & 0b111) {
            throw std::runtime_error("read floating-point register value not correctly aligned");
        }
        paddr -= shadow_state_get_f_abs_addr(0);
        *data = s.f[paddr >> 3];
        return true;
    }

    /// \brief Tries to read a TLB entry field.
    /// \param s Machine state.
    /// \param paddr Absolute address of the TLB entry fieldwithin shadow TLB range
    /// \param data Pointer to word receiving value.
    /// \return true if the register was successfully read
    static bool try_read_tlb(machine_state &s, uint64_t paddr, uint64_t *data) {
        if (paddr < PMA_SHADOW_TLB_START ||
            paddr >= PMA_SHADOW_TLB_START + PMA_SHADOW_TLB_LENGTH) { // In PMA TLB range?
            return false;
        }
        if (paddr % sizeof(uint64_t) != 0) { // Misaligned field?
            return false;
        }
        uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
        if (tlboff < offsetof(shadow_tlb_state, cold)) { // Hot entry
            uint64_t etype = tlboff / sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = tlboff % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_hot_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_hot_entry);
            return read_tlb_entry_field(s, true, etype, eidx, fieldoff, data);
        } else if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
            uint64_t coldoff = tlboff - offsetof(shadow_tlb_state, cold);
            uint64_t etype = coldoff / sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = coldoff % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_cold_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_cold_entry);
            return read_tlb_entry_field(s, false, etype, eidx, fieldoff, data);
        }
        return false;
    }

    /// \brief Tries to update a PMA entry field.
    /// \param s Machine state.
    /// \param paddr Absolute address of the PMA entry property within shadow PMAs range
    /// \param data Data to write
    /// \return true if the register was successfully written
    static bool try_write_tlb(machine_state &s, uint64_t paddr, uint64_t data) {
        if (paddr < PMA_SHADOW_TLB_START ||
            paddr >= PMA_SHADOW_TLB_START + PMA_SHADOW_TLB_LENGTH) { // In PMA TLB range?
            return false;
        }
        if (paddr % sizeof(uint64_t) != 0) { // Misaligned field?
            return false;
        }
        uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
        if (tlboff < offsetof(shadow_tlb_state, cold)) { // Hot entry
            uint64_t etype = tlboff / sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = tlboff % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_hot_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_hot_entry);
            return write_tlb_entry_field(s, true, etype, eidx, fieldoff, data);
        } else if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
            uint64_t coldoff = tlboff - offsetof(shadow_tlb_state, cold);
            uint64_t etype = coldoff / sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = coldoff % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_cold_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_cold_entry);
            return write_tlb_entry_field(s, false, etype, eidx, fieldoff, data);
        }
        return false;
    }

    /// \brief Reads a field of a TLB entry.
    /// \param s Machine state.
    /// \param hot If true read from hot TLB entries, otherwise from cold TLB entries.
    /// \param etype TLB entry type.
    /// \param eidx TLB entry index.
    /// \param fieldoff TLB entry field offset.
    /// \param pval Pointer to word receiving value.
    /// \returns True if the field was read, false otherwise.
    static bool read_tlb_entry_field(machine_state &s, bool hot, uint64_t etype, uint64_t eidx, uint64_t fieldoff,
        uint64_t *pval) {
        if (etype > TLB_WRITE || eidx >= PMA_TLB_SIZE) {
            return false;
        }
        const tlb_hot_entry &tlbhe = s.tlb.hot[etype][eidx];
        const tlb_cold_entry &tlbce = s.tlb.cold[etype][eidx];
        if (hot) {
            switch (fieldoff) {
                case offsetof(tlb_hot_entry, vaddr_page):
                    *pval = tlbhe.vaddr_page;
                    return true;
                default:
                    // Other fields like vh_offset contains host data, and cannot be read
                    return false;
            }
        } else {
            switch (fieldoff) {
                case offsetof(tlb_cold_entry, paddr_page):
                    *pval = tlbce.paddr_page;
                    return true;
                case offsetof(tlb_cold_entry, pma_index):
                    *pval = tlbce.pma_index;
                    return true;
                default:
                    return false;
            }
        }
    }

    /// \brief Writes a field of a TLB entry.
    /// \param s Machine state.
    /// \param hot If true write to hot TLB entries, otherwise to cold TLB entries.
    /// \param etype TLB entry type.
    /// \param eidx TLB entry index.
    /// \param fieldoff TLB entry field offset.
    /// \param val Value to be written.
    /// \returns True if the field was written, false otherwise.
    static bool write_tlb_entry_field(machine_state &s, bool hot, uint64_t etype, uint64_t eidx, uint64_t fieldoff,
        uint64_t val) {
        if (etype > TLB_WRITE || eidx >= PMA_TLB_SIZE) {
            return false;
        }
        tlb_hot_entry &tlbhe = s.tlb.hot[etype][eidx];
        tlb_cold_entry &tlbce = s.tlb.cold[etype][eidx];
        if (hot) {
            switch (fieldoff) {
                case offsetof(tlb_hot_entry, vaddr_page):
                    tlbhe.vaddr_page = val;
                    return true;
                default:
                    // Other fields like vh_offset contains host data, and cannot be written
                    return false;
            }
        } else {
            switch (fieldoff) {
                case offsetof(tlb_cold_entry, paddr_page): {
                    tlbce.paddr_page = val;
                    // Update vh_offset
                    const pma_entry &pma = find_pma_entry<uint64_t>(s, tlbce.paddr_page);
                    assert(pma.get_istart_M()); // TLB only works for memory mapped PMAs
                    const unsigned char *hpage =
                        pma.get_memory().get_host_memory() + (tlbce.paddr_page - pma.get_start());
                    tlb_hot_entry &tlbhe = s.tlb.hot[etype][eidx];
                    tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - tlbhe.vaddr_page;
                    return true;
                }
                case offsetof(tlb_cold_entry, pma_index):
                    tlbce.pma_index = val;
                    return true;
                default:
                    return false;
            }
        }
    }

    /// \brief Obtain PMA entry that covers a given physical memory region
    /// \tparam T Type of word.
    /// \param s Mmachine state.
    /// \param paddr Start of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    template <typename T>
    static const pma_entry &find_pma_entry(machine_state &s, uint64_t paddr) {
        for (const auto &pma : s.pmas) {
            // Stop at first empty PMA
            if (pma.get_length() == 0) {
                return pma;
            }
            if (pma.contains(paddr, sizeof(T))) {
                return pma;
            }
        }
        // Last PMA is always the empty range
        return s.pmas.back();
    }

    /// \brief Write src to dst
    static inline void success_read(const uint64_t &src, uint64_t *dst) {
        *dst = src;
    }

    /// \brief Write src to dst
    static inline void success_write(uint64_t &dst, const uint64_t &src) {
        dst = src;
    }

    /// \brief Writes a character to the console
    static void uarch_putchar(uint64_t data) {
        putchar(static_cast<char>(data));
    }

    /// \brief Abort request received from uarch
    static void uarch_abort() {
        throw std::runtime_error("Microarchitecture execution aborted");
    }
};

} // namespace cartesi

#endif
