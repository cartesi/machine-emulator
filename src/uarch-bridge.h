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
    static void write_register(uint64_t paddr, machine_state &s, uarch_state &us, uint64_t data) {
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
            case shadow_state_csr::uarch_halt_flag:
                if (data != uarch_halt_flag_halt_value) {
                    throw std::runtime_error("invalid value written microarchitecture halt flag");
                }
                return uarch_halt(us);
            case shadow_state_csr::pc:
                s.pc = data;
                return;
            case shadow_state_csr::fcsr:
                s.fcsr = data;
                return;
            case shadow_state_csr::mcycle:
                s.mcycle = data;
                return;
            case shadow_state_csr::icycleinstret:
                s.icycleinstret = data;
                return;
            case shadow_state_csr::mstatus:
                s.mstatus = data;
                return;
            case shadow_state_csr::mtvec:
                s.mtvec = data;
                return;
            case shadow_state_csr::mscratch:
                s.mscratch = data;
                return;
            case shadow_state_csr::mepc:
                s.mepc = data;
                return;
            case shadow_state_csr::mcause:
                s.mcause = data;
                return;
            case shadow_state_csr::mtval:
                s.mtval = data;
                return;
            case shadow_state_csr::misa:
                s.misa = data;
                return;
            case shadow_state_csr::mie:
                s.mie = data;
                return;
            case shadow_state_csr::mip:
                s.mip = data;
                return;
            case shadow_state_csr::medeleg:
                s.medeleg = data;
                return;
            case shadow_state_csr::mideleg:
                s.mideleg = data;
                return;
            case shadow_state_csr::mcounteren:
                s.mcounteren = data;
                return;
            case shadow_state_csr::menvcfg:
                s.menvcfg = data;
                return;
            case shadow_state_csr::stvec:
                s.stvec = data;
                return;
            case shadow_state_csr::sscratch:
                s.sscratch = data;
                return;
            case shadow_state_csr::sepc:
                s.sepc = data;
                return;
            case shadow_state_csr::scause:
                s.scause = data;
                return;
            case shadow_state_csr::stval:
                s.stval = data;
                return;
            case shadow_state_csr::satp:
                s.satp = data;
                return;
            case shadow_state_csr::scounteren:
                s.scounteren = data;
                return;
            case shadow_state_csr::senvcfg:
                s.senvcfg = data;
                return;
            case shadow_state_csr::hstatus:
                s.hstatus = data;
                return;
            case shadow_state_csr::hideleg:
                s.hideleg = data;
                return;
            case shadow_state_csr::hedeleg:
                s.hedeleg = data;
                return;
            case shadow_state_csr::hie:
                s.hie = data;
                return;
            case shadow_state_csr::hip:
                s.hip = data;
                return;
            case shadow_state_csr::hvip:
                s.hvip = data;
                return;
            case shadow_state_csr::hgatp:
                s.hgatp = data;
                return;
            case shadow_state_csr::henvcfg:
                s.henvcfg = data;
                return;
            case shadow_state_csr::htimedelta:
                s.htimedelta = data;
                return;
            case shadow_state_csr::htval:
                s.htval = data;
                return;
            case shadow_state_csr::vsepc:
                s.vsepc = data;
                return;
            case shadow_state_csr::vsstatus:
                s.vsstatus = data;
                return;
            case shadow_state_csr::vscause:
                s.vscause = data;
                return;
            case shadow_state_csr::vstval:
                s.vstval = data;
                return;
            case shadow_state_csr::vstvec:
                s.vstvec = data;
                return;
            case shadow_state_csr::vsscratch:
                s.vsscratch = data;
                return;
            case shadow_state_csr::vsatp:
                s.vsatp = data;
                return;
            case shadow_state_csr::vsie:
                s.vsie = data;
                return;
            case shadow_state_csr::vsip:
                s.vsip = data;
                return;
            case shadow_state_csr::ilrsc:
                s.ilrsc = data;
                return;
            case shadow_state_csr::iflags:
                s.write_iflags(data);
                return;
            case shadow_state_csr::clint_mtimecmp:
                s.clint.mtimecmp = data;
                return;
            case shadow_state_csr::htif_tohost:
                s.htif.tohost = data;
                return;
            case shadow_state_csr::htif_fromhost:
                s.htif.fromhost = data;
                return;
            default:
                break;
        }
        switch (static_cast<uarch_mmio_address>(paddr)) {
            case uarch_mmio_address::putchar:
                return uarch_putchar(data);
            case uarch_mmio_address::abort:
                if (data != uarch_mmio_abort_value) {
                    throw std::runtime_error("invalid write attempt to microarchitecture abort address");
                }
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
    static uint64_t read_register(uint64_t paddr, machine_state &s, uarch_state &us) {
        uint64_t data = 0;
        if (try_read_x(s, paddr, &data)) {
            return data;
        }
        if (try_read_f(s, paddr, &data)) {
            return data;
        }
        if (try_read_tlb(s, paddr, &data)) {
            return data;
        }
        if (try_read_pma(s, paddr, &data)) {
            return data;
        }
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::uarch_halt_flag:
                return us.halt_flag;
            case shadow_state_csr::pc:
                return s.pc;
            case shadow_state_csr::fcsr:
                return s.fcsr;
            case shadow_state_csr::mvendorid:
                return MVENDORID_INIT;
            case shadow_state_csr::marchid:
                return MARCHID_INIT;
            case shadow_state_csr::mimpid:
                return MIMPID_INIT;
            case shadow_state_csr::mcycle:
                return s.mcycle;
            case shadow_state_csr::icycleinstret:
                return s.icycleinstret;
            case shadow_state_csr::mstatus:
                return s.mstatus;
            case shadow_state_csr::mtvec:
                return s.mtvec;
            case shadow_state_csr::mscratch:
                return s.mscratch;
            case shadow_state_csr::mepc:
                return s.mepc;
            case shadow_state_csr::mcause:
                return s.mcause;
            case shadow_state_csr::mtval:
                return s.mtval;
            case shadow_state_csr::misa:
                return s.misa;
            case shadow_state_csr::mie:
                return s.mie;
            case shadow_state_csr::mip:
                return s.mip;
            case shadow_state_csr::medeleg:
                return s.medeleg;
            case shadow_state_csr::mideleg:
                return s.mideleg;
            case shadow_state_csr::mcounteren:
                return s.mcounteren;
            case shadow_state_csr::menvcfg:
                return s.menvcfg;
            case shadow_state_csr::stvec:
                return s.stvec;
            case shadow_state_csr::sscratch:
                return s.sscratch;
            case shadow_state_csr::sepc:
                return s.sepc;
            case shadow_state_csr::scause:
                return s.scause;
            case shadow_state_csr::stval:
                return s.stval;
            case shadow_state_csr::satp:
                return s.satp;
            case shadow_state_csr::scounteren:
                return s.scounteren;
            case shadow_state_csr::senvcfg:
                return s.senvcfg;
            case shadow_state_csr::hstatus:
                return s.hstatus;
            case shadow_state_csr::hideleg:
                return s.hideleg;
            case shadow_state_csr::hedeleg:
                return s.hedeleg;
            case shadow_state_csr::hie:
                return s.hie;
            case shadow_state_csr::hip:
                return s.hip;
            case shadow_state_csr::hvip:
                return s.hvip;
            case shadow_state_csr::hgatp:
                return s.hgatp;
            case shadow_state_csr::henvcfg:
                return s.henvcfg;
            case shadow_state_csr::htimedelta:
                return s.htimedelta;
            case shadow_state_csr::htval:
                return s.htval;
            case shadow_state_csr::vsepc:
                return s.vsepc;
            case shadow_state_csr::vsstatus:
                return s.vsstatus;
            case shadow_state_csr::vscause:
                return s.vscause;
            case shadow_state_csr::vstval:
                return s.vstval;
            case shadow_state_csr::vstvec:
                return s.vstvec;
            case shadow_state_csr::vsscratch:
                return s.vsscratch;
            case shadow_state_csr::vsatp:
                return s.vsatp;
            case shadow_state_csr::vsie:
                return s.vsie;
            case shadow_state_csr::vsip:
                return s.vsip;
            case shadow_state_csr::ilrsc:
                return s.ilrsc;
            case shadow_state_csr::iflags:
                return s.read_iflags();
            case shadow_state_csr::clint_mtimecmp:
                return s.clint.mtimecmp;
            case shadow_state_csr::htif_tohost:
                return s.htif.tohost;
            case shadow_state_csr::htif_fromhost:
                return s.htif.fromhost;
            case shadow_state_csr::htif_ihalt:
                return s.htif.ihalt;
            case shadow_state_csr::htif_iconsole:
                return s.htif.iconsole;
            case shadow_state_csr::htif_iyield:
                return s.htif.iyield;
            case shadow_state_csr::uarch_ram_length:
                return us.ram.get_length();
            default:
                break;
        }

        switch (static_cast<uarch_mmio_address>(paddr)) {
            case uarch_mmio_address::putchar:
                return 0;
            case uarch_mmio_address::abort:
                return 0;
        }
        throw std::runtime_error("invalid read memory access from microarchitecture");
    }

    /// \brief Reads the name of a machine state register.
    /// \param paddr Address of the state register.
    /// \returns The register name, if paddr maps to a register, or nullptr otherwise.
    static const char *get_register_name(uint64_t paddr) {
        switch (static_cast<shadow_state_csr>(paddr)) {
            case shadow_state_csr::uarch_halt_flag:
                return "uarch.halt_flag";
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
            case shadow_state_csr::icycleinstret:
                return "icycleinstret";
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
            case shadow_state_csr::hstatus:
                return "hstatus";
            case shadow_state_csr::hideleg:
                return "hideleg";
            case shadow_state_csr::hedeleg:
                return "hedeleg";
            case shadow_state_csr::hie:
                return "hie";
            case shadow_state_csr::hip:
                return "hip";
            case shadow_state_csr::hvip:
                return "hvip";
            case shadow_state_csr::hgatp:
                return "hgatp";
            case shadow_state_csr::henvcfg:
                return "henvcfg";
            case shadow_state_csr::htimedelta:
                return "htimedelta";
            case shadow_state_csr::htval:
                return "htval";
            case shadow_state_csr::vsepc:
                return "vsepc";
            case shadow_state_csr::vsstatus:
                return "vsstatus";
            case shadow_state_csr::vscause:
                return "vscause";
            case shadow_state_csr::vstval:
                return "vstval";
            case shadow_state_csr::vstvec:
                return "vstvec";
            case shadow_state_csr::vsscratch:
                return "vsscratch";
            case shadow_state_csr::vsatp:
                return "vsatp";
            case shadow_state_csr::vsie:
                return "vsie";
            case shadow_state_csr::vsip:
                return "vsip";
            case shadow_state_csr::ilrsc:
                return "ilrsc";
            case shadow_state_csr::iflags:
                return "iflags";
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
            case shadow_state_csr::uarch_ram_length:
                return "uarch.ram_length";
            default:
                break;
        }

        switch (static_cast<uarch_mmio_address>(paddr)) {
            case uarch_mmio_address::putchar:
                return "uarch.putchar";
            case uarch_mmio_address::abort:
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
            const uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
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
        const uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
        if (tlboff < offsetof(shadow_tlb_state, cold)) { // Hot entry
            const uint64_t etype = tlboff / sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            const uint64_t etypeoff = tlboff % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            const uint64_t eidx = etypeoff / sizeof(tlb_hot_entry);
            const uint64_t fieldoff = etypeoff % sizeof(tlb_hot_entry);
            return read_tlb_entry_field(s, true, etype, eidx, fieldoff, data);
        } else if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
            const uint64_t coldoff = tlboff - offsetof(shadow_tlb_state, cold);
            const uint64_t etype = coldoff / sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            const uint64_t etypeoff = coldoff % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            const uint64_t eidx = etypeoff / sizeof(tlb_cold_entry);
            const uint64_t fieldoff = etypeoff % sizeof(tlb_cold_entry);
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
        const uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
        if (tlboff < offsetof(shadow_tlb_state, cold)) { // Hot entry
            const uint64_t etype = tlboff / sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            const uint64_t etypeoff = tlboff % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            const uint64_t eidx = etypeoff / sizeof(tlb_hot_entry);
            const uint64_t fieldoff = etypeoff % sizeof(tlb_hot_entry);
            return write_tlb_entry_field(s, true, etype, eidx, fieldoff, data);
        } else if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
            const uint64_t coldoff = tlboff - offsetof(shadow_tlb_state, cold);
            const uint64_t etype = coldoff / sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            const uint64_t etypeoff = coldoff % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            const uint64_t eidx = etypeoff / sizeof(tlb_cold_entry);
            const uint64_t fieldoff = etypeoff % sizeof(tlb_cold_entry);
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

    /// \brief Writes a character to the console
    static void uarch_putchar(uint64_t data) {
        putchar(static_cast<char>(data));
    }

    /// \brief Halt  request received from uarch
    static void uarch_halt(uarch_state &us) {
        us.halt_flag = true;
    }

    /// \brief Abort request received from uarch
    static void uarch_abort() {
        throw std::runtime_error("microarchitecture execution aborted");
    }
};

} // namespace cartesi

#endif
