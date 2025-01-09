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

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "machine-reg.h"
#include "machine-state.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "shadow-pmas.h"
#include "shadow-state.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"

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
        using reg = machine_reg;
        switch (static_cast<reg>(paddr)) {
            case reg::x0:
                s.x[0] = data;
                return;
            case reg::x1:
                s.x[1] = data;
                return;
            case reg::x2:
                s.x[2] = data;
                return;
            case reg::x3:
                s.x[3] = data;
                return;
            case reg::x4:
                s.x[4] = data;
                return;
            case reg::x5:
                s.x[5] = data;
                return;
            case reg::x6:
                s.x[6] = data;
                return;
            case reg::x7:
                s.x[7] = data;
                return;
            case reg::x8:
                s.x[8] = data;
                return;
            case reg::x9:
                s.x[9] = data;
                return;
            case reg::x10:
                s.x[10] = data;
                return;
            case reg::x11:
                s.x[11] = data;
                return;
            case reg::x12:
                s.x[12] = data;
                return;
            case reg::x13:
                s.x[13] = data;
                return;
            case reg::x14:
                s.x[14] = data;
                return;
            case reg::x15:
                s.x[15] = data;
                return;
            case reg::x16:
                s.x[16] = data;
                return;
            case reg::x17:
                s.x[17] = data;
                return;
            case reg::x18:
                s.x[18] = data;
                return;
            case reg::x19:
                s.x[19] = data;
                return;
            case reg::x20:
                s.x[20] = data;
                return;
            case reg::x21:
                s.x[21] = data;
                return;
            case reg::x22:
                s.x[22] = data;
                return;
            case reg::x23:
                s.x[23] = data;
                return;
            case reg::x24:
                s.x[24] = data;
                return;
            case reg::x25:
                s.x[25] = data;
                return;
            case reg::x26:
                s.x[26] = data;
                return;
            case reg::x27:
                s.x[27] = data;
                return;
            case reg::x28:
                s.x[28] = data;
                return;
            case reg::x29:
                s.x[29] = data;
                return;
            case reg::x30:
                s.x[30] = data;
                return;
            case reg::x31:
                s.x[31] = data;
                return;
            case reg::f0:
                s.f[0] = data;
                return;
            case reg::f1:
                s.f[1] = data;
                return;
            case reg::f2:
                s.f[2] = data;
                return;
            case reg::f3:
                s.f[3] = data;
                return;
            case reg::f4:
                s.f[4] = data;
                return;
            case reg::f5:
                s.f[5] = data;
                return;
            case reg::f6:
                s.f[6] = data;
                return;
            case reg::f7:
                s.f[7] = data;
                return;
            case reg::f8:
                s.f[8] = data;
                return;
            case reg::f9:
                s.f[9] = data;
                return;
            case reg::f10:
                s.f[10] = data;
                return;
            case reg::f11:
                s.f[11] = data;
                return;
            case reg::f12:
                s.f[12] = data;
                return;
            case reg::f13:
                s.f[13] = data;
                return;
            case reg::f14:
                s.f[14] = data;
                return;
            case reg::f15:
                s.f[15] = data;
                return;
            case reg::f16:
                s.f[16] = data;
                return;
            case reg::f17:
                s.f[17] = data;
                return;
            case reg::f18:
                s.f[18] = data;
                return;
            case reg::f19:
                s.f[19] = data;
                return;
            case reg::f20:
                s.f[20] = data;
                return;
            case reg::f21:
                s.f[21] = data;
                return;
            case reg::f22:
                s.f[22] = data;
                return;
            case reg::f23:
                s.f[23] = data;
                return;
            case reg::f24:
                s.f[24] = data;
                return;
            case reg::f25:
                s.f[25] = data;
                return;
            case reg::f26:
                s.f[26] = data;
                return;
            case reg::f27:
                s.f[27] = data;
                return;
            case reg::f28:
                s.f[28] = data;
                return;
            case reg::f29:
                s.f[29] = data;
                return;
            case reg::f30:
                s.f[30] = data;
                return;
            case reg::f31:
                s.f[31] = data;
                return;
            case reg::pc:
                s.pc = data;
                return;
            case reg::fcsr:
                s.fcsr = data;
                return;
            case reg::mcycle:
                s.mcycle = data;
                return;
            case reg::icycleinstret:
                s.icycleinstret = data;
                return;
            case reg::mstatus:
                s.mstatus = data;
                return;
            case reg::mtvec:
                s.mtvec = data;
                return;
            case reg::mscratch:
                s.mscratch = data;
                return;
            case reg::mepc:
                s.mepc = data;
                return;
            case reg::mcause:
                s.mcause = data;
                return;
            case reg::mtval:
                s.mtval = data;
                return;
            case reg::misa:
                s.misa = data;
                return;
            case reg::mie:
                s.mie = data;
                return;
            case reg::mip:
                s.mip = data;
                return;
            case reg::medeleg:
                s.medeleg = data;
                return;
            case reg::mideleg:
                s.mideleg = data;
                return;
            case reg::mcounteren:
                s.mcounteren = data;
                return;
            case reg::menvcfg:
                s.menvcfg = data;
                return;
            case reg::stvec:
                s.stvec = data;
                return;
            case reg::sscratch:
                s.sscratch = data;
                return;
            case reg::sepc:
                s.sepc = data;
                return;
            case reg::scause:
                s.scause = data;
                return;
            case reg::stval:
                s.stval = data;
                return;
            case reg::satp:
                s.satp = data;
                return;
            case reg::scounteren:
                s.scounteren = data;
                return;
            case reg::senvcfg:
                s.senvcfg = data;
                return;
            case reg::ilrsc:
                s.ilrsc = data;
                return;
            case reg::iprv:
                s.iprv = data;
                return;
            case reg::iflags_X:
                s.iflags.X = data;
                return;
            case reg::iflags_Y:
                s.iflags.Y = data;
                return;
            case reg::iflags_H:
                s.iflags.H = data;
                return;
            case reg::clint_mtimecmp:
                s.clint.mtimecmp = data;
                return;
            case reg::plic_girqpend:
                s.plic.girqpend = data;
                return;
            case reg::plic_girqsrvd:
                s.plic.girqsrvd = data;
                return;
            case reg::htif_tohost:
                s.htif.tohost = data;
                return;
            case reg::htif_fromhost:
                s.htif.fromhost = data;
                return;
            default:
                break;
        }
        if (try_write_tlb(s, paddr, data)) {
            return;
        }
        throw std::runtime_error("invalid write memory access from microarchitecture");
    }

    /// \brief Reads a machine state register.
    /// \param s Machine state.
    /// \param paddr Address that identifies the machine register to be read.
    /// \param data Receives the state register value.
    /// \details \{
    /// An exception is thrown if paddr can't me mapped to a valid state register.
    //// \}
    static uint64_t read_register(uint64_t paddr, machine_state &s) {
        using reg = machine_reg;
        switch (static_cast<reg>(paddr)) {
            case reg::x0:
                return s.x[0];
            case reg::x1:
                return s.x[1];
            case reg::x2:
                return s.x[2];
            case reg::x3:
                return s.x[3];
            case reg::x4:
                return s.x[4];
            case reg::x5:
                return s.x[5];
            case reg::x6:
                return s.x[6];
            case reg::x7:
                return s.x[7];
            case reg::x8:
                return s.x[8];
            case reg::x9:
                return s.x[9];
            case reg::x10:
                return s.x[10];
            case reg::x11:
                return s.x[11];
            case reg::x12:
                return s.x[12];
            case reg::x13:
                return s.x[13];
            case reg::x14:
                return s.x[14];
            case reg::x15:
                return s.x[15];
            case reg::x16:
                return s.x[16];
            case reg::x17:
                return s.x[17];
            case reg::x18:
                return s.x[18];
            case reg::x19:
                return s.x[19];
            case reg::x20:
                return s.x[20];
            case reg::x21:
                return s.x[21];
            case reg::x22:
                return s.x[22];
            case reg::x23:
                return s.x[23];
            case reg::x24:
                return s.x[24];
            case reg::x25:
                return s.x[25];
            case reg::x26:
                return s.x[26];
            case reg::x27:
                return s.x[27];
            case reg::x28:
                return s.x[28];
            case reg::x29:
                return s.x[29];
            case reg::x30:
                return s.x[30];
            case reg::x31:
                return s.x[31];
            case reg::f0:
                return s.f[0];
            case reg::f1:
                return s.f[1];
            case reg::f2:
                return s.f[2];
            case reg::f3:
                return s.f[3];
            case reg::f4:
                return s.f[4];
            case reg::f5:
                return s.f[5];
            case reg::f6:
                return s.f[6];
            case reg::f7:
                return s.f[7];
            case reg::f8:
                return s.f[8];
            case reg::f9:
                return s.f[9];
            case reg::f10:
                return s.f[10];
            case reg::f11:
                return s.f[11];
            case reg::f12:
                return s.f[12];
            case reg::f13:
                return s.f[13];
            case reg::f14:
                return s.f[14];
            case reg::f15:
                return s.f[15];
            case reg::f16:
                return s.f[16];
            case reg::f17:
                return s.f[17];
            case reg::f18:
                return s.f[18];
            case reg::f19:
                return s.f[19];
            case reg::f20:
                return s.f[20];
            case reg::f21:
                return s.f[21];
            case reg::f22:
                return s.f[22];
            case reg::f23:
                return s.f[23];
            case reg::f24:
                return s.f[24];
            case reg::f25:
                return s.f[25];
            case reg::f26:
                return s.f[26];
            case reg::f27:
                return s.f[27];
            case reg::f28:
                return s.f[28];
            case reg::f29:
                return s.f[29];
            case reg::f30:
                return s.f[30];
            case reg::f31:
                return s.f[31];
            case reg::pc:
                return s.pc;
            case reg::fcsr:
                return s.fcsr;
            case reg::mvendorid:
                return MVENDORID_INIT;
            case reg::marchid:
                return MARCHID_INIT;
            case reg::mimpid:
                return MIMPID_INIT;
            case reg::mcycle:
                return s.mcycle;
            case reg::icycleinstret:
                return s.icycleinstret;
            case reg::mstatus:
                return s.mstatus;
            case reg::mtvec:
                return s.mtvec;
            case reg::mscratch:
                return s.mscratch;
            case reg::mepc:
                return s.mepc;
            case reg::mcause:
                return s.mcause;
            case reg::mtval:
                return s.mtval;
            case reg::misa:
                return s.misa;
            case reg::mie:
                return s.mie;
            case reg::mip:
                return s.mip;
            case reg::medeleg:
                return s.medeleg;
            case reg::mideleg:
                return s.mideleg;
            case reg::mcounteren:
                return s.mcounteren;
            case reg::menvcfg:
                return s.menvcfg;
            case reg::stvec:
                return s.stvec;
            case reg::sscratch:
                return s.sscratch;
            case reg::sepc:
                return s.sepc;
            case reg::scause:
                return s.scause;
            case reg::stval:
                return s.stval;
            case reg::satp:
                return s.satp;
            case reg::scounteren:
                return s.scounteren;
            case reg::senvcfg:
                return s.senvcfg;
            case reg::ilrsc:
                return s.ilrsc;
            case reg::iprv:
                return s.iprv;
            case reg::iflags_X:
                return s.iflags.X;
            case reg::iflags_Y:
                return s.iflags.Y;
            case reg::iflags_H:
                return s.iflags.H;
            case reg::clint_mtimecmp:
                return s.clint.mtimecmp;
            case reg::plic_girqpend:
                return s.plic.girqpend;
            case reg::plic_girqsrvd:
                return s.plic.girqsrvd;
            case reg::htif_tohost:
                return s.htif.tohost;
            case reg::htif_fromhost:
                return s.htif.fromhost;
            case reg::htif_ihalt:
                return s.htif.ihalt;
            case reg::htif_iconsole:
                return s.htif.iconsole;
            case reg::htif_iyield:
                return s.htif.iyield;
            default:
                break;
        }
        uint64_t data = 0;
        if (try_read_tlb(s, paddr, &data)) {
            return data;
        }
        if (try_read_pma(s, paddr, &data)) {
            return data;
        }
        throw std::runtime_error("invalid read memory access from microarchitecture");
    }

    /// \brief Reads the name of a machine state register.
    /// \param paddr Address of the state register.
    /// \returns The register name, if paddr maps to a register, or nullptr otherwise.
    static const char *get_register_name(uint64_t paddr) {
        using reg = machine_reg;
        switch (static_cast<reg>(paddr)) {
            case reg::x0:
                return "x0";
            case reg::x1:
                return "x1";
            case reg::x2:
                return "x2";
            case reg::x3:
                return "x3";
            case reg::x4:
                return "x4";
            case reg::x5:
                return "x5";
            case reg::x6:
                return "x6";
            case reg::x7:
                return "x7";
            case reg::x8:
                return "x8";
            case reg::x9:
                return "x9";
            case reg::x10:
                return "x10";
            case reg::x11:
                return "x11";
            case reg::x12:
                return "x12";
            case reg::x13:
                return "x13";
            case reg::x14:
                return "x14";
            case reg::x15:
                return "x15";
            case reg::x16:
                return "x16";
            case reg::x17:
                return "x17";
            case reg::x18:
                return "x18";
            case reg::x19:
                return "x19";
            case reg::x20:
                return "x20";
            case reg::x21:
                return "x21";
            case reg::x22:
                return "x22";
            case reg::x23:
                return "x23";
            case reg::x24:
                return "x24";
            case reg::x25:
                return "x25";
            case reg::x26:
                return "x26";
            case reg::x27:
                return "x27";
            case reg::x28:
                return "x28";
            case reg::x29:
                return "x29";
            case reg::x30:
                return "x30";
            case reg::x31:
                return "x31";
            case reg::f0:
                return "f0";
            case reg::f1:
                return "f1";
            case reg::f2:
                return "f2";
            case reg::f3:
                return "f3";
            case reg::f4:
                return "f4";
            case reg::f5:
                return "f5";
            case reg::f6:
                return "f6";
            case reg::f7:
                return "f7";
            case reg::f8:
                return "f8";
            case reg::f9:
                return "f9";
            case reg::f10:
                return "f10";
            case reg::f11:
                return "f11";
            case reg::f12:
                return "f12";
            case reg::f13:
                return "f13";
            case reg::f14:
                return "f14";
            case reg::f15:
                return "f15";
            case reg::f16:
                return "f16";
            case reg::f17:
                return "f17";
            case reg::f18:
                return "f18";
            case reg::f19:
                return "f19";
            case reg::f20:
                return "f20";
            case reg::f21:
                return "f21";
            case reg::f22:
                return "f22";
            case reg::f23:
                return "f23";
            case reg::f24:
                return "f24";
            case reg::f25:
                return "f25";
            case reg::f26:
                return "f26";
            case reg::f27:
                return "f27";
            case reg::f28:
                return "f28";
            case reg::f29:
                return "f29";
            case reg::f30:
                return "f30";
            case reg::f31:
                return "f31";
            case reg::pc:
                return "pc";
            case reg::fcsr:
                return "fcsr";
            case reg::mvendorid:
                return "mvendorid";
            case reg::marchid:
                return "marchid";
            case reg::mimpid:
                return "mimpid";
            case reg::mcycle:
                return "mcycle";
            case reg::icycleinstret:
                return "icycleinstret";
            case reg::mstatus:
                return "mstatus";
            case reg::mtvec:
                return "mtvec";
            case reg::mscratch:
                return "mscratch";
            case reg::mepc:
                return "mepc";
            case reg::mcause:
                return "mcause";
            case reg::mtval:
                return "mtval";
            case reg::misa:
                return "misa";
            case reg::mie:
                return "mie";
            case reg::mip:
                return "mip";
            case reg::medeleg:
                return "medeleg";
            case reg::mideleg:
                return "mideleg";
            case reg::mcounteren:
                return "mcounteren";
            case reg::menvcfg:
                return "menvcfg";
            case reg::stvec:
                return "stvec";
            case reg::sscratch:
                return "sscratch";
            case reg::sepc:
                return "sepc";
            case reg::scause:
                return "scause";
            case reg::stval:
                return "stval";
            case reg::satp:
                return "satp";
            case reg::scounteren:
                return "scounteren";
            case reg::senvcfg:
                return "senvcfg";
            case reg::ilrsc:
                return "ilrsc";
            case reg::iprv:
                return "iprv";
            case reg::iflags_X:
                return "iflags.X";
            case reg::iflags_Y:
                return "iflags.Y";
            case reg::iflags_H:
                return "iflags.H";
            case reg::clint_mtimecmp:
                return "clint.mtimecmp";
            case reg::plic_girqpend:
                return "plic.girqpend";
            case reg::plic_girqsrvd:
                return "plic.girqsrvd";
            case reg::htif_tohost:
                return "htif.tohost";
            case reg::htif_fromhost:
                return "htif.fromhost";
            case reg::htif_ihalt:
                return "htif.ihalt";
            case reg::htif_iconsole:
                return "htif.iconsole";
            case reg::htif_iyield:
                return "htif.iyield";
            default:
                break;
        }
        if (paddr >= machine_reg_address(machine_reg::x0) && paddr <= machine_reg_address(machine_reg::x31) &&
            (paddr & 0b111) == 0) {
            return "x";
        }

        if (paddr >= machine_reg_address(machine_reg::f0) && paddr <= machine_reg_address(machine_reg::f31) &&
            (paddr & 0b111) == 0) {
            return "f";
        }

        if (paddr >= shadow_pmas_get_pma_abs_addr(0) && paddr < shadow_pmas_get_pma_abs_addr(PMA_MAX)) {
            if ((paddr & 0b1111) == 0) {
                return "pma.istart";
            }
            if ((paddr & 0b1111) == 0b1000) {
                return "pma.ilength";
            }
        }

        if (paddr % sizeof(uint64_t) == 0) {
            if (paddr >= shadow_tlb_get_slot_abs_addr<TLB_WRITE>(0) &&
                paddr < shadow_tlb_get_slot_abs_addr<TLB_WRITE>(TLB_SET_SIZE)) {
                return "write tlb";
            }
            if (paddr >= shadow_tlb_get_slot_abs_addr<TLB_READ>(0) &&
                paddr < shadow_tlb_get_slot_abs_addr<TLB_READ>(TLB_SET_SIZE)) {
                return "read tlb";
            }
            if (paddr >= shadow_tlb_get_slot_abs_addr<TLB_READ>(0) &&
                paddr < shadow_tlb_get_slot_abs_addr<TLB_READ>(TLB_SET_SIZE)) {
                return "code tlb";
            }
        }

        return nullptr;
    }

private:
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
        }
        if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
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
        }
        if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
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
            if (fieldoff == offsetof(tlb_hot_entry, vaddr_page)) {
                *pval = tlbhe.vaddr_page;
                return true;
            }
            // Other fields like vh_offset contains host data, and cannot be read
            return false;
        }
        // Cold
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
            if (fieldoff == offsetof(tlb_hot_entry, vaddr_page)) {
                tlbhe.vaddr_page = val;
                // Update vh_offset
                if (val != TLB_INVALID_PAGE) {
                    const pma_entry &pma = find_pma_entry<uint64_t>(s, tlbce.paddr_page);
                    assert(pma.get_istart_M()); // TLB only works for memory mapped PMAs
                    const unsigned char *hpage =
                        pma.get_memory().get_host_memory() + (tlbce.paddr_page - pma.get_start());
                    tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - tlbhe.vaddr_page;
                }
                return true;
            }
            // Other fields like vh_offset contains host data, and cannot be written
            return false;
        }
        // Cold
        switch (fieldoff) {
            case offsetof(tlb_cold_entry, paddr_page):
                tlbce.paddr_page = val;
                return true;
            case offsetof(tlb_cold_entry, pma_index):
                tlbce.pma_index = val;
                return true;
            default:
                return false;
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
};

} // namespace cartesi

#endif
