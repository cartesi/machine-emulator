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

#include "machine-state.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "shadow-uarch-state.h"
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
        switch (static_cast<shadow_state_reg>(paddr)) {
            case shadow_state_reg::x0:
                s.x[0] = data;
                return;
            case shadow_state_reg::x1:
                s.x[1] = data;
                return;
            case shadow_state_reg::x2:
                s.x[2] = data;
                return;
            case shadow_state_reg::x3:
                s.x[3] = data;
                return;
            case shadow_state_reg::x4:
                s.x[4] = data;
                return;
            case shadow_state_reg::x5:
                s.x[5] = data;
                return;
            case shadow_state_reg::x6:
                s.x[6] = data;
                return;
            case shadow_state_reg::x7:
                s.x[7] = data;
                return;
            case shadow_state_reg::x8:
                s.x[8] = data;
                return;
            case shadow_state_reg::x9:
                s.x[9] = data;
                return;
            case shadow_state_reg::x10:
                s.x[10] = data;
                return;
            case shadow_state_reg::x11:
                s.x[11] = data;
                return;
            case shadow_state_reg::x12:
                s.x[12] = data;
                return;
            case shadow_state_reg::x13:
                s.x[13] = data;
                return;
            case shadow_state_reg::x14:
                s.x[14] = data;
                return;
            case shadow_state_reg::x15:
                s.x[15] = data;
                return;
            case shadow_state_reg::x16:
                s.x[16] = data;
                return;
            case shadow_state_reg::x17:
                s.x[17] = data;
                return;
            case shadow_state_reg::x18:
                s.x[18] = data;
                return;
            case shadow_state_reg::x19:
                s.x[19] = data;
                return;
            case shadow_state_reg::x20:
                s.x[20] = data;
                return;
            case shadow_state_reg::x21:
                s.x[21] = data;
                return;
            case shadow_state_reg::x22:
                s.x[22] = data;
                return;
            case shadow_state_reg::x23:
                s.x[23] = data;
                return;
            case shadow_state_reg::x24:
                s.x[24] = data;
                return;
            case shadow_state_reg::x25:
                s.x[25] = data;
                return;
            case shadow_state_reg::x26:
                s.x[26] = data;
                return;
            case shadow_state_reg::x27:
                s.x[27] = data;
                return;
            case shadow_state_reg::x28:
                s.x[28] = data;
                return;
            case shadow_state_reg::x29:
                s.x[29] = data;
                return;
            case shadow_state_reg::x30:
                s.x[30] = data;
                return;
            case shadow_state_reg::x31:
                s.x[31] = data;
                return;
            case shadow_state_reg::f0:
                s.f[0] = data;
                return;
            case shadow_state_reg::f1:
                s.f[1] = data;
                return;
            case shadow_state_reg::f2:
                s.f[2] = data;
                return;
            case shadow_state_reg::f3:
                s.f[3] = data;
                return;
            case shadow_state_reg::f4:
                s.f[4] = data;
                return;
            case shadow_state_reg::f5:
                s.f[5] = data;
                return;
            case shadow_state_reg::f6:
                s.f[6] = data;
                return;
            case shadow_state_reg::f7:
                s.f[7] = data;
                return;
            case shadow_state_reg::f8:
                s.f[8] = data;
                return;
            case shadow_state_reg::f9:
                s.f[9] = data;
                return;
            case shadow_state_reg::f10:
                s.f[10] = data;
                return;
            case shadow_state_reg::f11:
                s.f[11] = data;
                return;
            case shadow_state_reg::f12:
                s.f[12] = data;
                return;
            case shadow_state_reg::f13:
                s.f[13] = data;
                return;
            case shadow_state_reg::f14:
                s.f[14] = data;
                return;
            case shadow_state_reg::f15:
                s.f[15] = data;
                return;
            case shadow_state_reg::f16:
                s.f[16] = data;
                return;
            case shadow_state_reg::f17:
                s.f[17] = data;
                return;
            case shadow_state_reg::f18:
                s.f[18] = data;
                return;
            case shadow_state_reg::f19:
                s.f[19] = data;
                return;
            case shadow_state_reg::f20:
                s.f[20] = data;
                return;
            case shadow_state_reg::f21:
                s.f[21] = data;
                return;
            case shadow_state_reg::f22:
                s.f[22] = data;
                return;
            case shadow_state_reg::f23:
                s.f[23] = data;
                return;
            case shadow_state_reg::f24:
                s.f[24] = data;
                return;
            case shadow_state_reg::f25:
                s.f[25] = data;
                return;
            case shadow_state_reg::f26:
                s.f[26] = data;
                return;
            case shadow_state_reg::f27:
                s.f[27] = data;
                return;
            case shadow_state_reg::f28:
                s.f[28] = data;
                return;
            case shadow_state_reg::f29:
                s.f[29] = data;
                return;
            case shadow_state_reg::f30:
                s.f[30] = data;
                return;
            case shadow_state_reg::f31:
                s.f[31] = data;
                return;
            case shadow_state_reg::pc:
                s.pc = data;
                return;
            case shadow_state_reg::fcsr:
                s.fcsr = data;
                return;
            case shadow_state_reg::mcycle:
                s.mcycle = data;
                return;
            case shadow_state_reg::icycleinstret:
                s.icycleinstret = data;
                return;
            case shadow_state_reg::mstatus:
                s.mstatus = data;
                return;
            case shadow_state_reg::mtvec:
                s.mtvec = data;
                return;
            case shadow_state_reg::mscratch:
                s.mscratch = data;
                return;
            case shadow_state_reg::mepc:
                s.mepc = data;
                return;
            case shadow_state_reg::mcause:
                s.mcause = data;
                return;
            case shadow_state_reg::mtval:
                s.mtval = data;
                return;
            case shadow_state_reg::misa:
                s.misa = data;
                return;
            case shadow_state_reg::mie:
                s.mie = data;
                return;
            case shadow_state_reg::mip:
                s.mip = data;
                return;
            case shadow_state_reg::medeleg:
                s.medeleg = data;
                return;
            case shadow_state_reg::mideleg:
                s.mideleg = data;
                return;
            case shadow_state_reg::mcounteren:
                s.mcounteren = data;
                return;
            case shadow_state_reg::menvcfg:
                s.menvcfg = data;
                return;
            case shadow_state_reg::stvec:
                s.stvec = data;
                return;
            case shadow_state_reg::sscratch:
                s.sscratch = data;
                return;
            case shadow_state_reg::sepc:
                s.sepc = data;
                return;
            case shadow_state_reg::scause:
                s.scause = data;
                return;
            case shadow_state_reg::stval:
                s.stval = data;
                return;
            case shadow_state_reg::satp:
                s.satp = data;
                return;
            case shadow_state_reg::scounteren:
                s.scounteren = data;
                return;
            case shadow_state_reg::senvcfg:
                s.senvcfg = data;
                return;
            case shadow_state_reg::ilrsc:
                s.ilrsc = data;
                return;
            case shadow_state_reg::iflags:
                s.write_iflags(data);
                return;
            case shadow_state_reg::clint_mtimecmp:
                s.clint.mtimecmp = data;
                return;
            case shadow_state_reg::plic_girqpend:
                s.plic.girqpend = data;
                return;
            case shadow_state_reg::plic_girqsrvd:
                s.plic.girqsrvd = data;
                return;
            case shadow_state_reg::htif_tohost:
                s.htif.tohost = data;
                return;
            case shadow_state_reg::htif_fromhost:
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
        switch (static_cast<shadow_state_reg>(paddr)) {
            case shadow_state_reg::x0:
                return s.x[0];
            case shadow_state_reg::x1:
                return s.x[1];
            case shadow_state_reg::x2:
                return s.x[2];
            case shadow_state_reg::x3:
                return s.x[3];
            case shadow_state_reg::x4:
                return s.x[4];
            case shadow_state_reg::x5:
                return s.x[5];
            case shadow_state_reg::x6:
                return s.x[6];
            case shadow_state_reg::x7:
                return s.x[7];
            case shadow_state_reg::x8:
                return s.x[8];
            case shadow_state_reg::x9:
                return s.x[9];
            case shadow_state_reg::x10:
                return s.x[10];
            case shadow_state_reg::x11:
                return s.x[11];
            case shadow_state_reg::x12:
                return s.x[12];
            case shadow_state_reg::x13:
                return s.x[13];
            case shadow_state_reg::x14:
                return s.x[14];
            case shadow_state_reg::x15:
                return s.x[15];
            case shadow_state_reg::x16:
                return s.x[16];
            case shadow_state_reg::x17:
                return s.x[17];
            case shadow_state_reg::x18:
                return s.x[18];
            case shadow_state_reg::x19:
                return s.x[19];
            case shadow_state_reg::x20:
                return s.x[20];
            case shadow_state_reg::x21:
                return s.x[21];
            case shadow_state_reg::x22:
                return s.x[22];
            case shadow_state_reg::x23:
                return s.x[23];
            case shadow_state_reg::x24:
                return s.x[24];
            case shadow_state_reg::x25:
                return s.x[25];
            case shadow_state_reg::x26:
                return s.x[26];
            case shadow_state_reg::x27:
                return s.x[27];
            case shadow_state_reg::x28:
                return s.x[28];
            case shadow_state_reg::x29:
                return s.x[29];
            case shadow_state_reg::x30:
                return s.x[30];
            case shadow_state_reg::x31:
                return s.x[31];
            case shadow_state_reg::f0:
                return s.f[0];
            case shadow_state_reg::f1:
                return s.f[1];
            case shadow_state_reg::f2:
                return s.f[2];
            case shadow_state_reg::f3:
                return s.f[3];
            case shadow_state_reg::f4:
                return s.f[4];
            case shadow_state_reg::f5:
                return s.f[5];
            case shadow_state_reg::f6:
                return s.f[6];
            case shadow_state_reg::f7:
                return s.f[7];
            case shadow_state_reg::f8:
                return s.f[8];
            case shadow_state_reg::f9:
                return s.f[9];
            case shadow_state_reg::f10:
                return s.f[10];
            case shadow_state_reg::f11:
                return s.f[11];
            case shadow_state_reg::f12:
                return s.f[12];
            case shadow_state_reg::f13:
                return s.f[13];
            case shadow_state_reg::f14:
                return s.f[14];
            case shadow_state_reg::f15:
                return s.f[15];
            case shadow_state_reg::f16:
                return s.f[16];
            case shadow_state_reg::f17:
                return s.f[17];
            case shadow_state_reg::f18:
                return s.f[18];
            case shadow_state_reg::f19:
                return s.f[19];
            case shadow_state_reg::f20:
                return s.f[20];
            case shadow_state_reg::f21:
                return s.f[21];
            case shadow_state_reg::f22:
                return s.f[22];
            case shadow_state_reg::f23:
                return s.f[23];
            case shadow_state_reg::f24:
                return s.f[24];
            case shadow_state_reg::f25:
                return s.f[25];
            case shadow_state_reg::f26:
                return s.f[26];
            case shadow_state_reg::f27:
                return s.f[27];
            case shadow_state_reg::f28:
                return s.f[28];
            case shadow_state_reg::f29:
                return s.f[29];
            case shadow_state_reg::f30:
                return s.f[30];
            case shadow_state_reg::f31:
                return s.f[31];
            case shadow_state_reg::pc:
                return s.pc;
            case shadow_state_reg::fcsr:
                return s.fcsr;
            case shadow_state_reg::mvendorid:
                return MVENDORID_INIT;
            case shadow_state_reg::marchid:
                return MARCHID_INIT;
            case shadow_state_reg::mimpid:
                return MIMPID_INIT;
            case shadow_state_reg::mcycle:
                return s.mcycle;
            case shadow_state_reg::icycleinstret:
                return s.icycleinstret;
            case shadow_state_reg::mstatus:
                return s.mstatus;
            case shadow_state_reg::mtvec:
                return s.mtvec;
            case shadow_state_reg::mscratch:
                return s.mscratch;
            case shadow_state_reg::mepc:
                return s.mepc;
            case shadow_state_reg::mcause:
                return s.mcause;
            case shadow_state_reg::mtval:
                return s.mtval;
            case shadow_state_reg::misa:
                return s.misa;
            case shadow_state_reg::mie:
                return s.mie;
            case shadow_state_reg::mip:
                return s.mip;
            case shadow_state_reg::medeleg:
                return s.medeleg;
            case shadow_state_reg::mideleg:
                return s.mideleg;
            case shadow_state_reg::mcounteren:
                return s.mcounteren;
            case shadow_state_reg::menvcfg:
                return s.menvcfg;
            case shadow_state_reg::stvec:
                return s.stvec;
            case shadow_state_reg::sscratch:
                return s.sscratch;
            case shadow_state_reg::sepc:
                return s.sepc;
            case shadow_state_reg::scause:
                return s.scause;
            case shadow_state_reg::stval:
                return s.stval;
            case shadow_state_reg::satp:
                return s.satp;
            case shadow_state_reg::scounteren:
                return s.scounteren;
            case shadow_state_reg::senvcfg:
                return s.senvcfg;
            case shadow_state_reg::ilrsc:
                return s.ilrsc;
            case shadow_state_reg::iflags:
                return s.read_iflags();
            case shadow_state_reg::clint_mtimecmp:
                return s.clint.mtimecmp;
            case shadow_state_reg::plic_girqpend:
                return s.plic.girqpend;
            case shadow_state_reg::plic_girqsrvd:
                return s.plic.girqsrvd;
            case shadow_state_reg::htif_tohost:
                return s.htif.tohost;
            case shadow_state_reg::htif_fromhost:
                return s.htif.fromhost;
            case shadow_state_reg::htif_ihalt:
                return s.htif.ihalt;
            case shadow_state_reg::htif_iconsole:
                return s.htif.iconsole;
            case shadow_state_reg::htif_iyield:
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
        switch (static_cast<shadow_state_reg>(paddr)) {
            case shadow_state_reg::x0:
                return "x0";
            case shadow_state_reg::x1:
                return "x1";
            case shadow_state_reg::x2:
                return "x2";
            case shadow_state_reg::x3:
                return "x3";
            case shadow_state_reg::x4:
                return "x4";
            case shadow_state_reg::x5:
                return "x5";
            case shadow_state_reg::x6:
                return "x6";
            case shadow_state_reg::x7:
                return "x7";
            case shadow_state_reg::x8:
                return "x8";
            case shadow_state_reg::x9:
                return "x9";
            case shadow_state_reg::x10:
                return "x10";
            case shadow_state_reg::x11:
                return "x11";
            case shadow_state_reg::x12:
                return "x12";
            case shadow_state_reg::x13:
                return "x13";
            case shadow_state_reg::x14:
                return "x14";
            case shadow_state_reg::x15:
                return "x15";
            case shadow_state_reg::x16:
                return "x16";
            case shadow_state_reg::x17:
                return "x17";
            case shadow_state_reg::x18:
                return "x18";
            case shadow_state_reg::x19:
                return "x19";
            case shadow_state_reg::x20:
                return "x20";
            case shadow_state_reg::x21:
                return "x21";
            case shadow_state_reg::x22:
                return "x22";
            case shadow_state_reg::x23:
                return "x23";
            case shadow_state_reg::x24:
                return "x24";
            case shadow_state_reg::x25:
                return "x25";
            case shadow_state_reg::x26:
                return "x26";
            case shadow_state_reg::x27:
                return "x27";
            case shadow_state_reg::x28:
                return "x28";
            case shadow_state_reg::x29:
                return "x29";
            case shadow_state_reg::x30:
                return "x30";
            case shadow_state_reg::x31:
                return "x31";
            case shadow_state_reg::f0:
                return "f0";
            case shadow_state_reg::f1:
                return "f1";
            case shadow_state_reg::f2:
                return "f2";
            case shadow_state_reg::f3:
                return "f3";
            case shadow_state_reg::f4:
                return "f4";
            case shadow_state_reg::f5:
                return "f5";
            case shadow_state_reg::f6:
                return "f6";
            case shadow_state_reg::f7:
                return "f7";
            case shadow_state_reg::f8:
                return "f8";
            case shadow_state_reg::f9:
                return "f9";
            case shadow_state_reg::f10:
                return "f10";
            case shadow_state_reg::f11:
                return "f11";
            case shadow_state_reg::f12:
                return "f12";
            case shadow_state_reg::f13:
                return "f13";
            case shadow_state_reg::f14:
                return "f14";
            case shadow_state_reg::f15:
                return "f15";
            case shadow_state_reg::f16:
                return "f16";
            case shadow_state_reg::f17:
                return "f17";
            case shadow_state_reg::f18:
                return "f18";
            case shadow_state_reg::f19:
                return "f19";
            case shadow_state_reg::f20:
                return "f20";
            case shadow_state_reg::f21:
                return "f21";
            case shadow_state_reg::f22:
                return "f22";
            case shadow_state_reg::f23:
                return "f23";
            case shadow_state_reg::f24:
                return "f24";
            case shadow_state_reg::f25:
                return "f25";
            case shadow_state_reg::f26:
                return "f26";
            case shadow_state_reg::f27:
                return "f27";
            case shadow_state_reg::f28:
                return "f28";
            case shadow_state_reg::f29:
                return "f29";
            case shadow_state_reg::f30:
                return "f30";
            case shadow_state_reg::f31:
                return "f31";
            case shadow_state_reg::pc:
                return "pc";
            case shadow_state_reg::fcsr:
                return "fcsr";
            case shadow_state_reg::mvendorid:
                return "mvendorid";
            case shadow_state_reg::marchid:
                return "marchid";
            case shadow_state_reg::mimpid:
                return "mimpid";
            case shadow_state_reg::mcycle:
                return "mcycle";
            case shadow_state_reg::icycleinstret:
                return "icycleinstret";
            case shadow_state_reg::mstatus:
                return "mstatus";
            case shadow_state_reg::mtvec:
                return "mtvec";
            case shadow_state_reg::mscratch:
                return "mscratch";
            case shadow_state_reg::mepc:
                return "mepc";
            case shadow_state_reg::mcause:
                return "mcause";
            case shadow_state_reg::mtval:
                return "mtval";
            case shadow_state_reg::misa:
                return "misa";
            case shadow_state_reg::mie:
                return "mie";
            case shadow_state_reg::mip:
                return "mip";
            case shadow_state_reg::medeleg:
                return "medeleg";
            case shadow_state_reg::mideleg:
                return "mideleg";
            case shadow_state_reg::mcounteren:
                return "mcounteren";
            case shadow_state_reg::menvcfg:
                return "menvcfg";
            case shadow_state_reg::stvec:
                return "stvec";
            case shadow_state_reg::sscratch:
                return "sscratch";
            case shadow_state_reg::sepc:
                return "sepc";
            case shadow_state_reg::scause:
                return "scause";
            case shadow_state_reg::stval:
                return "stval";
            case shadow_state_reg::satp:
                return "satp";
            case shadow_state_reg::scounteren:
                return "scounteren";
            case shadow_state_reg::senvcfg:
                return "senvcfg";
            case shadow_state_reg::ilrsc:
                return "ilrsc";
            case shadow_state_reg::iflags:
                return "iflags";
            case shadow_state_reg::clint_mtimecmp:
                return "clint.mtimecmp";
            case shadow_state_reg::plic_girqpend:
                return "plic.girqpend";
            case shadow_state_reg::plic_girqsrvd:
                return "plic.girqsrvd";
            case shadow_state_reg::htif_tohost:
                return "htif.tohost";
            case shadow_state_reg::htif_fromhost:
                return "htif.fromhost";
            case shadow_state_reg::htif_ihalt:
                return "htif.ihalt";
            case shadow_state_reg::htif_iconsole:
                return "htif.iconsole";
            case shadow_state_reg::htif_iyield:
                return "htif.iyield";
            default:
                break;
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
            }
            return "pma.ilength";
        }

        if (paddr >= PMA_SHADOW_TLB_START && paddr < PMA_SHADOW_TLB_START + PMA_SHADOW_TLB_LENGTH &&
            paddr % sizeof(uint64_t) == 0) {
            const uint64_t tlboff = paddr - PMA_SHADOW_TLB_START;
            if (tlboff < offsetof(shadow_tlb_state, cold)) {
                return "cold_tlb_entry_field";
            }
            if (tlboff < sizeof(shadow_tlb_state)) {
                return "hot_tlb_entry_field";
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
