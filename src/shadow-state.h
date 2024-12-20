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

#ifndef SHADOW_STATE_H
#define SHADOW_STATE_H

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "compiler-defines.h"
#include "machine-reg.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

/// \brief Shadow memory layout
struct PACKED shadow_state {
    uint64_t x[X_REG_COUNT]; ///< Register file.
    uint64_t f[F_REG_COUNT]; ///< Floating-point register file.
    uint64_t pc;
    uint64_t fcsr;
    uint64_t mvendorid;
    uint64_t marchid;
    uint64_t mimpid;
    uint64_t mcycle;
    uint64_t icycleinstret;
    uint64_t mstatus;
    uint64_t mtvec;
    uint64_t mscratch;
    uint64_t mepc;
    uint64_t mcause;
    uint64_t mtval;
    uint64_t misa;
    uint64_t mie;
    uint64_t mip;
    uint64_t medeleg;
    uint64_t mideleg;
    uint64_t mcounteren;
    uint64_t menvcfg;
    uint64_t stvec;
    uint64_t sscratch;
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t satp;
    uint64_t scounteren;
    uint64_t senvcfg;
    uint64_t ilrsc;
    uint64_t iflags;
    uint64_t iunrep;
    uint64_t clint_mtimecmp;
    uint64_t plic_girqpend;
    uint64_t plic_girqsrvd;
    uint64_t htif_tohost;
    uint64_t htif_fromhost;
    uint64_t htif_ihalt;
    uint64_t htif_iconsole;
    uint64_t htif_iyield;
};

/// \brief Global instance of the processor shadow device driver.
extern const pma_driver shadow_state_driver;

/// \brief Mapping between registers and their relative addresses in shadow memory
enum class shadow_state_reg_rel_addr : uint64_t {
    x0 = offsetof(shadow_state, x[0]),
    x1 = offsetof(shadow_state, x[1]),
    x2 = offsetof(shadow_state, x[2]),
    x3 = offsetof(shadow_state, x[3]),
    x4 = offsetof(shadow_state, x[4]),
    x5 = offsetof(shadow_state, x[5]),
    x6 = offsetof(shadow_state, x[6]),
    x7 = offsetof(shadow_state, x[7]),
    x8 = offsetof(shadow_state, x[8]),
    x9 = offsetof(shadow_state, x[9]),
    x10 = offsetof(shadow_state, x[10]),
    x11 = offsetof(shadow_state, x[11]),
    x12 = offsetof(shadow_state, x[12]),
    x13 = offsetof(shadow_state, x[13]),
    x14 = offsetof(shadow_state, x[14]),
    x15 = offsetof(shadow_state, x[15]),
    x16 = offsetof(shadow_state, x[16]),
    x17 = offsetof(shadow_state, x[17]),
    x18 = offsetof(shadow_state, x[18]),
    x19 = offsetof(shadow_state, x[19]),
    x20 = offsetof(shadow_state, x[20]),
    x21 = offsetof(shadow_state, x[21]),
    x22 = offsetof(shadow_state, x[22]),
    x23 = offsetof(shadow_state, x[23]),
    x24 = offsetof(shadow_state, x[24]),
    x25 = offsetof(shadow_state, x[25]),
    x26 = offsetof(shadow_state, x[26]),
    x27 = offsetof(shadow_state, x[27]),
    x28 = offsetof(shadow_state, x[28]),
    x29 = offsetof(shadow_state, x[29]),
    x30 = offsetof(shadow_state, x[30]),
    x31 = offsetof(shadow_state, x[31]),
    f0 = offsetof(shadow_state, f[0]),
    f1 = offsetof(shadow_state, f[1]),
    f2 = offsetof(shadow_state, f[2]),
    f3 = offsetof(shadow_state, f[3]),
    f4 = offsetof(shadow_state, f[4]),
    f5 = offsetof(shadow_state, f[5]),
    f6 = offsetof(shadow_state, f[6]),
    f7 = offsetof(shadow_state, f[7]),
    f8 = offsetof(shadow_state, f[8]),
    f9 = offsetof(shadow_state, f[9]),
    f10 = offsetof(shadow_state, f[10]),
    f11 = offsetof(shadow_state, f[11]),
    f12 = offsetof(shadow_state, f[12]),
    f13 = offsetof(shadow_state, f[13]),
    f14 = offsetof(shadow_state, f[14]),
    f15 = offsetof(shadow_state, f[15]),
    f16 = offsetof(shadow_state, f[16]),
    f17 = offsetof(shadow_state, f[17]),
    f18 = offsetof(shadow_state, f[18]),
    f19 = offsetof(shadow_state, f[19]),
    f20 = offsetof(shadow_state, f[20]),
    f21 = offsetof(shadow_state, f[21]),
    f22 = offsetof(shadow_state, f[22]),
    f23 = offsetof(shadow_state, f[23]),
    f24 = offsetof(shadow_state, f[24]),
    f25 = offsetof(shadow_state, f[25]),
    f26 = offsetof(shadow_state, f[26]),
    f27 = offsetof(shadow_state, f[27]),
    f28 = offsetof(shadow_state, f[28]),
    f29 = offsetof(shadow_state, f[29]),
    f30 = offsetof(shadow_state, f[30]),
    f31 = offsetof(shadow_state, f[31]),
    pc = offsetof(shadow_state, pc),
    fcsr = offsetof(shadow_state, fcsr),
    mvendorid = offsetof(shadow_state, mvendorid),
    marchid = offsetof(shadow_state, marchid),
    mimpid = offsetof(shadow_state, mimpid),
    mcycle = offsetof(shadow_state, mcycle),
    icycleinstret = offsetof(shadow_state, icycleinstret),
    mstatus = offsetof(shadow_state, mstatus),
    mtvec = offsetof(shadow_state, mtvec),
    mscratch = offsetof(shadow_state, mscratch),
    mepc = offsetof(shadow_state, mepc),
    mcause = offsetof(shadow_state, mcause),
    mtval = offsetof(shadow_state, mtval),
    misa = offsetof(shadow_state, misa),
    mie = offsetof(shadow_state, mie),
    mip = offsetof(shadow_state, mip),
    medeleg = offsetof(shadow_state, medeleg),
    mideleg = offsetof(shadow_state, mideleg),
    mcounteren = offsetof(shadow_state, mcounteren),
    menvcfg = offsetof(shadow_state, menvcfg),
    stvec = offsetof(shadow_state, stvec),
    sscratch = offsetof(shadow_state, sscratch),
    sepc = offsetof(shadow_state, sepc),
    scause = offsetof(shadow_state, scause),
    stval = offsetof(shadow_state, stval),
    satp = offsetof(shadow_state, satp),
    scounteren = offsetof(shadow_state, scounteren),
    senvcfg = offsetof(shadow_state, senvcfg),
    ilrsc = offsetof(shadow_state, ilrsc),
    iflags = offsetof(shadow_state, iflags),
    iunrep = offsetof(shadow_state, iunrep),
    clint_mtimecmp = offsetof(shadow_state, clint_mtimecmp),
    plic_girqpend = offsetof(shadow_state, plic_girqpend),
    plic_girqsrvd = offsetof(shadow_state, plic_girqsrvd),
    htif_tohost = offsetof(shadow_state, htif_tohost),
    htif_fromhost = offsetof(shadow_state, htif_fromhost),
    htif_ihalt = offsetof(shadow_state, htif_ihalt),
    htif_iconsole = offsetof(shadow_state, htif_iconsole),
    htif_iyield = offsetof(shadow_state, htif_iyield),
};

/// \brief Obtains the relative address of a general purpose register
/// in shadow memory.
/// \param reg Register index in 0...31, for x0...x31, respectively.
/// \returns The address.
static inline uint64_t shadow_state_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < X_REG_COUNT);
    return offsetof(shadow_state, x) + reg * sizeof(uint64_t);
}

/// \brief Obtains the relative address of a floating-point register
static inline uint64_t shadow_state_get_f_rel_addr(int reg) {
    assert(reg >= 0 && reg < F_REG_COUNT);
    return offsetof(shadow_state, f) + reg * sizeof(uint64_t);
}

/// \brief Obtains the relative address of a register in shadow memory.
/// \param r Register name.
/// \returns The address.
static inline uint64_t shadow_state_get_reg_rel_addr(machine_reg r) {
    using reg = machine_reg;
    switch (r) {
        case reg::x0:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x0);
        case reg::x1:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x1);
        case reg::x2:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x2);
        case reg::x3:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x3);
        case reg::x4:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x4);
        case reg::x5:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x5);
        case reg::x6:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x6);
        case reg::x7:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x7);
        case reg::x8:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x8);
        case reg::x9:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x9);
        case reg::x10:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x10);
        case reg::x11:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x11);
        case reg::x12:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x12);
        case reg::x13:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x13);
        case reg::x14:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x14);
        case reg::x15:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x15);
        case reg::x16:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x16);
        case reg::x17:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x17);
        case reg::x18:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x18);
        case reg::x19:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x19);
        case reg::x20:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x20);
        case reg::x21:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x21);
        case reg::x22:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x22);
        case reg::x23:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x23);
        case reg::x24:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x24);
        case reg::x25:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x25);
        case reg::x26:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x26);
        case reg::x27:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x27);
        case reg::x28:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x28);
        case reg::x29:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x29);
        case reg::x30:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x30);
        case reg::x31:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::x31);
        case reg::f0:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f0);
        case reg::f1:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f1);
        case reg::f2:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f2);
        case reg::f3:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f3);
        case reg::f4:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f4);
        case reg::f5:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f5);
        case reg::f6:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f6);
        case reg::f7:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f7);
        case reg::f8:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f8);
        case reg::f9:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f9);
        case reg::f10:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f10);
        case reg::f11:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f11);
        case reg::f12:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f12);
        case reg::f13:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f13);
        case reg::f14:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f14);
        case reg::f15:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f15);
        case reg::f16:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f16);
        case reg::f17:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f17);
        case reg::f18:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f18);
        case reg::f19:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f19);
        case reg::f20:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f20);
        case reg::f21:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f21);
        case reg::f22:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f22);
        case reg::f23:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f23);
        case reg::f24:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f24);
        case reg::f25:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f25);
        case reg::f26:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f26);
        case reg::f27:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f27);
        case reg::f28:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f28);
        case reg::f29:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f29);
        case reg::f30:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f30);
        case reg::f31:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::f31);
        case reg::pc:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::pc);
        case reg::fcsr:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::fcsr);
        case reg::mvendorid:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mvendorid);
        case reg::marchid:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::marchid);
        case reg::mimpid:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mimpid);
        case reg::mcycle:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mcycle);
        case reg::icycleinstret:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::icycleinstret);
        case reg::mstatus:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mstatus);
        case reg::mtvec:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mtvec);
        case reg::mscratch:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mscratch);
        case reg::mepc:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mepc);
        case reg::mcause:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mcause);
        case reg::mtval:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mtval);
        case reg::misa:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::misa);
        case reg::mie:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mie);
        case reg::mip:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mip);
        case reg::medeleg:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::medeleg);
        case reg::mideleg:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mideleg);
        case reg::mcounteren:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::mcounteren);
        case reg::menvcfg:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::menvcfg);
        case reg::stvec:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::stvec);
        case reg::sscratch:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::sscratch);
        case reg::sepc:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::sepc);
        case reg::scause:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::scause);
        case reg::stval:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::stval);
        case reg::satp:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::satp);
        case reg::scounteren:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::scounteren);
        case reg::senvcfg:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::senvcfg);
        case reg::ilrsc:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::ilrsc);
        case reg::iflags:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::iflags);
        case reg::iunrep:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::iunrep);
        case reg::clint_mtimecmp:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::clint_mtimecmp);
        case reg::plic_girqpend:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::plic_girqpend);
        case reg::plic_girqsrvd:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::plic_girqsrvd);
        case reg::htif_tohost:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::htif_tohost);
        case reg::htif_fromhost:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::htif_fromhost);
        case reg::htif_ihalt:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::htif_ihalt);
        case reg::htif_iconsole:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::htif_iconsole);
        case reg::htif_iyield:
            return static_cast<uint64_t>(shadow_state_reg_rel_addr::htif_iyield);
        default:
            assert(0);
            return 0;
    }
}

/// \brief Obtains the absolute address of a register in shadow memory.
/// \param r Register name.
/// \returns The address.
static inline uint64_t shadow_state_get_reg_abs_addr(machine_reg r) {
    return PMA_SHADOW_STATE_START + shadow_state_get_reg_rel_addr(r);
}

/// \brief Obtains the absolute address of a general purpose register
static inline uint64_t shadow_state_get_x_abs_addr(int reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_x_rel_addr(reg);
}

/// \brief Obtains the absolute address of a floating-point register
static inline uint64_t shadow_state_get_f_abs_addr(int reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_f_rel_addr(reg);
}

} // namespace cartesi

#endif
