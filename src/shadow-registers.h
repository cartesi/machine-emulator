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

#ifndef SHADOW_REGISTERS_STATE_H
#define SHADOW_REGISTERS_STATE_H

#include <cstddef>
#include <cstdint>

#include "address-range-constants.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow state definitions.

namespace cartesi {

/// \brief Internal flags state (Cartesi specific).
struct iflags_state final {
    uint64_t X{IFLAGS_X_INIT}; ///< CPU has yielded with automatic reset.
    uint64_t Y{IFLAGS_Y_INIT}; ///< CPU has yielded with manual reset.
    uint64_t H{IFLAGS_H_INIT}; ///< CPU has been permanently halted.
};

/// \brief CLINT (Core-Local Interruptor) state
struct clint_state final {
    uint64_t mtimecmp{MTIMECMP_INIT}; ///< CSR mtimecmp.
};

/// \brief PLIC (Platform-Level Interrupt Controller) state
struct plic_state final {
    uint64_t girqpend{GIRQPEND_INIT}; ///< CSR girqpend (global interrupts pending).
    uint64_t girqsrvd{GIRQSRVD_INIT}; ///< CSR girqsrvd (global interrupts served).
};

/// HTIF (Host-Target config InterFace) state
struct htif_state final {
    uint64_t tohost{TOHOST_INIT};     ///< CSR tohost.
    uint64_t fromhost{FROMHOST_INIT}; ///< CSR fromhost.
    uint64_t ihalt{IHALT_INIT};       ///< CSR ihalt (Cartesi-specific).
    uint64_t iconsole{ICONSOLE_INIT}; ///< CSR iconsole (Cartesi-specific).
    uint64_t iyield{IYIELD_INIT};     ///< CSR iyield (Cartesi-specific).
};

/// \brief Machine registers state
struct registers_state final {
    // The X registers are the very first to optimize access of registers in the interpreter.
    uint64_t x[X_REG_COUNT]{REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7, REG_X8, REG_X9, REG_X10,
        REG_X11, REG_X12, REG_X13, REG_X14, REG_X15, REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22,
        REG_X23, REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_X31}; ///< Register file.
    // The following registers are carefully ordered to have better data locality in the interpreter loop.
    uint64_t mcycle{MCYCLE_INIT}; ///< CSR mcycle.
    uint64_t pc{PC_INIT};         ///< Program counter.
    uint64_t fcsr{FCSR_INIT};     ///< CSR fcsr.
    uint64_t f[F_REG_COUNT]{};    ///< Floating-point register file.
    uint64_t iprv{IPRV_INIT};     ///< Privilege level (Cartesi-specific).

    // RISC-V machine CSRs
    uint64_t mstatus{MSTATUS_INIT};       ///< CSR mstatus.
    uint64_t mtvec{MTVEC_INIT};           ///< CSR mtvec.
    uint64_t mscratch{MSCRATCH_INIT};     ///< CSR mscratch.
    uint64_t mepc{MEPC_INIT};             ///< CSR mepc.
    uint64_t mcause{MCAUSE_INIT};         ///< CSR mcause.
    uint64_t mtval{MTVAL_INIT};           ///< CSR mtval.
    uint64_t misa{MISA_INIT};             ///< CSR misa.
    uint64_t mie{MIE_INIT};               ///< CSR mie.
    uint64_t mip{MIP_INIT};               ///< CSR mip.
    uint64_t medeleg{MEDELEG_INIT};       ///< CSR medeleg.
    uint64_t mideleg{MIDELEG_INIT};       ///< CSR mideleg.
    uint64_t mcounteren{MCOUNTEREN_INIT}; ///< CSR mcounteren.
    uint64_t menvcfg{MENVCFG_INIT};       ///< CSR menvcfg.
    uint64_t mvendorid{MVENDORID_INIT};   ///< CSR mvendorid.
    uint64_t marchid{MARCHID_INIT};       ///< CSR marchid.
    uint64_t mimpid{MIMPID_INIT};         ///< CSR mimpid.

    // RISC-V supervisor CSRs
    uint64_t stvec{STVEC_INIT};           ///< CSR stvec.
    uint64_t sscratch{SSCRATCH_INIT};     ///< CSR sscratch.
    uint64_t sepc{SEPC_INIT};             ///< CSR sepc.
    uint64_t scause{SCAUSE_INIT};         ///< CSR scause.
    uint64_t stval{STVAL_INIT};           ///< CSR stval.
    uint64_t satp{SATP_INIT};             ///< CSR satp.
    uint64_t scounteren{SCOUNTEREN_INIT}; ///< CSR scounteren.
    uint64_t senvcfg{SENVCFG_INIT};       ///< CSR senvcfg.

    // Cartesi-specific state
    uint64_t ilrsc{ILRSC_INIT};                 ///< For LR/SC instructions.
    uint64_t icycleinstret{ICYCLEINSTRET_INIT}; ///< Difference between mcycle and minstret.
    uint64_t iunrep{IUNREP_INIT};               ///< Unreproducible mode.

    iflags_state iflags; ///< Internal flags (Cartesi specific).
    clint_state clint;   ///< CLINT registers.
    plic_state plic;     ///< PLIC registers.
    htif_state htif;     ///< HTIF registers.
};

/// \brief Shadow memory layout
using shadow_registers_state = registers_state;

// We need strong guarantees that shadow_state has fixed size and alignment across platforms.
static_assert(sizeof(shadow_registers_state) == 106 * sizeof(uint64_t), "unexpected registers state size");
static_assert(alignof(shadow_registers_state) == sizeof(uint64_t), "unexpected registers state alignment");

enum class shadow_registers_what : uint64_t {
    x0 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[0]),
    x1 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[1]),
    x2 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[2]),
    x3 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[3]),
    x4 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[4]),
    x5 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[5]),
    x6 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[6]),
    x7 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[7]),
    x8 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[8]),
    x9 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[9]),
    x10 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[10]),
    x11 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[11]),
    x12 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[12]),
    x13 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[13]),
    x14 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[14]),
    x15 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[15]),
    x16 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[16]),
    x17 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[17]),
    x18 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[18]),
    x19 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[19]),
    x20 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[20]),
    x21 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[21]),
    x22 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[22]),
    x23 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[23]),
    x24 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[24]),
    x25 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[25]),
    x26 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[26]),
    x27 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[27]),
    x28 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[28]),
    x29 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[29]),
    x30 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[30]),
    x31 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, x[31]),
    f0 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[0]),
    f1 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[1]),
    f2 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[2]),
    f3 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[3]),
    f4 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[4]),
    f5 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[5]),
    f6 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[6]),
    f7 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[7]),
    f8 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[8]),
    f9 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[9]),
    f10 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[10]),
    f11 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[11]),
    f12 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[12]),
    f13 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[13]),
    f14 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[14]),
    f15 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[15]),
    f16 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[16]),
    f17 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[17]),
    f18 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[18]),
    f19 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[19]),
    f20 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[20]),
    f21 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[21]),
    f22 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[22]),
    f23 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[23]),
    f24 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[24]),
    f25 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[25]),
    f26 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[26]),
    f27 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[27]),
    f28 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[28]),
    f29 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[29]),
    f30 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[30]),
    f31 = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, f[31]),
    pc = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, pc),
    fcsr = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, fcsr),
    mvendorid = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mvendorid),
    marchid = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, marchid),
    mimpid = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mimpid),
    mcycle = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mcycle),
    icycleinstret = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, icycleinstret),
    mstatus = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mstatus),
    mtvec = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mtvec),
    mscratch = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mscratch),
    mepc = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mepc),
    mcause = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mcause),
    mtval = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mtval),
    misa = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, misa),
    mie = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mie),
    mip = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mip),
    medeleg = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, medeleg),
    mideleg = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mideleg),
    mcounteren = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, mcounteren),
    menvcfg = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, menvcfg),
    stvec = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, stvec),
    sscratch = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, sscratch),
    sepc = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, sepc),
    scause = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, scause),
    stval = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, stval),
    satp = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, satp),
    scounteren = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, scounteren),
    senvcfg = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, senvcfg),
    ilrsc = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, ilrsc),
    iprv = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, iprv),
    iflags_X = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, iflags.X),
    iflags_Y = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, iflags.Y),
    iflags_H = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, iflags.H),
    iunrep = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, iunrep),
    clint_mtimecmp = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, clint.mtimecmp),
    plic_girqpend = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, plic.girqpend),
    plic_girqsrvd = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, plic.girqsrvd),
    htif_tohost = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, htif.tohost),
    htif_fromhost = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, htif.fromhost),
    htif_ihalt = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, htif.ihalt),
    htif_iconsole = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, htif.iconsole),
    htif_iyield = AR_SHADOW_REGISTERS_START + offsetof(shadow_registers_state, htif.iyield),
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

static constexpr shadow_registers_what shadow_registers_get_what(uint64_t paddr) {
    if (paddr < AR_SHADOW_REGISTERS_START || paddr - AR_SHADOW_REGISTERS_START >= sizeof(shadow_registers_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return shadow_registers_what::unknown_;
    }
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    return static_cast<shadow_registers_what>(paddr);
}

static constexpr shadow_registers_what shadow_registers_get_what(shadow_registers_what what, int i) {
    return static_cast<shadow_registers_what>(static_cast<uint64_t>(what) + (i * sizeof(uint64_t)));
}

static constexpr const char *shadow_registers_get_what_name(shadow_registers_what what) {
    const auto paddr = static_cast<uint64_t>(what);
    if (paddr < AR_SHADOW_REGISTERS_START || paddr - AR_SHADOW_REGISTERS_START >= sizeof(shadow_registers_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return "state.unknown_";
    }
    using reg = shadow_registers_what;
    switch (what) {
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
        case reg::iunrep:
            return "iunrep";
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
        case reg::unknown_:
            return "state.unknown_";
    }
    return "state.unknown_";
}

} // namespace cartesi

#endif
