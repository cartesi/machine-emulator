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

#include <cstddef>
#include <cstdint>

#include "address-range.h"
#include "compiler-defines.h"
#include "pmas-constants.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow state definitions.

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
    uint64_t iprv;
    uint64_t iflags_X;
    uint64_t iflags_Y;
    uint64_t iflags_H;
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

enum class shadow_state_what : uint64_t {
    x0 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[0]),
    x1 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[1]),
    x2 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[2]),
    x3 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[3]),
    x4 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[4]),
    x5 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[5]),
    x6 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[6]),
    x7 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[7]),
    x8 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[8]),
    x9 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[9]),
    x10 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[10]),
    x11 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[11]),
    x12 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[12]),
    x13 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[13]),
    x14 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[14]),
    x15 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[15]),
    x16 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[16]),
    x17 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[17]),
    x18 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[18]),
    x19 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[19]),
    x20 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[20]),
    x21 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[21]),
    x22 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[22]),
    x23 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[23]),
    x24 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[24]),
    x25 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[25]),
    x26 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[26]),
    x27 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[27]),
    x28 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[28]),
    x29 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[29]),
    x30 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[30]),
    x31 = AR_SHADOW_STATE_START + offsetof(shadow_state, x[31]),
    f0 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[0]),
    f1 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[1]),
    f2 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[2]),
    f3 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[3]),
    f4 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[4]),
    f5 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[5]),
    f6 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[6]),
    f7 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[7]),
    f8 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[8]),
    f9 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[9]),
    f10 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[10]),
    f11 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[11]),
    f12 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[12]),
    f13 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[13]),
    f14 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[14]),
    f15 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[15]),
    f16 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[16]),
    f17 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[17]),
    f18 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[18]),
    f19 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[19]),
    f20 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[20]),
    f21 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[21]),
    f22 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[22]),
    f23 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[23]),
    f24 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[24]),
    f25 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[25]),
    f26 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[26]),
    f27 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[27]),
    f28 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[28]),
    f29 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[29]),
    f30 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[30]),
    f31 = AR_SHADOW_STATE_START + offsetof(shadow_state, f[31]),
    pc = AR_SHADOW_STATE_START + offsetof(shadow_state, pc),
    fcsr = AR_SHADOW_STATE_START + offsetof(shadow_state, fcsr),
    mvendorid = AR_SHADOW_STATE_START + offsetof(shadow_state, mvendorid),
    marchid = AR_SHADOW_STATE_START + offsetof(shadow_state, marchid),
    mimpid = AR_SHADOW_STATE_START + offsetof(shadow_state, mimpid),
    mcycle = AR_SHADOW_STATE_START + offsetof(shadow_state, mcycle),
    icycleinstret = AR_SHADOW_STATE_START + offsetof(shadow_state, icycleinstret),
    mstatus = AR_SHADOW_STATE_START + offsetof(shadow_state, mstatus),
    mtvec = AR_SHADOW_STATE_START + offsetof(shadow_state, mtvec),
    mscratch = AR_SHADOW_STATE_START + offsetof(shadow_state, mscratch),
    mepc = AR_SHADOW_STATE_START + offsetof(shadow_state, mepc),
    mcause = AR_SHADOW_STATE_START + offsetof(shadow_state, mcause),
    mtval = AR_SHADOW_STATE_START + offsetof(shadow_state, mtval),
    misa = AR_SHADOW_STATE_START + offsetof(shadow_state, misa),
    mie = AR_SHADOW_STATE_START + offsetof(shadow_state, mie),
    mip = AR_SHADOW_STATE_START + offsetof(shadow_state, mip),
    medeleg = AR_SHADOW_STATE_START + offsetof(shadow_state, medeleg),
    mideleg = AR_SHADOW_STATE_START + offsetof(shadow_state, mideleg),
    mcounteren = AR_SHADOW_STATE_START + offsetof(shadow_state, mcounteren),
    menvcfg = AR_SHADOW_STATE_START + offsetof(shadow_state, menvcfg),
    stvec = AR_SHADOW_STATE_START + offsetof(shadow_state, stvec),
    sscratch = AR_SHADOW_STATE_START + offsetof(shadow_state, sscratch),
    sepc = AR_SHADOW_STATE_START + offsetof(shadow_state, sepc),
    scause = AR_SHADOW_STATE_START + offsetof(shadow_state, scause),
    stval = AR_SHADOW_STATE_START + offsetof(shadow_state, stval),
    satp = AR_SHADOW_STATE_START + offsetof(shadow_state, satp),
    scounteren = AR_SHADOW_STATE_START + offsetof(shadow_state, scounteren),
    senvcfg = AR_SHADOW_STATE_START + offsetof(shadow_state, senvcfg),
    ilrsc = AR_SHADOW_STATE_START + offsetof(shadow_state, ilrsc),
    iprv = AR_SHADOW_STATE_START + offsetof(shadow_state, iprv),
    iflags_X = AR_SHADOW_STATE_START + offsetof(shadow_state, iflags_X),
    iflags_Y = AR_SHADOW_STATE_START + offsetof(shadow_state, iflags_Y),
    iflags_H = AR_SHADOW_STATE_START + offsetof(shadow_state, iflags_H),
    iunrep = AR_SHADOW_STATE_START + offsetof(shadow_state, iunrep),
    clint_mtimecmp = AR_SHADOW_STATE_START + offsetof(shadow_state, clint_mtimecmp),
    plic_girqpend = AR_SHADOW_STATE_START + offsetof(shadow_state, plic_girqpend),
    plic_girqsrvd = AR_SHADOW_STATE_START + offsetof(shadow_state, plic_girqsrvd),
    htif_tohost = AR_SHADOW_STATE_START + offsetof(shadow_state, htif_tohost),
    htif_fromhost = AR_SHADOW_STATE_START + offsetof(shadow_state, htif_fromhost),
    htif_ihalt = AR_SHADOW_STATE_START + offsetof(shadow_state, htif_ihalt),
    htif_iconsole = AR_SHADOW_STATE_START + offsetof(shadow_state, htif_iconsole),
    htif_iyield = AR_SHADOW_STATE_START + offsetof(shadow_state, htif_iyield),
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

static constexpr shadow_state_what shadow_state_get_what(uint64_t paddr) {
    if (paddr < AR_SHADOW_STATE_START || paddr - AR_SHADOW_STATE_START >= sizeof(shadow_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return shadow_state_what::unknown_;
    }
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    return static_cast<shadow_state_what>(paddr);
}

static constexpr shadow_state_what shadow_state_get_what(shadow_state_what what, int i) {
    return static_cast<shadow_state_what>(static_cast<uint64_t>(what) + (i * sizeof(uint64_t)));
}

static constexpr const char *shadow_state_get_what_name(shadow_state_what what) {
    const auto paddr = static_cast<uint64_t>(what);
    if (paddr < AR_SHADOW_STATE_START || paddr - AR_SHADOW_STATE_START >= sizeof(shadow_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return "state.unknown_";
    }
    using reg = shadow_state_what;
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
