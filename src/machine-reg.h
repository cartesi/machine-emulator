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

#ifndef MACHINE_REG_H
#define MACHINE_REG_H

#include "pma-constants.h"
#include "shadow-state.h"
#include "shadow-uarch-state.h"

/// \file
/// \brief Cartesi machine registers

namespace cartesi {

/// \brief List of machine registers
enum class machine_reg : uint64_t {
    // Processor x registers
    x0 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[0]),
    x1 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[1]),
    x2 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[2]),
    x3 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[3]),
    x4 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[4]),
    x5 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[5]),
    x6 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[6]),
    x7 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[7]),
    x8 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[8]),
    x9 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[9]),
    x10 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[10]),
    x11 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[11]),
    x12 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[12]),
    x13 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[13]),
    x14 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[14]),
    x15 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[15]),
    x16 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[16]),
    x17 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[17]),
    x18 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[18]),
    x19 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[19]),
    x20 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[20]),
    x21 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[21]),
    x22 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[22]),
    x23 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[23]),
    x24 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[24]),
    x25 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[25]),
    x26 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[26]),
    x27 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[27]),
    x28 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[28]),
    x29 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[29]),
    x30 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[30]),
    x31 = PMA_SHADOW_STATE_START + offsetof(shadow_state, x[31]),
    f0 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[0]),
    f1 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[1]),
    f2 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[2]),
    f3 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[3]),
    f4 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[4]),
    f5 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[5]),
    f6 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[6]),
    f7 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[7]),
    f8 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[8]),
    f9 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[9]),
    f10 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[10]),
    f11 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[11]),
    f12 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[12]),
    f13 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[13]),
    f14 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[14]),
    f15 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[15]),
    f16 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[16]),
    f17 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[17]),
    f18 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[18]),
    f19 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[19]),
    f20 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[20]),
    f21 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[21]),
    f22 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[22]),
    f23 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[23]),
    f24 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[24]),
    f25 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[25]),
    f26 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[26]),
    f27 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[27]),
    f28 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[28]),
    f29 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[29]),
    f30 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[30]),
    f31 = PMA_SHADOW_STATE_START + offsetof(shadow_state, f[31]),
    pc = PMA_SHADOW_STATE_START + offsetof(shadow_state, pc),
    fcsr = PMA_SHADOW_STATE_START + offsetof(shadow_state, fcsr),
    mvendorid = PMA_SHADOW_STATE_START + offsetof(shadow_state, mvendorid),
    marchid = PMA_SHADOW_STATE_START + offsetof(shadow_state, marchid),
    mimpid = PMA_SHADOW_STATE_START + offsetof(shadow_state, mimpid),
    mcycle = PMA_SHADOW_STATE_START + offsetof(shadow_state, mcycle),
    icycleinstret = PMA_SHADOW_STATE_START + offsetof(shadow_state, icycleinstret),
    mstatus = PMA_SHADOW_STATE_START + offsetof(shadow_state, mstatus),
    mtvec = PMA_SHADOW_STATE_START + offsetof(shadow_state, mtvec),
    mscratch = PMA_SHADOW_STATE_START + offsetof(shadow_state, mscratch),
    mepc = PMA_SHADOW_STATE_START + offsetof(shadow_state, mepc),
    mcause = PMA_SHADOW_STATE_START + offsetof(shadow_state, mcause),
    mtval = PMA_SHADOW_STATE_START + offsetof(shadow_state, mtval),
    misa = PMA_SHADOW_STATE_START + offsetof(shadow_state, misa),
    mie = PMA_SHADOW_STATE_START + offsetof(shadow_state, mie),
    mip = PMA_SHADOW_STATE_START + offsetof(shadow_state, mip),
    medeleg = PMA_SHADOW_STATE_START + offsetof(shadow_state, medeleg),
    mideleg = PMA_SHADOW_STATE_START + offsetof(shadow_state, mideleg),
    mcounteren = PMA_SHADOW_STATE_START + offsetof(shadow_state, mcounteren),
    menvcfg = PMA_SHADOW_STATE_START + offsetof(shadow_state, menvcfg),
    stvec = PMA_SHADOW_STATE_START + offsetof(shadow_state, stvec),
    sscratch = PMA_SHADOW_STATE_START + offsetof(shadow_state, sscratch),
    sepc = PMA_SHADOW_STATE_START + offsetof(shadow_state, sepc),
    scause = PMA_SHADOW_STATE_START + offsetof(shadow_state, scause),
    stval = PMA_SHADOW_STATE_START + offsetof(shadow_state, stval),
    satp = PMA_SHADOW_STATE_START + offsetof(shadow_state, satp),
    scounteren = PMA_SHADOW_STATE_START + offsetof(shadow_state, scounteren),
    senvcfg = PMA_SHADOW_STATE_START + offsetof(shadow_state, senvcfg),
    ilrsc = PMA_SHADOW_STATE_START + offsetof(shadow_state, ilrsc),
    iflags = PMA_SHADOW_STATE_START + offsetof(shadow_state, iflags),
    iunrep = PMA_SHADOW_STATE_START + offsetof(shadow_state, iunrep),
    clint_mtimecmp = PMA_SHADOW_STATE_START + offsetof(shadow_state, clint_mtimecmp),
    plic_girqpend = PMA_SHADOW_STATE_START + offsetof(shadow_state, plic_girqpend),
    plic_girqsrvd = PMA_SHADOW_STATE_START + offsetof(shadow_state, plic_girqsrvd),
    htif_tohost = PMA_SHADOW_STATE_START + offsetof(shadow_state, htif_tohost),
    htif_fromhost = PMA_SHADOW_STATE_START + offsetof(shadow_state, htif_fromhost),
    htif_ihalt = PMA_SHADOW_STATE_START + offsetof(shadow_state, htif_ihalt),
    htif_iconsole = PMA_SHADOW_STATE_START + offsetof(shadow_state, htif_iconsole),
    htif_iyield = PMA_SHADOW_STATE_START + offsetof(shadow_state, htif_iyield),
    first_ = x0,
    last_ = htif_iyield,

    uarch_halt_flag = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, halt_flag),
    uarch_cycle = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, cycle),
    uarch_pc = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, pc),
    uarch_x0 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[0]),
    uarch_x1 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[1]),
    uarch_x2 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[2]),
    uarch_x3 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[3]),
    uarch_x4 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[4]),
    uarch_x5 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[5]),
    uarch_x6 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[6]),
    uarch_x7 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[7]),
    uarch_x8 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[8]),
    uarch_x9 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[9]),
    uarch_x10 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[10]),
    uarch_x11 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[11]),
    uarch_x12 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[12]),
    uarch_x13 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[13]),
    uarch_x14 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[14]),
    uarch_x15 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[15]),
    uarch_x16 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[16]),
    uarch_x17 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[17]),
    uarch_x18 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[18]),
    uarch_x19 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[19]),
    uarch_x20 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[20]),
    uarch_x21 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[21]),
    uarch_x22 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[22]),
    uarch_x23 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[23]),
    uarch_x24 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[24]),
    uarch_x25 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[25]),
    uarch_x26 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[26]),
    uarch_x27 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[27]),
    uarch_x28 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[28]),
    uarch_x29 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[29]),
    uarch_x30 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[30]),
    uarch_x31 = PMA_SHADOW_UARCH_STATE_START + offsetof(shadow_uarch_state, x[31]),
    uarch_first_ = uarch_halt_flag,
    uarch_last_ = uarch_x31,

    // Views of registers
    iflags_prv,
    iflags_x,
    iflags_y,
    iflags_h,
    htif_tohost_dev,
    htif_tohost_cmd,
    htif_tohost_reason,
    htif_tohost_data,
    htif_fromhost_dev,
    htif_fromhost_cmd,
    htif_fromhost_reason,
    htif_fromhost_data,
    unknown_,
};

constexpr uint64_t machine_reg_address(machine_reg reg, int i = 0) {
    return static_cast<uint64_t>(reg) + i * sizeof(uint64_t);
}

constexpr machine_reg machine_reg_enum(machine_reg reg, int i) {
    return static_cast<machine_reg>(static_cast<uint64_t>(reg) + i * sizeof(uint64_t));
}

static_assert(machine_reg_address(machine_reg::uarch_first_) > machine_reg_address(machine_reg::last_));

static_assert(machine_reg_address(machine_reg::x0, 1) == machine_reg_address(machine_reg::x1));
static_assert(machine_reg_address(machine_reg::x0, 2) == machine_reg_address(machine_reg::x2));
static_assert(machine_reg_address(machine_reg::x0, 3) == machine_reg_address(machine_reg::x3));
static_assert(machine_reg_address(machine_reg::x0, 4) == machine_reg_address(machine_reg::x4));
static_assert(machine_reg_address(machine_reg::x0, 5) == machine_reg_address(machine_reg::x5));
static_assert(machine_reg_address(machine_reg::x0, 6) == machine_reg_address(machine_reg::x6));
static_assert(machine_reg_address(machine_reg::x0, 7) == machine_reg_address(machine_reg::x7));
static_assert(machine_reg_address(machine_reg::x0, 8) == machine_reg_address(machine_reg::x8));
static_assert(machine_reg_address(machine_reg::x0, 9) == machine_reg_address(machine_reg::x9));
static_assert(machine_reg_address(machine_reg::x0, 10) == machine_reg_address(machine_reg::x10));
static_assert(machine_reg_address(machine_reg::x0, 11) == machine_reg_address(machine_reg::x11));
static_assert(machine_reg_address(machine_reg::x0, 12) == machine_reg_address(machine_reg::x12));
static_assert(machine_reg_address(machine_reg::x0, 13) == machine_reg_address(machine_reg::x13));
static_assert(machine_reg_address(machine_reg::x0, 14) == machine_reg_address(machine_reg::x14));
static_assert(machine_reg_address(machine_reg::x0, 15) == machine_reg_address(machine_reg::x15));
static_assert(machine_reg_address(machine_reg::x0, 16) == machine_reg_address(machine_reg::x16));
static_assert(machine_reg_address(machine_reg::x0, 17) == machine_reg_address(machine_reg::x17));
static_assert(machine_reg_address(machine_reg::x0, 18) == machine_reg_address(machine_reg::x18));
static_assert(machine_reg_address(machine_reg::x0, 19) == machine_reg_address(machine_reg::x19));
static_assert(machine_reg_address(machine_reg::x0, 20) == machine_reg_address(machine_reg::x20));
static_assert(machine_reg_address(machine_reg::x0, 21) == machine_reg_address(machine_reg::x21));
static_assert(machine_reg_address(machine_reg::x0, 22) == machine_reg_address(machine_reg::x22));
static_assert(machine_reg_address(machine_reg::x0, 23) == machine_reg_address(machine_reg::x23));
static_assert(machine_reg_address(machine_reg::x0, 24) == machine_reg_address(machine_reg::x24));
static_assert(machine_reg_address(machine_reg::x0, 25) == machine_reg_address(machine_reg::x25));
static_assert(machine_reg_address(machine_reg::x0, 26) == machine_reg_address(machine_reg::x26));
static_assert(machine_reg_address(machine_reg::x0, 27) == machine_reg_address(machine_reg::x27));
static_assert(machine_reg_address(machine_reg::x0, 28) == machine_reg_address(machine_reg::x28));
static_assert(machine_reg_address(machine_reg::x0, 29) == machine_reg_address(machine_reg::x29));
static_assert(machine_reg_address(machine_reg::x0, 30) == machine_reg_address(machine_reg::x30));
static_assert(machine_reg_address(machine_reg::x0, 31) == machine_reg_address(machine_reg::x31));

static_assert(machine_reg_address(machine_reg::f0, 1) == machine_reg_address(machine_reg::f1));
static_assert(machine_reg_address(machine_reg::f0, 2) == machine_reg_address(machine_reg::f2));
static_assert(machine_reg_address(machine_reg::f0, 3) == machine_reg_address(machine_reg::f3));
static_assert(machine_reg_address(machine_reg::f0, 4) == machine_reg_address(machine_reg::f4));
static_assert(machine_reg_address(machine_reg::f0, 5) == machine_reg_address(machine_reg::f5));
static_assert(machine_reg_address(machine_reg::f0, 6) == machine_reg_address(machine_reg::f6));
static_assert(machine_reg_address(machine_reg::f0, 7) == machine_reg_address(machine_reg::f7));
static_assert(machine_reg_address(machine_reg::f0, 8) == machine_reg_address(machine_reg::f8));
static_assert(machine_reg_address(machine_reg::f0, 9) == machine_reg_address(machine_reg::f9));
static_assert(machine_reg_address(machine_reg::f0, 10) == machine_reg_address(machine_reg::f10));
static_assert(machine_reg_address(machine_reg::f0, 11) == machine_reg_address(machine_reg::f11));
static_assert(machine_reg_address(machine_reg::f0, 12) == machine_reg_address(machine_reg::f12));
static_assert(machine_reg_address(machine_reg::f0, 13) == machine_reg_address(machine_reg::f13));
static_assert(machine_reg_address(machine_reg::f0, 14) == machine_reg_address(machine_reg::f14));
static_assert(machine_reg_address(machine_reg::f0, 15) == machine_reg_address(machine_reg::f15));
static_assert(machine_reg_address(machine_reg::f0, 16) == machine_reg_address(machine_reg::f16));
static_assert(machine_reg_address(machine_reg::f0, 17) == machine_reg_address(machine_reg::f17));
static_assert(machine_reg_address(machine_reg::f0, 18) == machine_reg_address(machine_reg::f18));
static_assert(machine_reg_address(machine_reg::f0, 19) == machine_reg_address(machine_reg::f19));
static_assert(machine_reg_address(machine_reg::f0, 20) == machine_reg_address(machine_reg::f20));
static_assert(machine_reg_address(machine_reg::f0, 21) == machine_reg_address(machine_reg::f21));
static_assert(machine_reg_address(machine_reg::f0, 22) == machine_reg_address(machine_reg::f22));
static_assert(machine_reg_address(machine_reg::f0, 23) == machine_reg_address(machine_reg::f23));
static_assert(machine_reg_address(machine_reg::f0, 24) == machine_reg_address(machine_reg::f24));
static_assert(machine_reg_address(machine_reg::f0, 25) == machine_reg_address(machine_reg::f25));
static_assert(machine_reg_address(machine_reg::f0, 26) == machine_reg_address(machine_reg::f26));
static_assert(machine_reg_address(machine_reg::f0, 27) == machine_reg_address(machine_reg::f27));
static_assert(machine_reg_address(machine_reg::f0, 28) == machine_reg_address(machine_reg::f28));
static_assert(machine_reg_address(machine_reg::f0, 29) == machine_reg_address(machine_reg::f29));
static_assert(machine_reg_address(machine_reg::f0, 30) == machine_reg_address(machine_reg::f30));
static_assert(machine_reg_address(machine_reg::f0, 31) == machine_reg_address(machine_reg::f31));

static_assert(machine_reg_address(machine_reg::uarch_x0, 1) == machine_reg_address(machine_reg::uarch_x1));
static_assert(machine_reg_address(machine_reg::uarch_x0, 2) == machine_reg_address(machine_reg::uarch_x2));
static_assert(machine_reg_address(machine_reg::uarch_x0, 3) == machine_reg_address(machine_reg::uarch_x3));
static_assert(machine_reg_address(machine_reg::uarch_x0, 4) == machine_reg_address(machine_reg::uarch_x4));
static_assert(machine_reg_address(machine_reg::uarch_x0, 5) == machine_reg_address(machine_reg::uarch_x5));
static_assert(machine_reg_address(machine_reg::uarch_x0, 6) == machine_reg_address(machine_reg::uarch_x6));
static_assert(machine_reg_address(machine_reg::uarch_x0, 7) == machine_reg_address(machine_reg::uarch_x7));
static_assert(machine_reg_address(machine_reg::uarch_x0, 8) == machine_reg_address(machine_reg::uarch_x8));
static_assert(machine_reg_address(machine_reg::uarch_x0, 9) == machine_reg_address(machine_reg::uarch_x9));
static_assert(machine_reg_address(machine_reg::uarch_x0, 10) == machine_reg_address(machine_reg::uarch_x10));
static_assert(machine_reg_address(machine_reg::uarch_x0, 11) == machine_reg_address(machine_reg::uarch_x11));
static_assert(machine_reg_address(machine_reg::uarch_x0, 12) == machine_reg_address(machine_reg::uarch_x12));
static_assert(machine_reg_address(machine_reg::uarch_x0, 13) == machine_reg_address(machine_reg::uarch_x13));
static_assert(machine_reg_address(machine_reg::uarch_x0, 14) == machine_reg_address(machine_reg::uarch_x14));
static_assert(machine_reg_address(machine_reg::uarch_x0, 15) == machine_reg_address(machine_reg::uarch_x15));
static_assert(machine_reg_address(machine_reg::uarch_x0, 16) == machine_reg_address(machine_reg::uarch_x16));
static_assert(machine_reg_address(machine_reg::uarch_x0, 17) == machine_reg_address(machine_reg::uarch_x17));
static_assert(machine_reg_address(machine_reg::uarch_x0, 18) == machine_reg_address(machine_reg::uarch_x18));
static_assert(machine_reg_address(machine_reg::uarch_x0, 19) == machine_reg_address(machine_reg::uarch_x19));
static_assert(machine_reg_address(machine_reg::uarch_x0, 20) == machine_reg_address(machine_reg::uarch_x20));
static_assert(machine_reg_address(machine_reg::uarch_x0, 21) == machine_reg_address(machine_reg::uarch_x21));
static_assert(machine_reg_address(machine_reg::uarch_x0, 22) == machine_reg_address(machine_reg::uarch_x22));
static_assert(machine_reg_address(machine_reg::uarch_x0, 23) == machine_reg_address(machine_reg::uarch_x23));
static_assert(machine_reg_address(machine_reg::uarch_x0, 24) == machine_reg_address(machine_reg::uarch_x24));
static_assert(machine_reg_address(machine_reg::uarch_x0, 25) == machine_reg_address(machine_reg::uarch_x25));
static_assert(machine_reg_address(machine_reg::uarch_x0, 26) == machine_reg_address(machine_reg::uarch_x26));
static_assert(machine_reg_address(machine_reg::uarch_x0, 27) == machine_reg_address(machine_reg::uarch_x27));
static_assert(machine_reg_address(machine_reg::uarch_x0, 28) == machine_reg_address(machine_reg::uarch_x28));
static_assert(machine_reg_address(machine_reg::uarch_x0, 29) == machine_reg_address(machine_reg::uarch_x29));
static_assert(machine_reg_address(machine_reg::uarch_x0, 30) == machine_reg_address(machine_reg::uarch_x30));
static_assert(machine_reg_address(machine_reg::uarch_x0, 31) == machine_reg_address(machine_reg::uarch_x31));

} // namespace cartesi

#endif // MACHINE_REG_H
