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

#include "shadow-state-address-range.h"
#include "shadow-uarch-state-address-range.h"

/// \file
/// \brief Cartesi machine registers

namespace cartesi {

/// \brief List of machine registers
enum class machine_reg : uint64_t {
    x0 = static_cast<uint64_t>(shadow_state_what::x0),
    x1 = static_cast<uint64_t>(shadow_state_what::x1),
    x2 = static_cast<uint64_t>(shadow_state_what::x2),
    x3 = static_cast<uint64_t>(shadow_state_what::x3),
    x4 = static_cast<uint64_t>(shadow_state_what::x4),
    x5 = static_cast<uint64_t>(shadow_state_what::x5),
    x6 = static_cast<uint64_t>(shadow_state_what::x6),
    x7 = static_cast<uint64_t>(shadow_state_what::x7),
    x8 = static_cast<uint64_t>(shadow_state_what::x8),
    x9 = static_cast<uint64_t>(shadow_state_what::x9),
    x10 = static_cast<uint64_t>(shadow_state_what::x10),
    x11 = static_cast<uint64_t>(shadow_state_what::x11),
    x12 = static_cast<uint64_t>(shadow_state_what::x12),
    x13 = static_cast<uint64_t>(shadow_state_what::x13),
    x14 = static_cast<uint64_t>(shadow_state_what::x14),
    x15 = static_cast<uint64_t>(shadow_state_what::x15),
    x16 = static_cast<uint64_t>(shadow_state_what::x16),
    x17 = static_cast<uint64_t>(shadow_state_what::x17),
    x18 = static_cast<uint64_t>(shadow_state_what::x18),
    x19 = static_cast<uint64_t>(shadow_state_what::x19),
    x20 = static_cast<uint64_t>(shadow_state_what::x20),
    x21 = static_cast<uint64_t>(shadow_state_what::x21),
    x22 = static_cast<uint64_t>(shadow_state_what::x22),
    x23 = static_cast<uint64_t>(shadow_state_what::x23),
    x24 = static_cast<uint64_t>(shadow_state_what::x24),
    x25 = static_cast<uint64_t>(shadow_state_what::x25),
    x26 = static_cast<uint64_t>(shadow_state_what::x26),
    x27 = static_cast<uint64_t>(shadow_state_what::x27),
    x28 = static_cast<uint64_t>(shadow_state_what::x28),
    x29 = static_cast<uint64_t>(shadow_state_what::x29),
    x30 = static_cast<uint64_t>(shadow_state_what::x30),
    x31 = static_cast<uint64_t>(shadow_state_what::x31),
    f0 = static_cast<uint64_t>(shadow_state_what::f0),
    f1 = static_cast<uint64_t>(shadow_state_what::f1),
    f2 = static_cast<uint64_t>(shadow_state_what::f2),
    f3 = static_cast<uint64_t>(shadow_state_what::f3),
    f4 = static_cast<uint64_t>(shadow_state_what::f4),
    f5 = static_cast<uint64_t>(shadow_state_what::f5),
    f6 = static_cast<uint64_t>(shadow_state_what::f6),
    f7 = static_cast<uint64_t>(shadow_state_what::f7),
    f8 = static_cast<uint64_t>(shadow_state_what::f8),
    f9 = static_cast<uint64_t>(shadow_state_what::f9),
    f10 = static_cast<uint64_t>(shadow_state_what::f10),
    f11 = static_cast<uint64_t>(shadow_state_what::f11),
    f12 = static_cast<uint64_t>(shadow_state_what::f12),
    f13 = static_cast<uint64_t>(shadow_state_what::f13),
    f14 = static_cast<uint64_t>(shadow_state_what::f14),
    f15 = static_cast<uint64_t>(shadow_state_what::f15),
    f16 = static_cast<uint64_t>(shadow_state_what::f16),
    f17 = static_cast<uint64_t>(shadow_state_what::f17),
    f18 = static_cast<uint64_t>(shadow_state_what::f18),
    f19 = static_cast<uint64_t>(shadow_state_what::f19),
    f20 = static_cast<uint64_t>(shadow_state_what::f20),
    f21 = static_cast<uint64_t>(shadow_state_what::f21),
    f22 = static_cast<uint64_t>(shadow_state_what::f22),
    f23 = static_cast<uint64_t>(shadow_state_what::f23),
    f24 = static_cast<uint64_t>(shadow_state_what::f24),
    f25 = static_cast<uint64_t>(shadow_state_what::f25),
    f26 = static_cast<uint64_t>(shadow_state_what::f26),
    f27 = static_cast<uint64_t>(shadow_state_what::f27),
    f28 = static_cast<uint64_t>(shadow_state_what::f28),
    f29 = static_cast<uint64_t>(shadow_state_what::f29),
    f30 = static_cast<uint64_t>(shadow_state_what::f30),
    f31 = static_cast<uint64_t>(shadow_state_what::f31),
    pc = static_cast<uint64_t>(shadow_state_what::pc),
    fcsr = static_cast<uint64_t>(shadow_state_what::fcsr),
    mvendorid = static_cast<uint64_t>(shadow_state_what::mvendorid),
    marchid = static_cast<uint64_t>(shadow_state_what::marchid),
    mimpid = static_cast<uint64_t>(shadow_state_what::mimpid),
    mcycle = static_cast<uint64_t>(shadow_state_what::mcycle),
    icycleinstret = static_cast<uint64_t>(shadow_state_what::icycleinstret),
    mstatus = static_cast<uint64_t>(shadow_state_what::mstatus),
    mtvec = static_cast<uint64_t>(shadow_state_what::mtvec),
    mscratch = static_cast<uint64_t>(shadow_state_what::mscratch),
    mepc = static_cast<uint64_t>(shadow_state_what::mepc),
    mcause = static_cast<uint64_t>(shadow_state_what::mcause),
    mtval = static_cast<uint64_t>(shadow_state_what::mtval),
    misa = static_cast<uint64_t>(shadow_state_what::misa),
    mie = static_cast<uint64_t>(shadow_state_what::mie),
    mip = static_cast<uint64_t>(shadow_state_what::mip),
    medeleg = static_cast<uint64_t>(shadow_state_what::medeleg),
    mideleg = static_cast<uint64_t>(shadow_state_what::mideleg),
    mcounteren = static_cast<uint64_t>(shadow_state_what::mcounteren),
    menvcfg = static_cast<uint64_t>(shadow_state_what::menvcfg),
    stvec = static_cast<uint64_t>(shadow_state_what::stvec),
    sscratch = static_cast<uint64_t>(shadow_state_what::sscratch),
    sepc = static_cast<uint64_t>(shadow_state_what::sepc),
    scause = static_cast<uint64_t>(shadow_state_what::scause),
    stval = static_cast<uint64_t>(shadow_state_what::stval),
    satp = static_cast<uint64_t>(shadow_state_what::satp),
    scounteren = static_cast<uint64_t>(shadow_state_what::scounteren),
    senvcfg = static_cast<uint64_t>(shadow_state_what::senvcfg),
    ilrsc = static_cast<uint64_t>(shadow_state_what::ilrsc),
    iprv = static_cast<uint64_t>(shadow_state_what::iprv),
    iflags_X = static_cast<uint64_t>(shadow_state_what::iflags_X),
    iflags_Y = static_cast<uint64_t>(shadow_state_what::iflags_Y),
    iflags_H = static_cast<uint64_t>(shadow_state_what::iflags_H),
    iunrep = static_cast<uint64_t>(shadow_state_what::iunrep),
    clint_mtimecmp = static_cast<uint64_t>(shadow_state_what::clint_mtimecmp),
    plic_girqpend = static_cast<uint64_t>(shadow_state_what::plic_girqpend),
    plic_girqsrvd = static_cast<uint64_t>(shadow_state_what::plic_girqsrvd),
    htif_tohost = static_cast<uint64_t>(shadow_state_what::htif_tohost),
    htif_fromhost = static_cast<uint64_t>(shadow_state_what::htif_fromhost),
    htif_ihalt = static_cast<uint64_t>(shadow_state_what::htif_ihalt),
    htif_iconsole = static_cast<uint64_t>(shadow_state_what::htif_iconsole),
    htif_iyield = static_cast<uint64_t>(shadow_state_what::htif_iyield),
    first_ = x0,
    last_ = htif_iyield,

    uarch_halt_flag = static_cast<uint64_t>(shadow_uarch_state_what::uarch_halt_flag),
    uarch_cycle = static_cast<uint64_t>(shadow_uarch_state_what::uarch_cycle),
    uarch_pc = static_cast<uint64_t>(shadow_uarch_state_what::uarch_pc),
    uarch_x0 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x0),
    uarch_x1 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x1),
    uarch_x2 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x2),
    uarch_x3 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x3),
    uarch_x4 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x4),
    uarch_x5 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x5),
    uarch_x6 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x6),
    uarch_x7 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x7),
    uarch_x8 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x8),
    uarch_x9 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x9),
    uarch_x10 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x10),
    uarch_x11 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x11),
    uarch_x12 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x12),
    uarch_x13 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x13),
    uarch_x14 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x14),
    uarch_x15 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x15),
    uarch_x16 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x16),
    uarch_x17 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x17),
    uarch_x18 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x18),
    uarch_x19 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x19),
    uarch_x20 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x20),
    uarch_x21 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x21),
    uarch_x22 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x22),
    uarch_x23 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x23),
    uarch_x24 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x24),
    uarch_x25 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x25),
    uarch_x26 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x26),
    uarch_x27 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x27),
    uarch_x28 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x28),
    uarch_x29 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x29),
    uarch_x30 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x30),
    uarch_x31 = static_cast<uint64_t>(shadow_uarch_state_what::uarch_x31),
    uarch_first_ = uarch_halt_flag,
    uarch_last_ = uarch_x31,

    // Something unknown
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space

    // Views of registers
    htif_tohost_dev,
    htif_tohost_cmd,
    htif_tohost_reason,
    htif_tohost_data,
    htif_fromhost_dev,
    htif_fromhost_cmd,
    htif_fromhost_reason,
    htif_fromhost_data,
    view_first_ = htif_tohost_dev,
    view_last_ = htif_fromhost_data,

};

static constexpr uint64_t machine_reg_address(machine_reg reg, int i = 0) {
    return static_cast<uint64_t>(reg) + (i * sizeof(uint64_t));
}

static constexpr machine_reg machine_reg_enum(machine_reg reg, int i) {
    return static_cast<machine_reg>(static_cast<uint64_t>(reg) + (i * sizeof(uint64_t)));
}

static constexpr machine_reg machine_reg_enum(shadow_state_what reg) {
    return static_cast<machine_reg>(reg);
}

static constexpr machine_reg machine_reg_enum(shadow_uarch_state_what reg) {
    return static_cast<machine_reg>(reg);
}

static constexpr const char *machine_reg_get_name(machine_reg reg) {
    const auto ureg = static_cast<uint64_t>(reg);
    if (ureg >= static_cast<uint64_t>(machine_reg::first_) && ureg <= static_cast<uint64_t>(machine_reg::last_)) {
        return shadow_state_get_what_name(static_cast<shadow_state_what>(reg));
    }
    if (ureg >= static_cast<uint64_t>(machine_reg::uarch_first_) &&
        ureg <= static_cast<uint64_t>(machine_reg::uarch_last_)) {
        return shadow_uarch_state_get_what_name(static_cast<shadow_uarch_state_what>(reg));
    }
    switch (reg) {
        case machine_reg::htif_tohost_dev:
            return "htif.tohost_dev";
        case machine_reg::htif_tohost_cmd:
            return "htif.tohost_cmd";
        case machine_reg::htif_tohost_reason:
            return "htif.tohost_reason";
        case machine_reg::htif_tohost_data:
            return "htif.tohost_data";
        case machine_reg::htif_fromhost_dev:
            return "htif.fromhost_dev";
        case machine_reg::htif_fromhost_cmd:
            return "htif.fromhost_cmd";
        case machine_reg::htif_fromhost_reason:
            return "htif.fromhost_reason";
        case machine_reg::htif_fromhost_data:
            return "htif.fromhost_data";
        case machine_reg::unknown_:
            [[fallthrough]];
        default:
            return "unknown";
    }
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
