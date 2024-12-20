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

#ifndef SHADOW_UARCH_STATE_H
#define SHADOW_UARCH_STATE_H

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "compiler-defines.h"
#include "machine-reg.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow uarch state device.

namespace cartesi {

/// \brief Shadow uarch memory layout
struct PACKED shadow_uarch_state {
    uint64_t halt_flag;
    uint64_t cycle;
    uint64_t pc;
    uint64_t x[UARCH_X_REG_COUNT];
};

/// \brief Global instance of  theprocessor shadow uarch state device driver.
extern const pma_driver shadow_uarch_state_driver;

/// \brief Mapping between registers and their relative addresses in shadow uarch state memory
enum class shadow_uarch_state_reg_rel_addr : uint64_t {
    uarch_halt_flag = offsetof(shadow_uarch_state, halt_flag),
    uarch_cycle = offsetof(shadow_uarch_state, cycle),
    uarch_pc = offsetof(shadow_uarch_state, pc),
    uarch_x0 = offsetof(shadow_uarch_state, x[0]),
    uarch_x1 = offsetof(shadow_uarch_state, x[1]),
    uarch_x2 = offsetof(shadow_uarch_state, x[2]),
    uarch_x3 = offsetof(shadow_uarch_state, x[3]),
    uarch_x4 = offsetof(shadow_uarch_state, x[4]),
    uarch_x5 = offsetof(shadow_uarch_state, x[5]),
    uarch_x6 = offsetof(shadow_uarch_state, x[6]),
    uarch_x7 = offsetof(shadow_uarch_state, x[7]),
    uarch_x8 = offsetof(shadow_uarch_state, x[8]),
    uarch_x9 = offsetof(shadow_uarch_state, x[9]),
    uarch_x10 = offsetof(shadow_uarch_state, x[10]),
    uarch_x11 = offsetof(shadow_uarch_state, x[11]),
    uarch_x12 = offsetof(shadow_uarch_state, x[12]),
    uarch_x13 = offsetof(shadow_uarch_state, x[13]),
    uarch_x14 = offsetof(shadow_uarch_state, x[14]),
    uarch_x15 = offsetof(shadow_uarch_state, x[15]),
    uarch_x16 = offsetof(shadow_uarch_state, x[16]),
    uarch_x17 = offsetof(shadow_uarch_state, x[17]),
    uarch_x18 = offsetof(shadow_uarch_state, x[18]),
    uarch_x19 = offsetof(shadow_uarch_state, x[19]),
    uarch_x20 = offsetof(shadow_uarch_state, x[20]),
    uarch_x21 = offsetof(shadow_uarch_state, x[21]),
    uarch_x22 = offsetof(shadow_uarch_state, x[22]),
    uarch_x23 = offsetof(shadow_uarch_state, x[23]),
    uarch_x24 = offsetof(shadow_uarch_state, x[24]),
    uarch_x25 = offsetof(shadow_uarch_state, x[25]),
    uarch_x26 = offsetof(shadow_uarch_state, x[26]),
    uarch_x27 = offsetof(shadow_uarch_state, x[27]),
    uarch_x28 = offsetof(shadow_uarch_state, x[28]),
    uarch_x29 = offsetof(shadow_uarch_state, x[29]),
    uarch_x30 = offsetof(shadow_uarch_state, x[30]),
    uarch_x31 = offsetof(shadow_uarch_state, x[31]),
};

/// \brief Obtains the relative address of a register in shadow uarch state memory.
/// \param r Register name.
/// \returns The address.
static inline uint64_t shadow_uarch_state_get_reg_rel_addr(machine_reg r) {
    using reg = machine_reg;
    switch (r) {
        case reg::uarch_halt_flag:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_halt_flag);
        case reg::uarch_cycle:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_cycle);
        case reg::uarch_pc:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_pc);
        case reg::uarch_x0:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x0);
        case reg::uarch_x1:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x1);
        case reg::uarch_x2:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x2);
        case reg::uarch_x3:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x3);
        case reg::uarch_x4:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x4);
        case reg::uarch_x5:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x5);
        case reg::uarch_x6:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x6);
        case reg::uarch_x7:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x7);
        case reg::uarch_x8:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x8);
        case reg::uarch_x9:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x9);
        case reg::uarch_x10:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x10);
        case reg::uarch_x11:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x11);
        case reg::uarch_x12:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x12);
        case reg::uarch_x13:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x13);
        case reg::uarch_x14:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x14);
        case reg::uarch_x15:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x15);
        case reg::uarch_x16:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x16);
        case reg::uarch_x17:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x17);
        case reg::uarch_x18:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x18);
        case reg::uarch_x19:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x19);
        case reg::uarch_x20:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x20);
        case reg::uarch_x21:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x21);
        case reg::uarch_x22:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x22);
        case reg::uarch_x23:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x23);
        case reg::uarch_x24:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x24);
        case reg::uarch_x25:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x25);
        case reg::uarch_x26:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x26);
        case reg::uarch_x27:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x27);
        case reg::uarch_x28:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x28);
        case reg::uarch_x29:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x29);
        case reg::uarch_x30:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x30);
        case reg::uarch_x31:
            return static_cast<uint64_t>(shadow_uarch_state_reg_rel_addr::uarch_x31);
        default:
            assert(0);
            return 0;
    }
}

/// \brief Obtains the absolute address of a register in shadow uarch state memory.
/// \param reg Register name.
static inline uint64_t shadow_uarch_state_get_reg_abs_addr(machine_reg reg) {
    return PMA_SHADOW_UARCH_STATE_START + shadow_uarch_state_get_reg_rel_addr(reg);
}

/// \brief Obtains the relative address of a microarchitecture general purpose register in shadow uarch state memory
/// \param reg Register index in 0...31, for x0...x31, respectively.
static inline uint64_t shadow_uarch_state_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < UARCH_X_REG_COUNT);
    return offsetof(shadow_uarch_state, x) + reg * sizeof(uint64_t);
}

/// \brief Obtains the absolute address of a microarchitecture general purpose register in shadow uarch state memory
/// \param reg Register index in 0...31, for x0...x31, respectively.
static inline uint64_t shadow_uarch_state_get_x_abs_addr(int reg) {
    return PMA_SHADOW_UARCH_STATE_START + shadow_uarch_state_get_x_rel_addr(reg);
}

} // namespace cartesi

#endif
