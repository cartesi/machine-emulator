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

#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow uarch state device.

namespace cartesi {

/// \brief Shadow uarch memory layout
#pragma pack(push, 1)
struct shadow_uarch_state {
    uint64_t halt_flag;
    uint64_t cycle;
    uint64_t pc;
    uint64_t x[UARCH_X_REG_COUNT];
};
#pragma pack(pop)

/// \brief Global instance of  theprocessor shadow uarch state device driver.
extern const pma_driver shadow_uarch_state_driver;

/// \brief Mapping between registers and their relative addresses in shadow uarch state memory
enum class shadow_uarch_state_reg {
    halt_flag = offsetof(shadow_uarch_state, halt_flag),
    cycle = offsetof(shadow_uarch_state, cycle),
    pc = offsetof(shadow_uarch_state, pc),
    x0 = offsetof(shadow_uarch_state, x[0]),
    x1 = offsetof(shadow_uarch_state, x[1]),
    x2 = offsetof(shadow_uarch_state, x[2]),
    x3 = offsetof(shadow_uarch_state, x[3]),
    x4 = offsetof(shadow_uarch_state, x[4]),
    x5 = offsetof(shadow_uarch_state, x[5]),
    x6 = offsetof(shadow_uarch_state, x[6]),
    x7 = offsetof(shadow_uarch_state, x[7]),
    x8 = offsetof(shadow_uarch_state, x[8]),
    x9 = offsetof(shadow_uarch_state, x[9]),
    x10 = offsetof(shadow_uarch_state, x[10]),
    x11 = offsetof(shadow_uarch_state, x[11]),
    x12 = offsetof(shadow_uarch_state, x[12]),
    x13 = offsetof(shadow_uarch_state, x[13]),
    x14 = offsetof(shadow_uarch_state, x[14]),
    x15 = offsetof(shadow_uarch_state, x[15]),
    x16 = offsetof(shadow_uarch_state, x[16]),
    x17 = offsetof(shadow_uarch_state, x[17]),
    x18 = offsetof(shadow_uarch_state, x[18]),
    x19 = offsetof(shadow_uarch_state, x[19]),
    x20 = offsetof(shadow_uarch_state, x[20]),
    x21 = offsetof(shadow_uarch_state, x[21]),
    x22 = offsetof(shadow_uarch_state, x[22]),
    x23 = offsetof(shadow_uarch_state, x[23]),
    x24 = offsetof(shadow_uarch_state, x[24]),
    x25 = offsetof(shadow_uarch_state, x[25]),
    x26 = offsetof(shadow_uarch_state, x[26]),
    x27 = offsetof(shadow_uarch_state, x[27]),
    x28 = offsetof(shadow_uarch_state, x[28]),
    x29 = offsetof(shadow_uarch_state, x[29]),
    x30 = offsetof(shadow_uarch_state, x[30]),
    x31 = offsetof(shadow_uarch_state, x[31]),
};

/// \brief Obtains the relative address of a register in shadow uarch state memory.
/// \param reg Register name.
/// \returns The address.
constexpr uint64_t shadow_uarch_state_get_reg_rel_addr(shadow_uarch_state_reg reg) {
    return static_cast<uint64_t>(reg);
}

/// \brief Obtains the absolute address of a register in shadow uarch state memory.
constexpr uint64_t shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg reg) {
    return PMA_SHADOW_UARCH_STATE_START + shadow_uarch_state_get_reg_rel_addr(reg);
}

/// \brief Obtains the relative address of a general purpose uarch register
/// in shadow uarch state memory.
/// \param reg Register index in 0...31, for x0...x31, respectively.
/// \brief Obtains the relative address of a microarchitecture general purpose register in shadow uarch state memory
static inline uint64_t shadow_uarch_state_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < UARCH_X_REG_COUNT);
    return offsetof(shadow_uarch_state, x) + reg * sizeof(uint64_t);
}

/// \brief Obtains the absolute address of a microarchitecture general purpose register
static inline uint64_t shadow_uarch_state_get_x_abs_addr(int reg) {
    return PMA_SHADOW_UARCH_STATE_START + shadow_uarch_state_get_x_rel_addr(reg);
}

} // namespace cartesi

#endif
