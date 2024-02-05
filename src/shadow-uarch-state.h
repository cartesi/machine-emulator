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

/// \brief Mapping between CSRs and their relative addresses in shadow uarch state memory
enum class shadow_uarch_state_csr {
    halt_flag = offsetof(shadow_uarch_state, halt_flag),
    cycle = offsetof(shadow_uarch_state, cycle),
    pc = offsetof(shadow_uarch_state, pc),
};

/// \brief Obtains the relative address of a CSR in shadow uarch state memory.
/// \param reg CSR name.
/// \returns The address.
constexpr uint64_t shadow_uarch_state_get_csr_rel_addr(shadow_uarch_state_csr reg) {
    return static_cast<uint64_t>(reg);
}

/// \brief Obtains the absolute address of a CSR in shadow uarch state memory.
constexpr uint64_t shadow_uarch_state_get_csr_abs_addr(shadow_uarch_state_csr reg) {
    return PMA_SHADOW_UARCH_STATE_START + shadow_uarch_state_get_csr_rel_addr(reg);
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
