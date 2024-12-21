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

} // namespace cartesi

#endif
