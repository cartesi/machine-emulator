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

enum class shadow_uarch_state_what : uint64_t {
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
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

static constexpr shadow_uarch_state_what shadow_uarch_state_get_what(uint64_t paddr) {
    if (paddr < PMA_SHADOW_UARCH_STATE_START || paddr - PMA_SHADOW_UARCH_STATE_START >= sizeof(shadow_uarch_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return shadow_uarch_state_what::unknown_;
    }
    return static_cast<shadow_uarch_state_what>(paddr);
}

static constexpr shadow_uarch_state_what shadow_uarch_state_get_what(shadow_uarch_state_what what, int i) {
    return static_cast<shadow_uarch_state_what>(static_cast<uint64_t>(what) + i * sizeof(uint64_t));
}

static constexpr const char *shadow_uarch_state_get_what_name(shadow_uarch_state_what what) {
    const auto paddr = static_cast<uint64_t>(what);
    if (paddr < PMA_SHADOW_UARCH_STATE_START || paddr - PMA_SHADOW_UARCH_STATE_START >= sizeof(shadow_uarch_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return "uarch.unknown";
    }
    using reg = shadow_uarch_state_what;
    switch (what) {
        case reg::uarch_halt_flag:
            return "uarch.halt_flag";
        case reg::uarch_cycle:
            return "uarch.cycle";
        case reg::uarch_pc:
            return "uarch.pc";
        case reg::uarch_x0:
            return "uarch.x0";
        case reg::uarch_x1:
            return "uarch.x1";
        case reg::uarch_x2:
            return "uarch.x2";
        case reg::uarch_x3:
            return "uarch.x3";
        case reg::uarch_x4:
            return "uarch.x4";
        case reg::uarch_x5:
            return "uarch.x5";
        case reg::uarch_x6:
            return "uarch.x6";
        case reg::uarch_x7:
            return "uarch.x7";
        case reg::uarch_x8:
            return "uarch.x8";
        case reg::uarch_x9:
            return "uarch.x9";
        case reg::uarch_x10:
            return "uarch.x10";
        case reg::uarch_x11:
            return "uarch.x11";
        case reg::uarch_x12:
            return "uarch.x12";
        case reg::uarch_x13:
            return "uarch.x13";
        case reg::uarch_x14:
            return "uarch.x14";
        case reg::uarch_x15:
            return "uarch.x15";
        case reg::uarch_x16:
            return "uarch.x16";
        case reg::uarch_x17:
            return "uarch.x17";
        case reg::uarch_x18:
            return "uarch.x18";
        case reg::uarch_x19:
            return "uarch.x19";
        case reg::uarch_x20:
            return "uarch.x20";
        case reg::uarch_x21:
            return "uarch.x21";
        case reg::uarch_x22:
            return "uarch.x22";
        case reg::uarch_x23:
            return "uarch.x23";
        case reg::uarch_x24:
            return "uarch.x24";
        case reg::uarch_x25:
            return "uarch.x25";
        case reg::uarch_x26:
            return "uarch.x26";
        case reg::uarch_x27:
            return "uarch.x27";
        case reg::uarch_x28:
            return "uarch.x28";
        case reg::uarch_x29:
            return "uarch.x29";
        case reg::uarch_x30:
            return "uarch.x30";
        case reg::uarch_x31:
            return "uarch.x31";
        case reg::unknown_:
            return "uarch.unknown_";
    }
}

/// \brief Global instance of  theprocessor shadow uarch state device driver.
extern const pma_driver shadow_uarch_state_driver;

} // namespace cartesi

#endif
