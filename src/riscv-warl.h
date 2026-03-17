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

#ifndef RISCV_WARL_H
#define RISCV_WARL_H

/// \file
/// \brief WARL (Write Any Read Legal) register legalization functions.
/// \details These functions ensure WARL registers always hold legal values,
/// even if written with arbitrary data through external APIs.

#include <cstdint>

#include "riscv-constants.h"

namespace cartesi {

constexpr uint64_t WARL_mstatus(uint64_t val) {
    val &= MSTATUS_R_MASK;
    if (PRV_HS == ((val & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT)) {
        val &= ~MSTATUS_MPP_MASK;
    }
    if ((val & MSTATUS_FS_MASK) != MSTATUS_FS_OFF) {
        val |= MSTATUS_FS_DIRTY;
        val |= MSTATUS_SD_MASK;
    } else {
        val &= ~MSTATUS_SD_MASK;
    }
    return val;
}

constexpr uint64_t WARL_menvcfg(uint64_t val) {
    return val & MENVCFG_R_MASK;
}

constexpr uint64_t WARL_senvcfg(uint64_t val) {
    return val & SENVCFG_R_MASK;
}

constexpr uint64_t WARL_medeleg(uint64_t val) {
    return val & MEDELEG_W_MASK;
}

constexpr uint64_t WARL_mideleg(uint64_t val) {
    return val & MIP_S_RW_MASK;
}

constexpr uint64_t WARL_mie(uint64_t val) {
    return val & MIP_RW_MASK;
}

constexpr uint64_t WARL_mip(uint64_t val) {
    return val & MIP_RW_MASK;
}

constexpr uint64_t WARL_mtvec(uint64_t val) {
    return val & ~UINT64_C(1);
}

constexpr uint64_t WARL_stvec(uint64_t val) {
    return val & ~UINT64_C(1);
}

constexpr uint64_t WARL_mepc(uint64_t val) {
    return val & ~UINT64_C(1);
}

constexpr uint64_t WARL_sepc(uint64_t val) {
    return val & ~UINT64_C(1);
}

constexpr uint64_t WARL_mcounteren(uint64_t val) {
    return val & MCOUNTEREN_RW_MASK;
}

constexpr uint64_t WARL_scounteren(uint64_t val) {
    return val & SCOUNTEREN_RW_MASK;
}

constexpr uint64_t WARL_satp(uint64_t val) {
    const uint64_t mode = val >> SATP_MODE_SHIFT;
    switch (mode) {
        case SATP_MODE_BARE:
        case SATP_MODE_SV39:
        case SATP_MODE_SV48:
#ifndef NO_SATP_MODE_SV57
        case SATP_MODE_SV57:
#endif
            return val & SATP_RW_MASK;
        default:
            return 0;
    }
}

constexpr uint64_t WARL_fcsr(uint64_t val) {
    return val & FCSR_RW_MASK;
}

} // namespace cartesi

#endif
