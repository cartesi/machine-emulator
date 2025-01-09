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

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "compiler-defines.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow device.

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

/// \brief Global instance of the processor shadow device driver.
extern const pma_driver shadow_state_driver;

} // namespace cartesi

#endif
