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

#include "pma-driver.h"
#include "riscv-constants.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

/// \brief Shadow memory layout
#pragma pack(push, 1)
struct shadow_state {
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
    uint64_t iflags;
    uint64_t clint_mtimecmp;
    uint64_t plic_girqpend;
    uint64_t plic_girqsrvd;
    uint64_t htif_tohost;
    uint64_t htif_fromhost;
    uint64_t htif_ihalt;
    uint64_t htif_iconsole;
    uint64_t htif_iyield;
};
#pragma pack(pop)

/// \brief Global instance of  theprocessor shadow device driver.
extern const pma_driver shadow_state_driver;

/// \brief Mapping between CSRs and their relative addresses in shadow memory
enum class shadow_state_csr {
    pc = offsetof(shadow_state, pc),
    fcsr = offsetof(shadow_state, fcsr),
    mvendorid = offsetof(shadow_state, mvendorid),
    marchid = offsetof(shadow_state, marchid),
    mimpid = offsetof(shadow_state, mimpid),
    mcycle = offsetof(shadow_state, mcycle),
    icycleinstret = offsetof(shadow_state, icycleinstret),
    mstatus = offsetof(shadow_state, mstatus),
    mtvec = offsetof(shadow_state, mtvec),
    mscratch = offsetof(shadow_state, mscratch),
    mepc = offsetof(shadow_state, mepc),
    mcause = offsetof(shadow_state, mcause),
    mtval = offsetof(shadow_state, mtval),
    misa = offsetof(shadow_state, misa),
    mie = offsetof(shadow_state, mie),
    mip = offsetof(shadow_state, mip),
    medeleg = offsetof(shadow_state, medeleg),
    mideleg = offsetof(shadow_state, mideleg),
    mcounteren = offsetof(shadow_state, mcounteren),
    menvcfg = offsetof(shadow_state, menvcfg),
    stvec = offsetof(shadow_state, stvec),
    sscratch = offsetof(shadow_state, sscratch),
    sepc = offsetof(shadow_state, sepc),
    scause = offsetof(shadow_state, scause),
    stval = offsetof(shadow_state, stval),
    satp = offsetof(shadow_state, satp),
    scounteren = offsetof(shadow_state, scounteren),
    senvcfg = offsetof(shadow_state, senvcfg),
    ilrsc = offsetof(shadow_state, ilrsc),
    iflags = offsetof(shadow_state, iflags),
    clint_mtimecmp = offsetof(shadow_state, clint_mtimecmp),
    plic_girqpend = offsetof(shadow_state, plic_girqpend),
    plic_girqsrvd = offsetof(shadow_state, plic_girqsrvd),
    htif_tohost = offsetof(shadow_state, htif_tohost),
    htif_fromhost = offsetof(shadow_state, htif_fromhost),
    htif_ihalt = offsetof(shadow_state, htif_ihalt),
    htif_iconsole = offsetof(shadow_state, htif_iconsole),
    htif_iyield = offsetof(shadow_state, htif_iyield),
};

/// \brief Obtains the relative address of a CSR in shadow memory.
/// \param reg CSR name.
/// \returns The address.
constexpr uint64_t shadow_state_get_csr_rel_addr(shadow_state_csr reg) {
    return static_cast<uint64_t>(reg);
}

/// \brief Obtains the absolute address of a CSR in shadow memory.
constexpr uint64_t shadow_state_get_csr_abs_addr(shadow_state_csr reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_csr_rel_addr(reg);
}

/// \brief Obtains the relative address of a general purpose register
/// in shadow memory.
/// \param reg Register index in 0...31, for x0...x31, respectively.
/// \returns The address.
static inline uint64_t shadow_state_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < X_REG_COUNT);
    return offsetof(shadow_state, x) + reg * sizeof(uint64_t);
}

/// \brief Obtains the absolute address of a general purpose register
static inline uint64_t shadow_state_get_x_abs_addr(int reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_x_rel_addr(reg);
}
/// \brief Obtains the relative address of a floating-point register
static inline uint64_t shadow_state_get_f_rel_addr(int reg) {
    assert(reg >= 0 && reg < F_REG_COUNT);
    return offsetof(shadow_state, f) + reg * sizeof(uint64_t);
}

/// \brief Obtains the absolute address of a floating-point register
static inline uint64_t shadow_state_get_f_abs_addr(int reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_f_rel_addr(reg);
}

} // namespace cartesi

#endif
