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

#include "pma-driver.h"
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

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
    uint64_t hstatus;
    uint64_t hideleg;
    uint64_t hedeleg;
    uint64_t hie;
    uint64_t hip;
    uint64_t hvip;
    uint64_t hgatp;
    uint64_t henvcfg;
    uint64_t htimedelta;
    uint64_t htval;
    uint64_t vsepc;
    uint64_t vsstatus;
    uint64_t vscause;
    uint64_t vstval;
    uint64_t vstvec;
    uint64_t vsscratch;
    uint64_t vsatp;
    uint64_t vsie;
    uint64_t vsip;
    uint64_t ilrsc;
    uint64_t iflags;
    uint64_t clint_mtimecmp;
    uint64_t htif_tohost;
    uint64_t htif_fromhost;
    uint64_t htif_ihalt;
    uint64_t htif_iconsole;
    uint64_t htif_iyield;
    uint64_t uarch_cycle;
    uint64_t uarch_halt_flag;
    uint64_t uarch_pc;
    uint64_t uarch_ram_length;
    uint64_t uarch_x[UARCH_X_REG_COUNT];
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
    hstatus = offsetof(shadow_state, hstatus),
    hideleg = offsetof(shadow_state, hideleg),
    hedeleg = offsetof(shadow_state, hedeleg),
    hie = offsetof(shadow_state, hie),
    hip = offsetof(shadow_state, hip),
    hvip = offsetof(shadow_state, hvip),
    hgatp = offsetof(shadow_state, hgatp),
    henvcfg = offsetof(shadow_state, henvcfg),
    htimedelta = offsetof(shadow_state, htimedelta),
    htval = offsetof(shadow_state, htval),
    vsepc = offsetof(shadow_state, vsepc),
    vsstatus = offsetof(shadow_state, vsstatus),
    vscause = offsetof(shadow_state, vscause),
    vstval = offsetof(shadow_state, vstval),
    vstvec = offsetof(shadow_state, vstvec),
    vsscratch = offsetof(shadow_state, vsscratch),
    vsatp = offsetof(shadow_state, vsatp),
    vsie = offsetof(shadow_state, vsie),
    vsip = offsetof(shadow_state, vsip),
    ilrsc = offsetof(shadow_state, ilrsc),
    iflags = offsetof(shadow_state, iflags),
    clint_mtimecmp = offsetof(shadow_state, clint_mtimecmp),
    htif_tohost = offsetof(shadow_state, htif_tohost),
    htif_fromhost = offsetof(shadow_state, htif_fromhost),
    htif_ihalt = offsetof(shadow_state, htif_ihalt),
    htif_iconsole = offsetof(shadow_state, htif_iconsole),
    htif_iyield = offsetof(shadow_state, htif_iyield),
    uarch_cycle = offsetof(shadow_state, uarch_cycle),
    uarch_halt_flag = offsetof(shadow_state, uarch_halt_flag),
    uarch_ram_length = offsetof(shadow_state, uarch_ram_length),
    uarch_pc = offsetof(shadow_state, uarch_pc),
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

/// \brief Obtains the relative address of a microarchitecture general purpose register
static inline uint64_t shadow_state_get_uarch_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < UARCH_X_REG_COUNT);
    return offsetof(shadow_state, uarch_x) + reg * sizeof(uint64_t);
}

/// \brief Obtains the absolute address of a microarchitecture general purpose register
static inline uint64_t shadow_state_get_uarch_x_abs_addr(int reg) {
    return PMA_SHADOW_STATE_START + shadow_state_get_uarch_x_rel_addr(reg);
}

/// \brief Absolute address of shadow_csr::uarch_ram_length. This symbol is used by the microarchitecture boostrap to
/// detect the RAM size
extern "C" const uint64_t shadow_state_uarch_ram_length_abs_addr;

} // namespace cartesi

#endif
