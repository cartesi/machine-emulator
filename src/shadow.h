// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef SHADOW_H
#define SHADOW_H

#include <cstdint>

/// \file
/// \brief Shadow device.

namespace cartesi {

// Forward declarations
class machine;

/// \brief Mapping between CSRs and their relative addresses in shadow memory
enum class shadow_csr {
    pc         = 0x100,
    mvendorid  = 0x108,
    marchid    = 0x110,
    mimpid     = 0x118,
    mcycle     = 0x120,
    minstret   = 0x128,
    mstatus    = 0x130,
    mtvec      = 0x138,
    mscratch   = 0x140,
    mepc       = 0x148,
    mcause     = 0x150,
    mtval      = 0x158,
    misa       = 0x160,
    mie        = 0x168,
    mip        = 0x170,
    medeleg    = 0x178,
    mideleg    = 0x180,
    mcounteren = 0x188,
    stvec      = 0x190,
    sscratch   = 0x198,
    sepc       = 0x1a0,
    scause     = 0x1a8,
    stval      = 0x1b0,
    satp       = 0x1b8,
    scounteren = 0x1c0,
    ilrsc      = 0x1c8,
    iflags     = 0x1d0
};

/// \brief Obtains the relative address of a CSR in shadow memory.
/// \param reg CSR name.
/// \returns The address.
uint64_t shadow_get_csr_rel_addr(shadow_csr reg);

/// \brief Obtains the relative address of a general purpose register
/// in shadow memory.
/// \param reg Register index in 0...31, for x0...x31, respectively.
/// \returns The address.
uint64_t shadow_get_register_rel_addr(int reg);

/// \brief Obtains the relative address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry, in 0..31.
/// \returns The address.
uint64_t shadow_get_pma_rel_addr(int p);

/// \brief Registers a shadow device with the machine
/// \param m Associated machine.
/// \param start Start address for memory range.
/// \param length Length of memory range.
void shadow_register_device(machine &m, uint64_t start, uint64_t length);

} // namespace cartesi


#endif
