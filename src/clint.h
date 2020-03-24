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

#ifndef CLINT_H
#define CLINT_H

#include <cstdint>

#include "pma.h"

/// \file
/// \brief Clock interruptor device.

namespace cartesi {

class machine;

/// \brief Mapping between CSRs and their relative addresses in CLINT memory
enum class clint_csr {
    msip0    = UINT64_C(0),      // Machine software interrupt for hart 0
    mtimecmp = UINT64_C(0x4000),
    mtime    = UINT64_C(0xbff8)
};

/// \brief Obtains the relative address of a CSR in HTIF memory.
/// \param reg CSR name.
/// \returns The address.
uint64_t clint_get_csr_rel_addr(clint_csr reg);

/// \brief Creates a PMA entry for the CLINT device
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns Corresponding PMA entry
pma_entry make_clint_pma_entry(uint64_t start, uint64_t length);

} // namespace cartesi

#endif
