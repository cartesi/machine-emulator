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

#include <cassert>
#include <cinttypes>

#include "device-driver.h"
#include "i-device-state-access.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "shadow.h"
#include "strict-aliasing.h"

namespace cartesi {

uint64_t shadow_get_csr_rel_addr(shadow_csr reg) {
    return static_cast<uint64_t>(reg);
}

uint64_t shadow_get_csr_abs_addr(shadow_csr reg) {
    return PMA_SHADOW_START + shadow_get_csr_rel_addr(reg);
}

uint64_t shadow_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < X_REG_COUNT);
    return reg * sizeof(uint64_t);
}

uint64_t shadow_get_x_abs_addr(int reg) {
    return PMA_SHADOW_START + shadow_get_x_rel_addr(reg);
}

uint64_t shadow_get_uarch_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < UARCH_X_REG_COUNT);
    return shadow_get_csr_rel_addr(shadow_csr::uarch_x0) + (reg * sizeof(uint64_t));
}

uint64_t shadow_get_pma_rel_addr(int p) {
    assert(p >= 0 && p < (int) PMA_MAX);
    return PMA_BOARD_SHADOW_START + 2UL * p * sizeof(uint64_t);
}

uint64_t shadow_get_pma_abs_addr(int p) {
    return PMA_SHADOW_START + shadow_get_pma_rel_addr(p);
}

/// \brief Shadow device read callback. See ::pma_read.
static bool shadow_read(void *context, i_device_state_access *a, uint64_t offset, uint64_t *pval, int log2_size) {
    (void) context;

    // Our shadow only supports aligned 64-bit reads
    if (log2_size != 3 || offset & 7) {
        return false;
    }

    // If offset is past start of PMA range
    if (offset >= PMA_constants::PMA_BOARD_SHADOW_START) {
        offset -= PMA_constants::PMA_BOARD_SHADOW_START;
        offset >>= 3;
        // If offset within PMA range
        if (offset < PMA_MAX * 2) {
            int p = static_cast<int>(offset >> 1);
            if (offset & 1) {
                *pval = a->read_pma_ilength(p);
            } else {
                *pval = a->read_pma_istart(p);
            }
            return true;
        }
    }

    return false;
}

const device_driver shadow_driver = {"SHADOW", shadow_read, device_write_error};

} // namespace cartesi
