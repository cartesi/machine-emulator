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

#include <cstdint>

#include "clint.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"
#include "rtc.h"

namespace cartesi {

static constexpr uint64_t base(uint64_t v) {
    return v - (v % PMA_PAGE_SIZE);
}

static bool clint_read_msip(i_device_state_access *a, uint64_t *val, int log2_size) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    static_assert(base(clint_msip0_rel_addr) != base(clint_mtimecmp_rel_addr) &&
            base(clint_mtimecmp_rel_addr) != base(clint_mtime_rel_addr) &&
            base(clint_mtime_rel_addr) != base(clint_msip0_rel_addr),
        "code expects msip0, mtimcmp, and mtime to be in different pages");

    if (log2_size == 2) {
        *val = static_cast<uint64_t>((a->read_mip() & MIP_MSIP_MASK) == MIP_MSIP_MASK);
        return true;
    }
    return false;
}

static bool clint_read_mtime(i_device_state_access *a, uint64_t *val, int log2_size) {
    if (log2_size == 3) {
        *val = rtc_cycle_to_time(a->read_mcycle());
        return true;
    }
    return false;
}

static bool clint_read_mtimecmp(i_device_state_access *a, uint64_t *val, int log2_size) {
    if (log2_size == 3) {
        *val = a->read_clint_mtimecmp();
        return true;
    }
    return false;
}

/// \brief CLINT device read callback. See ::pma_read.
static bool clint_read(void * /*context*/, i_device_state_access *a, uint64_t offset, uint64_t *val, int log2_size) {
    switch (offset) {
        case clint_msip0_rel_addr:
            return clint_read_msip(a, val, log2_size);
        case clint_mtimecmp_rel_addr:
            return clint_read_mtimecmp(a, val, log2_size);
        case clint_mtime_rel_addr:
            return clint_read_mtime(a, val, log2_size);
        default:
            // other reads are exceptions
            return false;
    }
}

/// \brief CLINT device read callback. See ::pma_write.
static execute_status clint_write(void * /*context*/, i_device_state_access *a, uint64_t offset, uint64_t val,
    int log2_size) {
    switch (offset) {
        case clint_msip0_rel_addr:
            if (log2_size == 2) {
                //??D I don't yet know why Linux tries to raise MSIP when we only have a single hart
                //    It does so repeatedly before and after every command run in the shell
                //    Will investigate.
                if ((val & 1) != 0) {
                    a->set_mip(MIP_MSIP_MASK);
                    return execute_status::success_and_serve_interrupts;
                }
                a->reset_mip(MIP_MSIP_MASK);

                return execute_status::success;
            }
            return execute_status::failure;
        case clint_mtimecmp_rel_addr:
            if (log2_size == 3) {
                a->write_clint_mtimecmp(val);
                a->reset_mip(MIP_MTIP_MASK);
                return execute_status::success;
            }
            // partial mtimecmp is not supported
            return execute_status::failure;
        default:
            // other writes are exceptions
            return execute_status::failure;
    }
}

const pma_driver clint_driver = {.name = "CLINT", .read = clint_read, .write = clint_write};

} // namespace cartesi
