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

#include "clint.h"
#include "i-device-state-access.h"
#include "machine.h"
#include "pma.h"
#include "rtc.h"
#include "riscv-constants.h"
#include "strict-aliasing.h"

namespace cartesi {

#define CLINT_MSIP0_REL_ADDR (static_cast<uint64_t>(clint_csr::msip0))
#define CLINT_MTIME_REL_ADDR (static_cast<uint64_t>(clint_csr::mtime))
#define CLINT_MTIMECMP_REL_ADDR (static_cast<uint64_t>(clint_csr::mtimecmp))

uint64_t clint_get_csr_rel_addr(clint_csr reg) {
    return static_cast<uint64_t>(reg);
}

static bool clint_read_msip(i_device_state_access *a, uint64_t *val,
    int log2_size) {
    if (log2_size == 2) {
        *val = ((a->read_mip() & MIP_MSIP_MASK) == MIP_MSIP_MASK);
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
static bool clint_read(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t *val, int log2_size) {
    (void) pma;

    switch (offset) {
        case CLINT_MSIP0_REL_ADDR:
            return clint_read_msip(a, val, log2_size);
        case CLINT_MTIMECMP_REL_ADDR:
            return clint_read_mtimecmp(a, val, log2_size);
        case CLINT_MTIME_REL_ADDR:
            return clint_read_mtime(a, val, log2_size);
        default:
            // other reads are exceptions
            return false;
    }
}

/// \brief CLINT device read callback. See ::pma_write.
static bool clint_write(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t val, int log2_size) {
    (void) pma;

    switch (offset) {
        case CLINT_MSIP0_REL_ADDR:
            if (log2_size == 2) {
                //??D I don't yet know why Linux tries to raise MSIP when we only have a single hart
                //    It does so repeatedly before and after every command run in the shell
                //    Will investigate.
                if (val & 1) {
                    a->set_mip(MIP_MSIP_MASK);
                } else {
                    a->reset_mip(MIP_MSIP_MASK);
                }
                return true;
            }
            return false;
        case CLINT_MTIMECMP_REL_ADDR:
            if (log2_size == 3) {
                a->write_clint_mtimecmp(val);
                a->reset_mip(MIP_MTIP_MASK);
                return true;
            }
            // partial mtimecmp is not supported
            return false;
        default:
            // other writes are exceptions
            return false;
    }
}

#define base(v) ((v) - ((v) % (PMA_PAGE_SIZE)))
#define offset(v) ((v) % (PMA_PAGE_SIZE))
/// \brief CLINT device peek callback. See ::pma_peek.
static bool clint_peek(const pma_entry &pma, const machine &m, 
    uint64_t page_offset, const unsigned char **page_data,
    unsigned char *scratch) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
        "code assumes little-endian byte ordering");
    static_assert(base(CLINT_MSIP0_REL_ADDR) != base(CLINT_MTIMECMP_REL_ADDR) &&
        base(CLINT_MTIMECMP_REL_ADDR) != base(CLINT_MTIME_REL_ADDR) &&
        base(CLINT_MTIME_REL_ADDR) != base(CLINT_MSIP0_REL_ADDR),
        "code expects msip0, mtimcmp, and mtime to be in different pages");
    // There are 3 non-pristine pages: base(CLINT_MSIP0_REL_ADDR), base(CLINT_MTIMECMP_REL_ADDR), and base(CLINT_MTIME_REL_ADDR)
    switch (page_offset) {
        case base(CLINT_MSIP0_REL_ADDR):
            // This page contains only msip (which is either 0 or 1)
            // Since we are little-endian, we can simply write the bytes
            memset(scratch, 0, PMA_PAGE_SIZE);
            aliased_aligned_write<uint64_t>(scratch +
                offset(CLINT_MSIP0_REL_ADDR),
                (m.read_mip() & MIP_MSIP_MASK) == MIP_MSIP_MASK);
            *page_data = scratch;
            return true;
        case base(CLINT_MTIMECMP_REL_ADDR):
            memset(scratch, 0, PMA_PAGE_SIZE);
            aliased_aligned_write<uint64_t>(scratch +
                offset(CLINT_MTIMECMP_REL_ADDR), m.read_clint_mtimecmp());
            *page_data = scratch;
            return true;
        case base(CLINT_MTIME_REL_ADDR):
            memset(scratch, 0, PMA_PAGE_SIZE);
            aliased_aligned_write<uint64_t>(scratch +
                offset(CLINT_MTIME_REL_ADDR),
                rtc_cycle_to_time(m.read_mcycle()));
            *page_data = scratch;
            return true;
        default:
            *page_data = nullptr;
            if (page_offset % PMA_PAGE_SIZE == 0 && page_offset <
                pma.get_length()) return true;
            else return false;
    }
}
#undef base
#undef offset

static const pma_driver clint_driver = {
    "CLINT",
    clint_read,
    clint_write
};

pma_entry make_clint_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                   // R
        true,                   // W
        false,                  // X
        false,                  // IR
        false,                  // IW
        PMA_ISTART_DID::CLINT   // DID
    };
    return make_device_pma_entry(start, length, clint_peek, &clint_driver).
        set_flags(f);
}

} // namespace cartesi
