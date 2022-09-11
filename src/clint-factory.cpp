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

#include "clint-factory.h"
#include "i-device-state-access.h"
#include "machine.h"
#include "pma.h"
#include "riscv-constants.h"
#include "rtc.h"
#include "strict-aliasing.h"

namespace cartesi {

static constexpr uint64_t base(uint64_t v) {
    return v - (v % PMA_PAGE_SIZE);
}

static constexpr uint64_t offset(uint64_t v) {
    return v % PMA_PAGE_SIZE;
}

/// \brief CLINT device peek callback. See ::pma_peek.
static bool clint_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *scratch) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    static_assert(base(clint_msip0_rel_addr) != base(clint_mtimecmp_rel_addr) &&
            base(clint_mtimecmp_rel_addr) != base(clint_mtime_rel_addr) &&
            base(clint_mtime_rel_addr) != base(clint_msip0_rel_addr),
        "code expects msip0, mtimcmp, and mtime to be in different pages");
    // There are 1 non-pristine page: base(CLINT_MTIMECMP_REL_ADDR)
    // Both base(CLINT_MSIP0_REL_ADDR), base(CLINT_MTIME_REL_ADDR) contain only derived values, and therefore
    // do not enter the Merkle tree. mtime is derived from mcycle, and msip0 is derived from mip
    switch (page_offset) {
        case base(clint_mtimecmp_rel_addr):
            memset(scratch, 0, PMA_PAGE_SIZE);
            aliased_aligned_write<uint64_t>(scratch + offset(clint_mtimecmp_rel_addr), m.read_clint_mtimecmp());
            *page_data = scratch;
            return true;
        default:
            *page_data = nullptr;
            return (page_offset % PMA_PAGE_SIZE) == 0 && page_offset < pma.get_length();
    }
}

#undef base
#undef offset

pma_entry make_clint_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                 // R
        true,                 // W
        false,                // X
        false,                // IR
        false,                // IW
        PMA_ISTART_DID::CLINT // DID
    };
    return make_device_pma_entry(start, length, clint_peek, &clint_driver).set_flags(f);
}

} // namespace cartesi
