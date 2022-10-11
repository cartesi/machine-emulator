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
#include <cstring>

#include "machine.h"
#include "pma-driver.h"
#include "shadow-pmas-factory.h"
#include "shadow-pmas.h"

namespace cartesi {

static bool shadow_pmas_peek(const pma_entry &pma, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    (void) pma;
    static_assert(sizeof(shadow_pmas) <= PMA_PAGE_SIZE);

    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }

    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);

    // The page will reflect the pma_board structure
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *b = reinterpret_cast<shadow_pmas *>(scratch);
    int i = 0;
    for (const auto &pma : m.get_pmas()) {
        b->pmas[i].start = pma.get_istart();
        b->pmas[i].length = pma.get_ilength();
        ++i;
    }
    *page_data = scratch;
    return true;
}

pma_entry make_shadow_pmas_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                       // R
        false,                      // W
        false,                      // X
        false,                      // IR
        false,                      // IW
        PMA_ISTART_DID::shadow_pmas // DID
    };
    return make_device_pma_entry(start, length, shadow_pmas_peek, &shadow_pmas_driver).set_flags(f);
}

} // namespace cartesi
