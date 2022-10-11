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

/// \brief CLINT device peek callback. See ::pma_peek.
static bool clint_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *) {
    (void) m;
    *page_data = nullptr;
    return (page_offset % PMA_PAGE_SIZE) == 0 && page_offset < pma.get_length();
}

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
