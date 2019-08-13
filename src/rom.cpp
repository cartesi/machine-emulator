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

#include <stdexcept>
#include <cinttypes>

/// \file
/// \brief Bootstrap and device tree in ROM

#include "pma-ext.h"
#include "machine-config.h"

namespace cartesi {

void rom_init(const machine_config &c, unsigned char *rom_start, uint64_t length) {
    if (length < PMA_EXT_LENGTH_DEF)
        throw std::runtime_error{"Not enough space on ROM for PMA extension data"};

    struct pma_ext_hdr *hdr = (struct pma_ext_hdr *)(rom_start + length - PMA_EXT_LENGTH_DEF);
    hdr->version = PMA_EXT_VERSION;

    if (!c.rom.bootargs.empty()) {
        strncpy(hdr->bootargs, c.rom.bootargs.c_str(), PMA_EXT_BOOTARGS_SIZE);
        hdr->bootargs[PMA_EXT_BOOTARGS_SIZE - 1] = '\0';
    } else {
        memset(hdr->bootargs, 0, PMA_EXT_BOOTARGS_SIZE);
    }
}

} // namespace cartesi
