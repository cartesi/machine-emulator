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

#include <cinttypes>
#include <stdexcept>

/// \file
/// \brief Bootstrap and device tree in ROM

#include <pma-defines.h>

#include "machine-config.h"

namespace cartesi {

void rom_init(const machine_config &c, unsigned char *rom_start, uint64_t length) {
    if (length < PMA_ROM_EXTRASPACE_LENGTH_DEF) {
        throw std::runtime_error{"not enough space on ROM for bootargs"};
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    char *bootargs = reinterpret_cast<char *>(rom_start + length - PMA_ROM_EXTRASPACE_LENGTH_DEF);

    if (!c.rom.bootargs.empty()) {
        strncpy(bootargs, c.rom.bootargs.c_str(), PMA_BOOTARGS_LENGTH_DEF);
        bootargs[PMA_BOOTARGS_LENGTH_DEF - 1] = '\0';
    }
}

} // namespace cartesi
