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

#ifndef ROM_H
#define ROM_H

/// \file
/// \brief Bootstrap and device tree in ROM

#include <cstdint>

namespace cartesi {

// Forward declarations
struct machine_config;

/// \brief Initializes PMA extension metadata on ROM
/// \param c Machine configuration.
/// \param rom_start Pointer to start of ROM contiguous range in host memory
/// \param length Maximum amount of ROM to use from start.
void rom_init(const machine_config &c, unsigned char *rom_start,
    uint64_t length);

} // namespace cartesi

#endif
