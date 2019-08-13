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

#ifndef PMA_EXT_H
#define PMA_EXT_H

#include <cstdint>

#include "pma-defines.h"

#define PMA_EXT_VERSION 		1
#define PMA_EXT_BOOTARGS_SIZE		2048

struct pma {
    uint64_t istart;
    uint64_t ilength;
};

struct pma_ext_hdr {
    uint64_t version;
    char bootargs[PMA_EXT_BOOTARGS_SIZE];
};

#endif /* PMA_EXT_H */
