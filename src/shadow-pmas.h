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

#ifndef SHADOW_PMAS_H
#define SHADOW_PMAS_H

#include <cstddef>
#include <cstdint>

#include "i-device-state-access.h"
#include "pma-constants.h"
#include "pma-driver.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

#pragma pack(push, 1)

/// \brief Shadow memory layout

struct shadow_pma_entry {
    uint64_t start;
    uint64_t length;
};

struct shadow_pmas {
    shadow_pma_entry pmas[PMA_MAX];
};

#pragma pack(pop)

/// \brief Global instance of the pma board shadow device driver.
extern const pma_driver shadow_pmas_driver;

/// \brief Obtains the relative address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry, in 0..31.
/// \returns The address.
uint64_t shadow_pmas_get_pma_rel_addr(int p);

/// \brief Obtains the absolute address of a PMA entry in shadow memory.
uint64_t shadow_pmas_get_pma_abs_addr(int p);

} // namespace cartesi

#endif
