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

#ifndef SHADOW_PMAS_ADDRESS_RANGE_H
#define SHADOW_PMAS_ADDRESS_RANGE_H

#include <cstdint>
#include <stdexcept>

#include "memory-address-range.h"
#include "pma-constants.h"
#include "shadow-pmas.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

static inline auto make_shadow_pmas_address_range(uint64_t start, uint64_t length) {
    static constexpr pma_flags shadow_pmas_flags{
        .M = true,
        .IO = false,
        .E = false,
        .R = true,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_pmas,
    };
    return make_callocd_memory_address_range("shadow PMAs", start, length, shadow_pmas_flags);
}

} // namespace cartesi

#endif
