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

#ifndef SHADOW_PMAS_H
#define SHADOW_PMAS_H

#include <array>
#include <cassert>
#include <cstdint>

#include "compiler-defines.h"
#include "pma-constants.h"
#include "pma-driver.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

/// \brief Shadow memory layout

struct PACKED shadow_pmas_entry {
    uint64_t istart;
    uint64_t ilength;
};

using shadow_pmas_state = std::array<shadow_pmas_entry, PMA_MAX>;

/// \brief List of field types
enum class shadow_pmas_what : uint64_t {
    istart = offsetof(shadow_pmas_entry, istart),
    ilength = offsetof(shadow_pmas_entry, ilength),
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

/// \brief Obtains the absolute address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry
/// \returns The address.
static constexpr uint64_t shadow_pmas_get_pma_abs_addr(uint64_t p) {
    return PMA_SHADOW_PMAS_START + (p * sizeof(shadow_pmas_entry));
}

/// \brief Obtains the absolute address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry
/// \param what Desired field
/// \returns The address.
static constexpr uint64_t shadow_pmas_get_pma_abs_addr(uint64_t p, shadow_pmas_what what) {
    return shadow_pmas_get_pma_abs_addr(p) + static_cast<uint64_t>(what);
}

static constexpr shadow_pmas_what shadow_pmas_get_what(uint64_t paddr) {
    if (paddr < PMA_SHADOW_PMAS_START || paddr - PMA_SHADOW_PMAS_START >= sizeof(shadow_pmas_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return shadow_pmas_what::unknown_;
    }
    //??D First condition ensures offset = (paddr-PMA_SHADOW_PMAS_START) >= 0
    //??D Second ensures offset < sizeof(shadow_pmas_state)
    //??D Third ensures offset is aligned to sizeof(uint64_t)
    //??D shadow_pmas_entry only contains uint64_t fields
    //??D shadow_pmas_state_what contains one entry with the offset of each field in shadow_pmas_entry
    //??D I don't see how the cast can produce something outside the enum...
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    return shadow_pmas_what{(paddr - PMA_SHADOW_PMAS_START) % sizeof(shadow_pmas_entry)};
}

static constexpr const char *shadow_pmas_get_what_name(shadow_pmas_what what) {
    const auto paddr = static_cast<uint64_t>(what);
    if (paddr >= sizeof(shadow_pmas_entry) || (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return "pma.unknown_";
    }
    using reg = shadow_pmas_what;
    switch (what) {
        case reg::istart:
            return "pma.istart";
        case reg::ilength:
            return "pma.ilength";
        case reg::unknown_:
            return "pma.unknown_";
    }
    return "pmas.unknown_";
}

} // namespace cartesi

#endif
