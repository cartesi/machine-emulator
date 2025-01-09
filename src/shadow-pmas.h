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

#include <cassert>
#include <cstdint>

#include "compiler-defines.h"
#include "pma-constants.h"
#include "pma-driver.h"

/// \file
/// \brief Shadow device.

namespace cartesi {

/// \brief Shadow memory layout

struct PACKED shadow_pma_entry {
    uint64_t istart;
    uint64_t ilength;
};

struct PACKED shadow_pmas_state {
    shadow_pma_entry pmas[PMA_MAX];
};

/// \brief Obtains the relative address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry, in 0..31.
/// \returns The address.
static inline uint64_t shadow_pmas_get_pma_rel_addr(uint64_t p) {
    assert(p < (int) PMA_MAX);
    return p * sizeof(shadow_pma_entry);
}

/// \brief Obtains the absolute address of a PMA entry in shadow memory.
static inline uint64_t shadow_pmas_get_pma_abs_addr(uint64_t p) {
    return PMA_SHADOW_PMAS_START + shadow_pmas_get_pma_rel_addr(p);
}

/// \brief Obtains the absolute address of the istart field in a PMA entry in shadow memory.
static inline uint64_t shadow_pmas_get_pma_istart_abs_addr(uint64_t p) {
    return shadow_pmas_get_pma_abs_addr(p) + offsetof(shadow_pma_entry, istart);
}

/// \brief Obtains the absolute address of the ilength field in a PMA entry in shadow memory.
static inline uint64_t shadow_pmas_get_pma_ilength_abs_addr(uint64_t p) {
    return shadow_pmas_get_pma_abs_addr(p) + offsetof(shadow_pma_entry, ilength);
}

} // namespace cartesi

#endif
