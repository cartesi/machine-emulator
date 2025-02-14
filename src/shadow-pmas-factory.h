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

#ifndef SHADOW_PMAS_FACTORY_H
#define SHADOW_PMAS_FACTORY_H

#include <cstdint>

/// \file
/// \brief Shadow device.

#include "pma.h"
#include "shadow-pmas.h"

namespace cartesi {

pma_entry make_shadow_pmas_pma_entry(uint64_t start, uint64_t length);

template <typename PMAS>
void shadow_pmas_init(const PMAS &pmas, shadow_pmas_state *shadow) {
    static_assert(sizeof(shadow_pmas_state) == PMA_MAX * 2 * sizeof(uint64_t), "inconsistent shadow PMAs length");
    static_assert(PMA_SHADOW_PMAS_LENGTH >= sizeof(shadow_pmas_state), "shadow PMAs not long enough");
    if (pmas.size() > PMA_MAX) {
        throw std::invalid_argument{"more PMAs than shadow PMAs can hold"};
    }
    unsigned index = 0;
    for (const auto &pma : pmas) {
        (*shadow)[index].istart = pma.get_istart();
        (*shadow)[index].ilength = pma.get_ilength();
        ++index;
    }
}

} // namespace cartesi

#endif
