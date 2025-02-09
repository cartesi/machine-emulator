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

#include "shadow-pmas-factory.h"

#include <cstdint>

#include "pma-constants.h"
#include "pma.h"

namespace cartesi {

pma_entry make_shadow_pmas_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{.R = true,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_pmas};
    return make_callocd_memory_pma_entry("shadow PMAs", start, length).set_flags(f);
}

} // namespace cartesi
