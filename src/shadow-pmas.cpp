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

#include "shadow-pmas.h"
#include "i-device-state-access.h"

#include <cstddef>

namespace cartesi {

/// \brief Shadow device read callback. See ::pma_read.
static bool shadow_pmas_read(void * /*context*/, i_device_state_access *a, uint64_t offset, uint64_t *pval,
    int log2_size) {
    static_assert(offsetof(shadow_pmas, pmas) == 0, "Unexpected offswet of PMA board");
    static_assert(sizeof(shadow_pma_entry) == 2 * sizeof(uint64_t), "Unexpected size of shadow PMA entry");
    static_assert(sizeof(shadow_pmas) == PMA_MAX * sizeof(shadow_pma_entry), "Unexpected size of Shadow PMA array ");

    // Our shadow only supports aligned 64-bit reads
    if (((offset & 7) != 0) || log2_size != 3) {
        return false;
    }
    if (offset < sizeof(shadow_pmas)) {
        offset >>= 3;
        const int p = static_cast<int>(offset >> 1);
        if ((offset & 1) != 0) {
            *pval = a->read_pma_ilength(p);
        } else {
            *pval = a->read_pma_istart(p);
        }
        return true;
    }
    return false;
}

const pma_driver shadow_pmas_driver = {"SHADOW PMAS", shadow_pmas_read, device_write_error};

} // namespace cartesi
