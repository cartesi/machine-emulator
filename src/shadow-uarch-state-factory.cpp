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

#include "shadow-uarch-state-factory.h"

#include <cstdint>

#include "machine-reg.h"
#include "machine.h"
#include "pma-constants.h"
#include "pma.h"
#include "shadow-peek.h"
#include "shadow-uarch-state.h"

namespace cartesi {

/// \brief Shadow uarch state device peek callback. See ::pma_peek.
static bool shadow_uarch_state_peek(const pma_entry &pma, const machine &m, uint64_t offset, uint64_t length,
    const unsigned char **data, unsigned char *scratch) {
    // If past useful range
    if (offset >= sizeof(shadow_uarch_state)) {
        *data = nullptr;
        return length <= pma.get_length() && offset <= pma.get_length() - length;
    }
    // Otherwise, copy and return register data
    return shadow_peek(
        [](const machine &m, uint64_t paddr) {
            const auto reg = shadow_uarch_state_get_what(paddr);
            uint64_t val = 0;
            if (reg != shadow_uarch_state_what::unknown_) {
                val = m.read_reg(machine_reg_enum(reg));
            }
            return val;
        },
        pma, m, offset, length, data, scratch);
}

pma_entry make_shadow_uarch_state_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{.R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_uarch};
    return make_device_pma_entry("shadow uarch state", start, length, shadow_uarch_state_peek,
        &shadow_uarch_state_driver)
        .set_flags(f);
}

} // namespace cartesi
