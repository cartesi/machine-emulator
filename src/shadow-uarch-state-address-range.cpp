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

#include "shadow-uarch-state-address-range.h"

#include <cstdint>

#include "machine-reg.h"
#include "machine.h"
#include "pmas-constants.h"
#include "shadow-peek.h"
#include "shadow-uarch-state.h"

namespace cartesi {

/// \brief Shadow uarch state device peek callback. See ::pmas_peek.
bool shadow_uarch_state_address_range::do_peek(const machine &m, uint64_t offset, uint64_t length,
    const unsigned char **data, unsigned char *scratch) const noexcept {
    // If past useful range
    if (offset >= sizeof(shadow_uarch_state)) {
        *data = nullptr;
        return contains_relative(offset, length);
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
        *this, m, offset, length, data, scratch);
}

} // namespace cartesi
