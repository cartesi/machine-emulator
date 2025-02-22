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

#include "shadow-tlb-address-range.h"

#include <cstdint>

#include "machine.h"
#include "shadow-peek.h"

namespace cartesi {

bool shadow_tlb_address_range::do_peek(const machine &m, uint64_t offset, uint64_t length, const unsigned char **data,
    unsigned char *scratch) const noexcept {
    // If past useful range
    if (offset >= sizeof(shadow_tlb_state)) {
        *data = nullptr;
        return contains_relative(offset, length);
    }
    // Otherwise, copy and return register data
    return shadow_peek(
        [](const machine &m, uint64_t paddr) {
            TLB_set_index set_index{};
            uint64_t slot_index{};
            auto reg = shadow_tlb_get_what(paddr, set_index, slot_index);
            uint64_t val = 0;
            if (reg != shadow_tlb_what::unknown_) {
                val = m.read_shadow_tlb(set_index, slot_index, reg);
            }
            return val;
        },
        *this, m, offset, length, data, scratch);
}

} // namespace cartesi
