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

#include "pma-constants.h"
#include "pma.h"
#include "riscv-constants.h"
#include "shadow-uarch-state.h"
#include <cstdint>
#include <cstring>

#include "machine.h"

namespace cartesi {

/// \brief Shadow uarch state device peek callback. See ::pma_peek.
static bool shadow_uarch_state_peek(const pma_entry & /*pma*/, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    static_assert(sizeof(shadow_uarch_state) <= PMA_PAGE_SIZE);

    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);

    // The page will reflect the shadow uarch state structure
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *s = reinterpret_cast<shadow_uarch_state *>(scratch);

    s->halt_flag = m.read_reg(machine_reg::uarch_halt_flag);
    s->cycle = m.read_reg(machine_reg::uarch_cycle);
    s->pc = m.read_reg(machine_reg::uarch_pc);
    for (int i = 0; i < UARCH_X_REG_COUNT; ++i) {
        s->x[i] = m.read_reg(machine_reg_enum(machine_reg::uarch_x0, i));
    }
    *page_data = scratch;
    return true;
}

pma_entry make_shadow_uarch_state_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{.R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_uarch};
    return make_device_pma_entry("shadow uarch state device", start, length, shadow_uarch_state_peek,
        &shadow_uarch_state_driver)
        .set_flags(f);
}

} // namespace cartesi
