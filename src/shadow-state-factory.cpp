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

#include "shadow-state-factory.h"

#include <cstring>

#include "machine.h"

namespace cartesi {

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_state_peek(const pma_entry & /*pma*/, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    static_assert(sizeof(shadow_state) <= PMA_PAGE_SIZE);

    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);

    // The page will reflect the shadow structure
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *s = reinterpret_cast<shadow_state *>(scratch);

    // Copy general-purpose registers
    for (int i = 0; i < X_REG_COUNT; ++i) {
        s->x[i] = m.read_reg(static_cast<machine::reg>(machine::reg::x0 + i));
    }
    // Copy floating-point registers
    for (int i = 0; i < F_REG_COUNT; ++i) {
        s->f[i] = m.read_reg(static_cast<machine::reg>(machine::reg::f0 + i));
    }
    // Copy named registers
    s->pc = m.read_reg(machine::reg::pc);
    s->fcsr = m.read_reg(machine::reg::fcsr);
    s->mvendorid = m.read_reg(machine::reg::mvendorid);
    s->marchid = m.read_reg(machine::reg::marchid);
    s->mimpid = m.read_reg(machine::reg::mimpid);
    s->mcycle = m.read_reg(machine::reg::mcycle);
    s->icycleinstret = m.read_reg(machine::reg::icycleinstret);
    s->mstatus = m.read_reg(machine::reg::mstatus);
    s->mtvec = m.read_reg(machine::reg::mtvec);
    s->mscratch = m.read_reg(machine::reg::mscratch);
    s->mepc = m.read_reg(machine::reg::mepc);
    s->mcause = m.read_reg(machine::reg::mcause);
    s->mtval = m.read_reg(machine::reg::mtval);
    s->misa = m.read_reg(machine::reg::misa);
    s->mie = m.read_reg(machine::reg::mie);
    s->mip = m.read_reg(machine::reg::mip);
    s->medeleg = m.read_reg(machine::reg::medeleg);
    s->mideleg = m.read_reg(machine::reg::mideleg);
    s->mcounteren = m.read_reg(machine::reg::mcounteren);
    s->menvcfg = m.read_reg(machine::reg::menvcfg);
    s->stvec = m.read_reg(machine::reg::stvec);
    s->sscratch = m.read_reg(machine::reg::sscratch);
    s->sepc = m.read_reg(machine::reg::sepc);
    s->scause = m.read_reg(machine::reg::scause);
    s->stval = m.read_reg(machine::reg::stval);
    s->satp = m.read_reg(machine::reg::satp);
    s->scounteren = m.read_reg(machine::reg::scounteren);
    s->senvcfg = m.read_reg(machine::reg::senvcfg);
    s->ilrsc = m.read_reg(machine::reg::ilrsc);
    s->iflags = m.read_reg(machine::reg::iflags);
    s->iunrep = m.read_reg(machine::reg::iunrep);
    s->clint_mtimecmp = m.read_reg(machine::reg::clint_mtimecmp);
    s->plic_girqpend = m.read_reg(machine::reg::plic_girqpend);
    s->plic_girqsrvd = m.read_reg(machine::reg::plic_girqsrvd);
    s->htif_tohost = m.read_reg(machine::reg::htif_tohost);
    s->htif_fromhost = m.read_reg(machine::reg::htif_fromhost);
    s->htif_ihalt = m.read_reg(machine::reg::htif_ihalt);
    s->htif_iconsole = m.read_reg(machine::reg::htif_iconsole);
    s->htif_iyield = m.read_reg(machine::reg::htif_iyield);
    *page_data = scratch;
    return true;
}

pma_entry make_shadow_state_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{
        false,                       // R
        false,                       // W
        false,                       // X
        false,                       // IR
        false,                       // IW
        PMA_ISTART_DID::shadow_state // DID
    };
    return make_device_pma_entry("shadow state device", start, length, shadow_state_peek, &shadow_state_driver)
        .set_flags(f);
}

} // namespace cartesi
