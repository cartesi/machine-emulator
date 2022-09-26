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

#include <cassert>
#include <cinttypes>
#include <cstring>

#include "clint.h"
#include "htif.h"
#include "i-device-state-access.h"
#include "machine.h"
#include "pma-driver.h"
#include "shadow-state-factory.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_state_peek(const pma_entry &pma, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    (void) pma;
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
        s->x[i] = m.read_x(i);
    }
    // Copy floating-point registers
    for (int i = 0; i < F_REG_COUNT; ++i) {
        s->f[i] = m.read_f(i);
    }
    // Copy named registers
    s->pc = m.read_pc();
    s->fcsr = m.read_fcsr();
    s->mvendorid = m.read_mvendorid();
    s->marchid = m.read_marchid();
    s->mimpid = m.read_mimpid();
    s->mcycle = m.read_mcycle();
    s->icycleinstret = m.read_icycleinstret();
    s->mstatus = m.read_mstatus();
    s->mtvec = m.read_mtvec();
    s->mscratch = m.read_mscratch();
    s->mepc = m.read_mepc();
    s->mcause = m.read_mcause();
    s->mtval = m.read_mtval();
    s->misa = m.read_misa();
    s->mie = m.read_mie();
    s->mip = m.read_mip();
    s->medeleg = m.read_medeleg();
    s->mideleg = m.read_mideleg();
    s->mcounteren = m.read_mcounteren();
    s->menvcfg = m.read_menvcfg();
    s->stvec = m.read_stvec();
    s->sscratch = m.read_sscratch();
    s->sepc = m.read_sepc();
    s->scause = m.read_scause();
    s->stval = m.read_stval();
    s->satp = m.read_satp();
    s->scounteren = m.read_scounteren();
    s->senvcfg = m.read_senvcfg();
    s->hstatus = m.read_hstatus();
    s->hideleg = m.read_hideleg();
    s->hedeleg = m.read_hedeleg();
    s->hie = m.read_hie();
    s->hip = m.read_hip();
    s->hvip = m.read_hvip();
    s->hgatp = m.read_hgatp();
    s->henvcfg = m.read_henvcfg();
    s->htimedelta = m.read_htimedelta();
    s->htval = m.read_htval();
    s->vsepc = m.read_vsepc();
    s->vsstatus = m.read_vsstatus();
    s->vscause = m.read_vscause();
    s->vstval = m.read_vstval();
    s->vstvec = m.read_vstvec();
    s->vsscratch = m.read_vsscratch();
    s->vsatp = m.read_vsatp();
    s->vsie = m.read_vsie();
    s->vsip = m.read_vsip();
    s->ilrsc = m.read_ilrsc();
    s->iflags = m.read_iflags();
    s->clint_mtimecmp = m.read_clint_mtimecmp();
    s->htif_tohost = m.read_htif_tohost();
    s->htif_fromhost = m.read_htif_fromhost();
    s->htif_ihalt = m.read_htif_ihalt();
    s->htif_iconsole = m.read_htif_iconsole();
    s->htif_iyield = m.read_htif_iyield();
    s->uarch_cycle = m.read_uarch_cycle();
    s->uarch_halt_flag = m.read_uarch_halt_flag();
    s->uarch_pc = m.read_uarch_pc();
    s->uarch_ram_length = m.get_initial_config().uarch.ram.length;
    // Copy general-purpose uarch registers
    for (int i = 0; i < UARCH_X_REG_COUNT; ++i) {
        s->uarch_x[i] = m.read_uarch_x(i);
    }
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
