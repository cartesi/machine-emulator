// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include <cassert>
#include <cinttypes>
#include <cstring>

#include "i-device-state-access.h"
#include "machine.h"
#include "shadow.h"
#include "strict-aliasing.h"

namespace cartesi {

uint64_t shadow_get_csr_rel_addr(shadow_csr reg) {
    return static_cast<uint64_t>(reg);
}

uint64_t shadow_get_x_rel_addr(int reg) {
    assert(reg >= 0 && reg < X_REG_COUNT);
    return reg * sizeof(uint64_t);
}

uint64_t shadow_get_pma_rel_addr(int p) {
    assert(p >= 0 && p < (int) PMA_MAX);
    return PMA_BOARD_SHADOW_START + 2 * p * sizeof(uint64_t);
}

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *shadow) {
    (void) pma;
    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(shadow, 0, PMA_PAGE_SIZE);
    // Copy general-purpose registers
    for (int i = 0; i < X_REG_COUNT; ++i) {
        aliased_aligned_write<uint64_t>(shadow + shadow_get_x_rel_addr(i), m.read_x(i));
    }
    // Copy named registers
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::pc), m.read_pc());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mvendorid), m.read_mvendorid());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::marchid), m.read_marchid());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mimpid), m.read_mimpid());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mcycle), m.read_mcycle());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::minstret), m.read_minstret());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mstatus), m.read_mstatus());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mtvec), m.read_mtvec());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mscratch), m.read_mscratch());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mepc), m.read_mepc());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mcause), m.read_mcause());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mtval), m.read_mtval());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::misa), m.read_misa());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mie), m.read_mie());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mip), m.read_mip());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::medeleg), m.read_medeleg());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mideleg), m.read_mideleg());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::mcounteren), m.read_mcounteren());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::stvec), m.read_stvec());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::sscratch), m.read_sscratch());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::sepc), m.read_sepc());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::scause), m.read_scause());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::stval), m.read_stval());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::satp), m.read_satp());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::scounteren), m.read_scounteren());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::ilrsc), m.read_ilrsc());
    aliased_aligned_write<uint64_t>(shadow + shadow_get_csr_rel_addr(shadow_csr::iflags), m.read_iflags());
    // Copy PMAs
    int i = 0;
    for (const auto &pma : m.get_pmas()) {
        auto rel_addr = shadow_get_pma_rel_addr(i);
        aliased_aligned_write<uint64_t>(shadow + rel_addr, pma.get_istart());
        aliased_aligned_write<uint64_t>(shadow + rel_addr + sizeof(uint64_t), pma.get_ilength());
        ++i;
    }
    *page_data = shadow;
    return true;
}

/// \brief Shadow device read callback. See ::pma_read.
static bool shadow_read(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t *pval,
    int log2_size) {
    (void) pma;

    // Our shadow only supports aligned 64-bit reads
    if (log2_size != 3 || offset & 7) {
        return false;
    }

    // If offset is past start of PMA range
    if (offset >= PMA_constants::PMA_BOARD_SHADOW_START) {
        offset -= PMA_constants::PMA_BOARD_SHADOW_START;
        offset >>= 3;
        // If offset within PMA range
        if (offset < PMA_MAX * 2) {
            int p = static_cast<int>(offset >> 1);
            if (offset & 1) {
                *pval = a->read_pma_ilength(p);
            } else {
                *pval = a->read_pma_istart(p);
            }
            return true;
        }
    }

    return false;
}

static const pma_driver shadow_driver = {"SHADOW", shadow_read, pma_write_error};

pma_entry make_shadow_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                  // R
        false,                 // W
        false,                 // X
        false,                 // IR
        false,                 // IW
        PMA_ISTART_DID::shadow // DID
    };
    return make_device_pma_entry(start, length, shadow_peek, &shadow_driver).set_flags(f);
}

} // namespace cartesi
