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

#include "shadow-tlb-factory.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "machine.h"
#include "pma-constants.h"
#include "pma.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief TLB device peek callback. See ::pma_peek.
static bool shadow_tlb_peek(const pma_entry &pma, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    // Check for alignment and range
    if (page_offset % PMA_PAGE_SIZE != 0 || page_offset >= pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy relevant TLB entries to the page
    const auto &tlb = m.get_state().tlb;
    for (uint64_t offset = 0; offset < PMA_PAGE_SIZE; offset += sizeof(uint64_t)) {
        uint64_t val = 0;
        if (offset < sizeof(shadow_tlb_state)) {
            // Figure out in which set (code/read/write) the offset falls
            const uint64_t set_index = offset / sizeof(shadow_tlb_set);
            const uint64_t slot_offset = offset % sizeof(shadow_tlb_set);
            // Figure out in which slot index the offset falls
            const uint64_t slot_index = slot_offset / sizeof(shadow_tlb_slot);
            const uint64_t field_offset = slot_offset % sizeof(shadow_tlb_slot);
            switch (field_offset) {
                case offsetof(shadow_tlb_slot, vaddr_page):
                    val = tlb.hot[set_index][slot_index].vaddr_page;
                    break;
                case offsetof(shadow_tlb_slot, vp_offset): {
                    auto pma_index = tlb.cold[set_index][slot_index].pma_index;
                    auto vh_offset = tlb.hot[set_index][slot_index].vh_offset;
                    // This method converts vh_offset to vp_offset as well as haddr to paddr
                    val = m.get_paddr(vh_offset, pma_index);
                    break;
                }
                case offsetof(shadow_tlb_slot, pma_index):
                    val = tlb.cold[set_index][slot_index].pma_index;
                    break;
                default:
                    val = 0;
                    break;
            }
        }
        aliased_aligned_write<uint64_t>(scratch + offset, val);
    }
    *page_data = scratch;
    return true;
}

pma_entry make_shadow_tlb_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{
        false,                     // R
        false,                     // W
        false,                     // X
        false,                     // IR
        false,                     // IW
        PMA_ISTART_DID::shadow_TLB // DID
    };
    return make_device_pma_entry("shadow TLB device", start, length, shadow_tlb_peek, &shadow_tlb_driver).set_flags(f);
}

} // namespace cartesi
