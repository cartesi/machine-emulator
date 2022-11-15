// Copyright 2022 Cartesi Pte. Ltd.
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

#include "shadow-tlb-factory.h"
#include "machine.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief TLB device peek callback. See ::pma_peek.
static bool shadow_tlb_peek(const pma_entry &pma, const machine &m, uint64_t page_offset,
    const unsigned char **page_data, unsigned char *scratch) {
    (void) pma;

    // Check for alignment and range
    if (page_offset % PMA_PAGE_SIZE != 0 || page_offset >= pma.get_length()) {
        *page_data = nullptr;
        return false;
    }

    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);

    // Copy relevant TLB entries to the page
    for (uint64_t off = 0; off < PMA_PAGE_SIZE; off += sizeof(uint64_t)) {
        uint64_t val = 0;
        uint64_t tlboff = page_offset + off;
        if (tlboff < offsetof(shadow_tlb_state, cold)) { // Hot entry
            uint64_t etype = tlboff / sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = tlboff % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_hot_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_hot_entry);
            const tlb_hot_entry &tlbhe = m.get_state().tlb.hot[etype][eidx];
            switch (fieldoff) {
                case offsetof(tlb_hot_entry, vaddr_page):
                    val = tlbhe.vaddr_page;
                    break;
                case offsetof(tlb_hot_entry, vh_offset):
                    // Here we skip host related fields, they are visible as 0 in the device
                    val = 0;
                    break;
            }
        } else if (tlboff < sizeof(shadow_tlb_state)) { // Cold entry
            uint64_t coldoff = tlboff - offsetof(shadow_tlb_state, cold);
            uint64_t etype = coldoff / sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t etypeoff = coldoff % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>);
            uint64_t eidx = etypeoff / sizeof(tlb_cold_entry);
            uint64_t fieldoff = etypeoff % sizeof(tlb_cold_entry);
            const tlb_cold_entry &tlbce = m.get_state().tlb.cold[etype][eidx];
            switch (fieldoff) {
                case offsetof(tlb_cold_entry, paddr_page):
                    val = tlbce.paddr_page;
                    break;
                case offsetof(tlb_cold_entry, pma_index):
                    val = tlbce.pma_index;
                    break;
            }
        }
        aliased_aligned_write<uint64_t>(scratch + off, val);
    }

    *page_data = scratch;
    return true;
}

pma_entry make_shadow_tlb_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
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
