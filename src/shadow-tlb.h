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

#ifndef SHADOW_TLB_H
#define SHADOW_TLB_H

/// \file
/// \brief TLB device.
/// \details The Translation Lookaside Buffer is a small cache used to speed up translation between address spaces.

#include <array>
#include <cstddef>
#include <cstdint>

#include "compiler-defines.h"
#include "pma-driver.h"
#include "tlb.h"

namespace cartesi {

/// \brief Shadow TLB slot
struct PACKED shadow_tlb_slot {
    uint64_t vaddr_page; ///< Tag is target virtual address of start of page
    uint64_t vp_offset;  ///< Value is offset from target virtual address to target physical address within page
    uint64_t pma_index;  ///< Index of PMA where physical page falls
};

/// \brief Shadow TLB set
using shadow_tlb_set = std::array<shadow_tlb_slot, TLB_SET_SIZE>;

/// \brief Shadow TLB memory layout
using shadow_tlb_state = std::array<shadow_tlb_set, TLB_LAST_ + 1>; // one set for code, one for read and one for write

static_assert(PMA_SHADOW_TLB_LENGTH >= sizeof(shadow_tlb_state), "TLB state must fit in TLB shadow");

extern const pma_driver shadow_tlb_driver;

template <TLB_set_use USE>
constexpr uint64_t shadow_tlb_get_slot_abs_addr(uint64_t slot_index) {
    return PMA_SHADOW_TLB_START + USE * sizeof(shadow_tlb_set) + slot_index * sizeof(shadow_tlb_slot);
}

template <TLB_set_use USE>
constexpr uint64_t shadow_tlb_get_vaddr_page_abs_addr(uint64_t slot_index) {
    return shadow_tlb_get_slot_abs_addr<USE>(slot_index) + offsetof(shadow_tlb_slot, vaddr_page);
}

template <TLB_set_use USE>
constexpr uint64_t shadow_tlb_get_vp_offset_abs_addr(uint64_t slot_index) {
    return shadow_tlb_get_slot_abs_addr<USE>(slot_index) + offsetof(shadow_tlb_slot, vp_offset);
}

template <TLB_set_use USE>
constexpr uint64_t shadow_tlb_get_pma_index_abs_addr(uint64_t slot_index) {
    return shadow_tlb_get_slot_abs_addr<USE>(slot_index) + offsetof(shadow_tlb_slot, pma_index);
}

} // namespace cartesi

#endif
