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

#ifndef TLB_H
#define TLB_H

/// \file
/// \brief TLB definitions
/// \details The Translation Lookaside Buffer is a small cache used to speed up translation between address spaces.

#include <array>
#include <cstddef>
#include <cstdint>

#include "host-addr.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"

namespace cartesi {

/// \brief TLB set mode.
enum TLB_set_use : uint64_t { TLB_CODE, TLB_READ, TLB_WRITE, TLB_LAST_ = TLB_WRITE };

/// \brief TLB constants.
enum TLB_constants : uint64_t {
    TLB_SET_SIZE = 256,
    TLB_INVALID_PAGE = UINT64_C(-1),
    TLB_INVALID_PMA_INDEX = UINT64_C(-1)
};

/// \brief TLB hot slot.
struct tlb_hot_slot final {
    uint64_t vaddr_page; ///< Tag is the target virtual address of page start
    host_addr vh_offset; ///< Value is the offset from target virtual address in the same page to
                         ///< translated host address (vh_offset = haddr - vaddr)
};

using tlb_hot_set = std::array<tlb_hot_slot, TLB_SET_SIZE>;

/// \brief TLB cold slot.
struct tlb_cold_slot final {
    uint64_t pma_index; ///< Index of PMA where physical address falls
};

using tlb_cold_set = std::array<tlb_cold_slot, TLB_SET_SIZE>;

/// \brief TLB state.
struct tlb_state {
    std::array<tlb_hot_set, TLB_LAST_ + 1> hot;
    std::array<tlb_cold_set, TLB_LAST_ + 1> cold;
};

static_assert(sizeof(uint64_t) >= sizeof(uintptr_t), "TLB expects host pointer fit in 64 bits");
//??D why?
static_assert((sizeof(tlb_hot_slot) & (sizeof(tlb_hot_slot) - 1)) == 0, "TLB slot size must be a power of 2");
static_assert((sizeof(tlb_cold_slot) & (sizeof(tlb_cold_slot) - 1)) == 0, "TLB slot size must be a power of 2");

/// \brief Gets a TLB slot index for a page.
/// \param vaddr Target virtual address.
/// \returns TLB slot index.
constexpr uint64_t tlb_slot_index(uint64_t vaddr) {
    return (vaddr >> LOG2_PAGE_SIZE) & (TLB_SET_SIZE - 1);
}

/// \brief Checks for a TLB hit.
/// \tparam T Type of access needed (uint8_t, uint16_t, uint32_t, uint64_t).
/// \param slot_vaddr_page vaddr_page in TLB slot
/// \param vaddr Target virtual address being looked up.
/// \returns True on hit, false otherwise.
template <typename T>
constexpr bool tlb_is_hit(uint64_t slot_vaddr_page, uint64_t vaddr) {
    // Make sure misaligned accesses are always considered a miss
    // Otherwise, we could report a hit for a word that goes past the end of the page.
    // Aligned accesses smaller than a page size cannot straddle two pages.
    return slot_vaddr_page == (vaddr & ~(PAGE_OFFSET_MASK & ~(sizeof(T) - 1)));
}

constexpr uint64_t tlb_addr_page(uint64_t addr) {
    return addr & ~PAGE_OFFSET_MASK;
}

} // namespace cartesi

#endif
