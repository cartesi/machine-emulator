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
#include "pmas-constants.h"
#include "riscv-constants.h"

namespace cartesi {

/// \brief Index of TLB set
enum TLB_set_index : uint64_t { TLB_CODE, TLB_READ, TLB_WRITE, TLB_LAST_ = TLB_WRITE, TLB_NUM_SETS_ = TLB_WRITE + 1 };

/// \brief TLB constants.
enum TLB_constants : uint64_t {
    TLB_SET_SIZE = 256,
    TLB_INVALID_PAGE = UINT64_C(-1),
    TLB_INVALID_PMA_INDEX = UINT64_C(-1),
};

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

/// \brief Shadow TLB slot
/// \details
/// Given a target virtual address vaddr within a page matching vaddr_page in TLB slot, the corresponding
/// target physical address paddr = vaddr + vp_offset.
/// The pma_index helps translate between target physical addresses and host addresses when needed.
/// Writes to TLB slots have to be atomic.
/// We can only do /aligned/ atomic writes.
/// Therefore, TLB slot cannot be misaligned.
/// To complete the power-of-two size, we include a zero_padding_ entry.
struct shadow_tlb_slot final {
    uint64_t vaddr_page{TLB_INVALID_PAGE}; ///< Target virtual address of start of page
    uint64_t vp_offset{0}; ///< Offset from target virtual address to target physical address within page
    uint64_t pma_index{TLB_INVALID_PMA_INDEX}; ///< Index of PMA where physical page falls and host addresses
    uint64_t zero_padding_{0};                 ///< Padding to make sure the sizeof(shadow_tlb_slot) is a power of 2
};

constexpr uint64_t SHADOW_TLB_SLOT_SIZE = sizeof(shadow_tlb_slot);
static_assert((SHADOW_TLB_SLOT_SIZE & (SHADOW_TLB_SLOT_SIZE - 1)) == 0, "shadow TLB slot size must be power of two");
constexpr uint64_t SHADOW_TLB_SLOT_LOG2_SIZE = 5;
static_assert((UINT64_C(1) << SHADOW_TLB_SLOT_LOG2_SIZE) == SHADOW_TLB_SLOT_SIZE, "shadow TLB slot log2 size is wrong");

/// \brief Shadow TLB set
using shadow_tlb_set = std::array<shadow_tlb_slot, TLB_SET_SIZE>;

/// \brief Shadow TLB memory layout
using shadow_tlb_state = std::array<shadow_tlb_set, TLB_LAST_ + 1>; // one set for code, one for read and one for write

static_assert(AR_SHADOW_TLB_LENGTH >= sizeof(shadow_tlb_state), "TLB state must fit in TLB shadow");

/// \brief List of field types
enum class shadow_tlb_what : uint64_t {
    vaddr_page = offsetof(shadow_tlb_slot, vaddr_page),
    vp_offset = offsetof(shadow_tlb_slot, vp_offset),
    pma_index = offsetof(shadow_tlb_slot, pma_index),
    zero_padding_ = offsetof(shadow_tlb_slot, zero_padding_),
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

static constexpr uint64_t shadow_tlb_get_abs_addr(TLB_set_index set_index, uint64_t slot_index) {
    return AR_SHADOW_TLB_START + (set_index * sizeof(shadow_tlb_set)) + (slot_index * sizeof(shadow_tlb_slot));
}

static constexpr uint64_t shadow_tlb_get_abs_addr(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) {
    return shadow_tlb_get_abs_addr(set_index, slot_index) + static_cast<uint64_t>(what);
}

static constexpr shadow_tlb_what shadow_tlb_get_what(uint64_t paddr, TLB_set_index &set_index, uint64_t &slot_index) {
    if (paddr < AR_SHADOW_TLB_START || paddr - AR_SHADOW_TLB_START >= sizeof(shadow_tlb_state) ||
        (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return shadow_tlb_what::unknown_;
    }
    paddr -= AR_SHADOW_TLB_START;
    set_index = TLB_set_index{paddr / sizeof(shadow_tlb_set)};
    slot_index = (paddr % sizeof(shadow_tlb_set)) / sizeof(shadow_tlb_slot);
    return shadow_tlb_what{paddr % sizeof(shadow_tlb_slot)};
}

static constexpr const char *shadow_tlb_get_what_name(shadow_tlb_what what) {
    const auto offset = static_cast<uint64_t>(what);
    using reg = shadow_tlb_what;
    if (offset > static_cast<uint64_t>(reg::unknown_) || (offset & (sizeof(uint64_t) - 1)) != 0) {
        return "tlb.unknown_";
    }
    switch (what) {
        case reg::vaddr_page:
            return "tlb.slot.vaddr_page";
        case reg::vp_offset:
            return "tlb.slot.vp_offset";
        case reg::pma_index:
            return "tlb.slot.pma_index";
        case reg::zero_padding_:
            return "tlb.slot.zero_padding_";
        case reg::unknown_:
            return "tlb.unknown_";
    }
    return "tlb.unknown_";
}

[[maybe_unused]] static void shadow_tlb_fill_slot(uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index,
    shadow_tlb_slot &slot) {
    slot.vaddr_page = vaddr_page;
    slot.vp_offset = vp_offset;
    slot.pma_index = pma_index;
    slot.zero_padding_ = 0;
}

} // namespace cartesi

#endif
