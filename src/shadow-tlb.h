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

#ifndef SHADOW_TLB_H
#define SHADOW_TLB_H

/// \file
/// \brief TLB device.
/// \details The Translation Lookaside Buffer is a small cache used to speed up translation between
/// virtual target addresses and the corresponding memory address in the host.

#include "compiler-defines.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"
#include <array>
#include <cstddef>

namespace cartesi {

extern const pma_driver shadow_tlb_driver;

/// \brief TLB entry type.
enum TLB_entry_type : uint64_t { TLB_CODE, TLB_READ, TLB_WRITE };

/// \brief TLB constants.
enum TLB_constants : uint64_t { TLB_INVALID_PAGE = UINT64_C(-1), TLB_INVALID_PMA = PMA_MAX };

/// \brief TLB hot entry.
struct tlb_hot_entry final {
    uint64_t vaddr_page; ///< Target virtual address of page start
    uint64_t vh_offset;  ///< Offset that maps target virtual addresses directly to host addresses.
};

/// \brief TLB cold entry.
struct tlb_cold_entry final {
    uint64_t paddr_page; ///< Target physical address of page start
    uint64_t pma_index;  ///< PMA entry index for corresponding range
};

/// \brief TLB state.
struct shadow_tlb_state final {
    // The TLB state is split in hot and cold regions.
    // The hot region is accessed with very high frequency every hit check,
    // while the cold region with low frequency only when replacing or flushing write TLB entries.
    //
    // Splitting into hold and cold regions increases host CPU cache usage when checking TLB hits,
    // due to more data locality, therefore improving the TLB performance.
    std::array<std::array<tlb_hot_entry, PMA_TLB_SIZE>, 3> hot;
    std::array<std::array<tlb_cold_entry, PMA_TLB_SIZE>, 3> cold;
};

//??E Do we even want to support 128 bit systems someday?
// Make sure uint64_t is large enough to hold host pointers, otherwise 'vh_offset' field will not work correctly.
static_assert(sizeof(uint64_t) >= sizeof(uintptr_t), "TLB expects host pointer to be at maximum 64bit");

// This TLB algorithm assumes the following conditions
static_assert((sizeof(tlb_hot_entry) & (sizeof(tlb_hot_entry) - 1)) == 0 &&
        (sizeof(tlb_cold_entry) & (sizeof(tlb_cold_entry) - 1)) == 0,
    "TLB entry size must be a power of 2");
static_assert(PMA_SHADOW_TLB_LENGTH % sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>) == 0 &&
        PMA_SHADOW_TLB_LENGTH % sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>) == 0,
    "code assumes PMA TLB length is divisible by TLB entry array size");
static_assert(PMA_SHADOW_TLB_LENGTH == sizeof(shadow_tlb_state),
    "code assumes PMA TLB length is equal to TLB state size");

/// \brief Gets a TLB entry index.
/// \param vaddr Target virtual address.
static inline uint64_t tlb_get_entry_index(uint64_t vaddr) {
    return (vaddr >> PAGE_NUMBER_SHIFT) & (PMA_TLB_SIZE - 1);
}

/// \brief Checks for a TLB hit.
/// \tparam T Type of access needed (uint8_t, uint16_t, uint32_t, uint64_t).
/// \param vaddr_page Target virtual address of page start of a TLB entry
/// \param vaddr Target virtual address.
/// \returns True on hit, false otherwise.
template <typename T>
static inline bool tlb_is_hit(uint64_t vaddr_page, uint64_t vaddr) {
    // Make sure misaligned accesses are always considered a miss
    // Otherwise, we could report a hit for a word that goes past the end of the PMA range.
    // Aligned accesses cannot do so because the PMA ranges
    // are always page-aligned.
    return (vaddr_page == (vaddr & ~(PAGE_OFFSET_MASK & ~(sizeof(T) - 1))));
}

template <TLB_entry_type ETYPE>
static inline uint64_t tlb_get_entry_hot_abs_addr(uint64_t eidx) {
    return PMA_SHADOW_TLB_START + offsetof(shadow_tlb_state, hot) +
        (ETYPE * sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>)) + (eidx * sizeof(tlb_hot_entry));
}

template <TLB_entry_type ETYPE>
static inline uint64_t tlb_get_entry_cold_abs_addr(uint64_t eidx) {
    return PMA_SHADOW_TLB_START + offsetof(shadow_tlb_state, cold) +
        (ETYPE * sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>)) + (eidx * sizeof(tlb_cold_entry));
}

template <TLB_entry_type ETYPE>
static inline uint64_t tlb_get_vaddr_page_rel_addr(uint64_t eidx) {
    return offsetof(shadow_tlb_state, hot) + (ETYPE * sizeof(std::array<tlb_hot_entry, PMA_TLB_SIZE>)) +
        (eidx * sizeof(tlb_hot_entry)) + offsetof(tlb_hot_entry, vaddr_page);
}

template <TLB_entry_type ETYPE>
static inline uint64_t tlb_get_paddr_page_rel_addr(uint64_t eidx) {
    return offsetof(shadow_tlb_state, cold) + (ETYPE * sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>)) +
        (eidx * sizeof(tlb_cold_entry)) + offsetof(tlb_cold_entry, paddr_page);
}

template <TLB_entry_type ETYPE>
static inline uint64_t tlb_get_pma_index_rel_addr(uint64_t eidx) {
    return offsetof(shadow_tlb_state, cold) + (ETYPE * sizeof(std::array<tlb_cold_entry, PMA_TLB_SIZE>)) +
        (eidx * sizeof(tlb_cold_entry)) + offsetof(tlb_cold_entry, pma_index);
}

} // namespace cartesi

#endif
