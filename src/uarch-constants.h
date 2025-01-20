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

#ifndef UARCH_CONSTANTS_H
#define UARCH_CONSTANTS_H

#include "pma-constants.h"
#include "pma-defines.h"
#include "uarch-defines.h"

#include <cstdint>

namespace cartesi {

/// \brief uarch state constants
enum uarch_state_constants : uint64_t {
    UARCH_STATE_START_ADDRESS =
        EXPAND_UINT64_C(UARCH_STATE_START_ADDRESS_DEF), ///< Start address of the uarch state: shadow + ram
    UARCH_STATE_LOG2_SIZE = EXPAND_UINT64_C(UARCH_STATE_LOG2_SIZE_DEF), ///< Log2 size of the uarch state: shadow + ram
    UARCH_STATE_CHILD_LOG2_SIZE = UARCH_STATE_LOG2_SIZE - 1, ///< Log2 size of a uarch state child: shadow or ram
    UARCH_SHADOW_START_ADDRESS =
        EXPAND_UINT64_C(PMA_SHADOW_UARCH_STATE_START_DEF), ///< Start address of the shadow uarch state
    UARCH_SHADOW_LENGTH = EXPAND_UINT64_C(PMA_SHADOW_UARCH_STATE_LENGTH_DEF),   ///< Length of the shadow uarch state
    UARCH_RAM_START_ADDRESS = EXPAND_UINT64_C(PMA_UARCH_RAM_START_DEF),         ///< Start address of the uarch ram
    UARCH_RAM_LENGTH = EXPAND_UINT64_C(PMA_UARCH_RAM_LENGTH_DEF),               ///< Length of the uarch ram
    UARCH_STATE_ALIGN_MASK = (EXPAND_UINT64_C(1) << UARCH_STATE_LOG2_SIZE) - 1, ///< Mask for uarch state alignment
    UARCH_STATE_MASK = ~UARCH_STATE_ALIGN_MASK,                                 ///< Mask for uarch state address space
    UARCH_STATE_CHILD_ALIGN_MASK =
        (EXPAND_UINT64_C(1) << UARCH_STATE_CHILD_LOG2_SIZE) - 1 ///< Mask for uarch state child alignment
};

static_assert((UARCH_STATE_START_ADDRESS & UARCH_STATE_ALIGN_MASK) == 0,
    "UARCH_STATE_START_ADDRESS must be aligned to UARCH_STATE_LOG2_SIZE");
static_assert((UARCH_SHADOW_START_ADDRESS & UARCH_STATE_MASK) == UARCH_STATE_START_ADDRESS,
    "UARCH_SHADOW_START_ADDRESS must be within uarch state address space");
static_assert((UARCH_RAM_START_ADDRESS & UARCH_STATE_MASK) == UARCH_STATE_START_ADDRESS,
    "UARCH_RAM_START_ADDRESS must be within uarch state address space");
static_assert((UARCH_SHADOW_START_ADDRESS & UARCH_STATE_CHILD_ALIGN_MASK) == 0,
    "UARCH_SHADOW_START_ADDRESS must be aligned to UARCH_STATE_LOG2_SIZE");
static_assert((UARCH_RAM_START_ADDRESS & UARCH_STATE_CHILD_ALIGN_MASK) == 0,
    "UARCH_RAM_START_ADDRESS must be aligned to UARCH_STATE_LOG2_SIZE");
static_assert(UARCH_RAM_LENGTH <= (static_cast<uint64_t>(1) << UARCH_STATE_CHILD_LOG2_SIZE),
    "UARCH_RAM_LENGTH is too big");
static_assert(UARCH_SHADOW_LENGTH <= (static_cast<uint64_t>(1) << UARCH_STATE_CHILD_LOG2_SIZE),
    "UARCH_SHADOW_LENGTH is too big");
static_assert(UARCH_SHADOW_START_ADDRESS < UARCH_RAM_START_ADDRESS,
    "UARCH_SHADOW_START_ADDRESS must be smaller than UARCH_RAN_START_ADDRESS");
static_assert((UARCH_SHADOW_LENGTH & (PMA_PAGE_SIZE - 1)) == 0,
    "UARCH_SHADOW_LENGTH must be multiple of PMA_PAGE_SIZE");
static_assert((UARCH_RAM_LENGTH & (PMA_PAGE_SIZE - 1)) == 0, "UARCH_RAM_LENGTH must be multiple of PMA_PAGE_SIZE");

/// \brief ecall function codes
enum uarch_ecall_functions : uint64_t {
    UARCH_ECALL_FN_HALT = EXPAND_UINT64_C(UARCH_ECALL_FN_HALT_DEF),                       ///< halt uarch execution
    UARCH_ECALL_FN_PUTCHAR = EXPAND_UINT64_C(UARCH_ECALL_FN_PUTCHAR_DEF),                 ///< putchar
    UARCH_ECALL_FN_MARK_DIRTY_PAGE = EXPAND_UINT64_C(UARCH_ECALL_FN_MARK_DIRTY_PAGE_DEF), ///< mark_dirty_page
    UARCH_ECALL_FN_WRITE_TLB = EXPAND_UINT64_C(UARCH_ECALL_FN_WRITE_TLB_DEF),             ///< write_tlb
};

} // namespace cartesi

#endif
