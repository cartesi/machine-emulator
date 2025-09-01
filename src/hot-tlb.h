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

#ifndef HOT_TLB_H
#define HOT_TLB_H

/// \file
/// \brief TLB definitions
/// \details The Translation Lookaside Buffer is a small cache used to speed up translation between address spaces.

#include <array>
#include <cstdint>

#include "host-addr.h"
#include "shadow-tlb.h"

namespace cartesi {

/// \brief Hot TLB slot.
/// \details
/// Given a target virtual address vaddr within a page matching vaddr_page in TLB slot, the corresponding host address
/// haddr = vaddr + vh_offset.
struct hot_tlb_slot final {
    uint64_t vaddr_page{TLB_INVALID_PAGE}; ///< Target virtual address of start of page
    host_addr vh_offset{0};                ///< Offset from target virtual address in the same page to host address
};

using hot_tlb_set = std::array<hot_tlb_slot, TLB_SET_SIZE>;
using hot_tlb_state = std::array<hot_tlb_set, TLB_NUM_SETS_>;

static_assert(sizeof(uint64_t) >= sizeof(uintptr_t), "TLB expects host pointer fit in 64 bits");

// We need to ensure TLB state sizes are fixed across different platforms
static_assert(sizeof(hot_tlb_state) == 3 * TLB_SET_SIZE * 2 * sizeof(uint64_t), "unexpected hot TLB state size");
static_assert(alignof(hot_tlb_state) == sizeof(uint64_t), "unexpected hot TLB state alignment");

} // namespace cartesi

#endif
