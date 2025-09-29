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

#ifndef PROCESSOR_STATE_H
#define PROCESSOR_STATE_H

/// \file
/// \brief Cartesi machine processor state structure definition.

#include <cstddef>
#include <cstdint>

#include "address-range-constants.h"
#include "hot-tlb.h"
#include "shadow-registers.h"
#include "shadow-tlb.h"

namespace cartesi {

/// brief Shadow state.
/// \details It's stored in the processor backing file.
struct shadow_state final {
    registers_state registers;          ///< Registers state
    uint64_t registers_padding_[406]{}; ///< Padding to align next field to a page boundary
    shadow_tlb_state tlb;               ///< Shadow TLB state
    uint64_t tlb_padding_[512]{};       ///< Padding to align next field to a page boundary
};

/// \brief Penumbra state.
/// \details It's not stored in the processor backing file, it's only visible in host memory during runtime.
struct penumbra_state final {
    hot_tlb_state tlb; ///< Hot TLB state
};

/// \brief Machine processor state.
/// \details Contains the registers and TLB state of a machine.
struct processor_state final {
    shadow_state shadow;     ///< Shadow state
    penumbra_state penumbra; ///< Penumbra state
};

static_assert(offsetof(shadow_state, tlb) % AR_PAGE_SIZE == 0, "shadow tlb state must be aligned to a page boundary");
static_assert(offsetof(processor_state, penumbra) % AR_PAGE_SIZE == 0,
    "penumbra state must be aligned to a page boundary");

static_assert(sizeof(processor_state) % AR_PAGE_SIZE == 0, "processor state size must be multiple of a page size");
static_assert(sizeof(shadow_state) == AR_SHADOW_STATE_LENGTH, "unexpected shadow state size");

// The size of the shadow state should align with the largest page size used by the supported operating systems.
// For instance, macOS on arm64 currently utilizes a page size of 16KB.
// Doing this ensures that memory allocations made with os::mapped_memory()
// result in the backing shadow file occupying whole pages, avoiding partial page mappings.
static_assert(sizeof(shadow_state) % 16384 == 0, "shadow state size must be multiple of a 16KB");

} // namespace cartesi

#endif
