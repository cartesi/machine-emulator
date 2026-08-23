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

#ifndef PROCESSOR_STATE_HPP
#define PROCESSOR_STATE_HPP

/// \file
/// \brief Cartesi machine processor state structure definition.

#include <cstddef>
#include <cstdint>

#include "address-range-constants.hpp"
#include "hot-tlb.hpp"
#include "machine-hash.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"

namespace cartesi {

/// brief Shadow state.
/// \details It's stored in the processor backing file.
struct shadow_state final {
    registers_state registers;          ///< Registers state
    uint64_t registers_padding_[401]{}; ///< Padding to align next field to a page boundary
    machine_hash revert_root_hash{};    ///< Revert root hash
    shadow_tlb_state tlb;               ///< Shadow TLB state
    uint64_t tlb_padding_[3584]{};      ///< Padding to align next field to a page boundary
};

class machine;

/// \brief Penumbra state.
/// \details It's not stored in the processor backing file, it's only visible in host memory during runtime.
struct penumbra_state final {
    hot_tlb_state tlb;           ///< Hot TLB state
    machine *owner{};            ///< Machine holding this state
    host_addr fetch_vf_offset{}; ///< Fetch mapping offset of the current code page
    /// \brief Cached translation-context slot base (tlb_ctx * TLB_SET_SIZE).
    /// \details Maintained by the stateful machine's iprv/mstatus writes and
    /// recomputed at interpret entry; boots in M-mode.
    uint64_t tlb_ctx_slot_base{3 * TLB_SET_SIZE};
    /// \brief Host-write notification hook, null unless a runtime consumer of
    /// guest memory bytes (the trace backend) has derived state to invalidate.
    /// \details Called wherever guest RAM bytes can change: at write-TLB slot
    /// establishment (fill and re-verification), and at the host-side write
    /// choke points. The extent is conservative (whole pages are fine).
    void (*write_hook)(void *ctx, host_addr hstart, uint64_t length){};
    void *write_hook_ctx{};        ///< Opaque context for write_hook
    uint64_t hard_float_enabled{}; ///< Current interpret call proved the host FP environment safe
    /// \brief Opaque per-machine state owned by a runtime consumer of the
    /// interpreter (the trace backend), allocated on first use.
    /// \details The machine destructor releases it through tc_state_free, so
    /// recorded traces die with the machine that recorded them instead of
    /// outliving it in thread storage.
    void *tc_state{};
    void (*tc_state_free)(void *){};
    uint64_t scratch[504]{}; ///< Interpreter loop scratch area; also aligns penumbra state size to a page boundary
};

/// \brief Machine processor state.
/// \details Contains the registers and TLB state of a machine.
struct processor_state final {
    shadow_state shadow;             ///< Shadow state
    mutable penumbra_state penumbra; ///< Penumbra state (mutable: out-of-state runtime cache)
};

static_assert(offsetof(shadow_state, tlb) % AR_PAGE_SIZE == 0, "shadow tlb state must be aligned to a page boundary");
static_assert(offsetof(processor_state, penumbra) % AR_PAGE_SIZE == 0,
    "penumbra state must be aligned to a page boundary");
static_assert(offsetof(shadow_state, revert_root_hash) == AR_SHADOW_REVERT_ROOT_HASH_START,
    "unexpected shadow revert root hash start");

static_assert(sizeof(processor_state) % AR_PAGE_SIZE == 0, "processor state size must be multiple of a page size");
static_assert(sizeof(shadow_state) == AR_SHADOW_STATE_LENGTH, "unexpected shadow state size");

// The size of the shadow state should align with the largest page size used by the supported operating systems.
// For instance, macOS on arm64 currently utilizes a page size of 16KB.
// Doing this ensures that memory allocations made with os::mapped_memory()
// result in the backing shadow file occupying whole pages, avoiding partial page mappings.
static_assert(sizeof(shadow_state) % 16384 == 0, "shadow state size must be multiple of a 16KB");

} // namespace cartesi

#endif
