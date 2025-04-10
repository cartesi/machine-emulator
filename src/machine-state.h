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

#ifndef MACHINE_STATE_H
#define MACHINE_STATE_H

/// \file
/// \brief Cartesi machine state structure definition.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "address-range.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "tlb.h"

namespace cartesi {

/// \brief Machine state.
/// \details The machine_state structure contains the entire
/// state of a Cartesi machine.
struct machine_state final {
    machine_state() = default;
    ~machine_state() = default;

    /// \brief No copy or move constructor or assignment
    machine_state(const machine_state &other) = delete;
    machine_state(machine_state &&other) = delete;
    machine_state &operator=(const machine_state &other) = delete;
    machine_state &operator=(machine_state &&other) = delete;

    // Shadow region.
    registers_state registers;          ///< Registers
    uint64_t registers_padding_[406]{}; ///< Padding to align next field to a page boundary
    tlb_cold_state tlb_cold;            ///< TLB cold state

    // Penumbra region, the fields below are not stored in the backing file,
    // it's only visible in host resident memory during runtime.
    tlb_hot_state tlb_hot; ///< TLB hot state
};

static_assert(offsetof(machine_state, tlb_cold) % 4096 == 0, "tlb cold state must be aligned to a page boundary");
static_assert(offsetof(machine_state, tlb_hot) % 4096 == 0, "tlb hot state must be aligned to a page boundary");
static_assert(sizeof(machine_state) % 4096 == 0, "machine state size must be multiple of a page size");

} // namespace cartesi

#endif
