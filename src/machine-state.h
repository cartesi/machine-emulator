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
    registers_state registers; ///< Registers

    // Penumbra region, the fields below are not stored in the backing file,
    // it's only visible in host resident memory during runtime.
    tlb_state tlb{};            ///< TLB state
    bool soft_yield{};          ///< Whether soft yield is enabled
    std::vector<uint64_t> pmas; ///< Indices of address ranges that interpret can find
};

} // namespace cartesi

#endif
