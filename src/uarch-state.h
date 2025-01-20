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

#ifndef UARCH_STATE_H
#define UARCH_STATE_H

/// \file
/// \brief Cartesi microarchitecture machine state structure definition.

#include <array>
#include <cstdint>

#include "pma.h"
#include "riscv-constants.h"

namespace cartesi {

struct uarch_state {
    uarch_state() = default;
    ~uarch_state() = default;

    /// \brief No copy or move constructor or assignment
    uarch_state(const uarch_state &other) = delete;
    uarch_state(uarch_state &&other) = delete;
    uarch_state &operator=(const uarch_state &other) = delete;
    uarch_state &operator=(uarch_state &&other) = delete;

    uint64_t pc{};                               ///< Program counter.
    std::array<uint64_t, UARCH_X_REG_COUNT> x{}; ///< Register file.
    uint64_t cycle{};                            ///< Cycles counter
    uint64_t halt_flag{};
    pma_entry shadow_state; ///< Shadow uarch state
    pma_entry ram;          ///< Memory range for micro RAM
    pma_entry empty_pma;    ///< Empty range fallback
};

} // namespace cartesi

#endif
