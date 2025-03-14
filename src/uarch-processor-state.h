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

#ifndef UARCH_PROCESSOR_STATE_H
#define UARCH_PROCESSOR_STATE_H

/// \file
/// \brief Cartesi microarchitecture machine processor state structure definition.

#include <array>
#include <cstdint>
#include <memory>

#include "memory-address-range.h"
#include "riscv-constants.h"
#include "shadow-uarch-state.h"

namespace cartesi {

struct uarch_processor_state final {
    uarch_registers_state registers;    ///< Uarch registers
    uint64_t registers_padding_[477]{}; ///< Padding to align next field to a page boundary
};

static_assert(sizeof(uarch_processor_state) % 4096 == 0, "uarch processor state size must be multiple of a page size");

} // namespace cartesi

#endif
