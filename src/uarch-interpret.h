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

#ifndef UARCH_INTERPRET_H
#define UARCH_INTERPRET_H

#include <cstdint>

namespace cartesi {

// Forward declaration
class uarch_state_access;

enum class uarch_interpreter_break_reason : int { reached_target_cycle, uarch_halted };

// Run the microarchitecture interpreter until cycle hits a target or a fixed point is reached
uarch_interpreter_break_reason uarch_interpret(uarch_state_access &a, uint64_t uarch_cycle_end);

} // namespace cartesi

#endif
