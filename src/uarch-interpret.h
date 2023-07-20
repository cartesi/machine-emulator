// Copyright 2019 Cartesi Pte. Ltd.
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

#ifndef UARCH_INTERPRET_H
#define UARCH_INTERPRET_H

#include "uarch-state-access.h"

namespace cartesi {

enum class uarch_interpreter_break_reason : int { reached_target_cycle, uarch_halted };

// Run the microarchitecture interpreter until cycle hits a target or a fixed point is reached
uarch_interpreter_break_reason uarch_interpret(uarch_state_access &a, uint64_t uarch_cycle_end);

} // namespace cartesi

#endif
