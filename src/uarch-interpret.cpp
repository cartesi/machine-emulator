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

#include "uarch-interpret.h"
#include "uarch-step.h"

namespace cartesi {

uarch_interpreter_break_reason uarch_interpret(uarch_state_access &a, uint64_t cycle_end) {
    uint64_t cycle = a.read_cycle();
    if (cycle_end < cycle) {
        throw std::invalid_argument{"uarch_cycle is past"};
    }
    while (cycle < cycle_end) {
        uarch_step_status status = uarch_step(a);
        switch (status) {
            case uarch_step_status::success:
                cycle += 1;
                break;
            case uarch_step_status::uarch_halted:
                return uarch_interpreter_break_reason::uarch_halted;
            // LCOV_EXCL_START
            case uarch_step_status::cycle_overflow:
                // Prior condition ensures that this case is unreachable. but linter may complain about missing it
                return uarch_interpreter_break_reason::reached_target_cycle;
                // LCOV_EXCL_STOP
        }
    }
    return uarch_interpreter_break_reason::reached_target_cycle;
}

} // namespace cartesi
