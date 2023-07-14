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

#include "uarch-interpret.h"
#include "uarch-step.h"

namespace cartesi {

uarch_interpreter_break_reason uarch_interpret(uarch_state_access &a, uint64_t cycle_end) {
    uint64_t cycle = a.read_cycle();
    if (cycle_end < cycle) {
        throw std::invalid_argument{"uarch_cycle is past"};
    }
    while (cycle < cycle_end) {
        const UArchStepStatus status = uarch_step(a);
        switch (status) {
            case UArchStepStatus::Success:
                cycle += 1;
                break;
            case UArchStepStatus::UArchHalted:
                return uarch_interpreter_break_reason::uarch_halted;
            // LCOV_EXCL_START
            case UArchStepStatus::CycleOverflow:
                // Prior condition ensures that this case is unreachable. but linter may complain about missing it
                return uarch_interpreter_break_reason::reached_target_cycle;
                // LCOV_EXCL_STOP
        }
    }
    return uarch_interpreter_break_reason::reached_target_cycle;
}

} // namespace cartesi
