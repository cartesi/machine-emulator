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

#include "uarch-interpret.hpp"

#include <cstdint>

#include "collect-uarch-cycle-hashes-state-access.hpp" // IWYU pragma: keep
#include "riscv-constants.hpp"
#include "uarch-constants.hpp"
#include "uarch-state-access.hpp" // IWYU pragma: keep
#include "uarch-step.hpp"

namespace cartesi {

uarch_interpreter_break_reason uarch_halt_to_interpreter_break_reason(uint64_t uarch_halt) {
    return uarch_halt == UARCH_HALT_CYCLE_OVERFLOW ? uarch_interpreter_break_reason::uarch_cycle_overflow :
                                                     uarch_interpreter_break_reason::uarch_halted;
}

template <typename STATE_ACCESS>
uarch_interpreter_break_reason uarch_interpret(const STATE_ACCESS a, uint64_t cycle_end) {
    uint64_t cycle = a.read_uarch_cycle();
    if (cycle_end < cycle) {
        throw std::invalid_argument{"uarch_cycle is past"};
    }
    if (cycle == cycle_end) {
        return uarch_interpreter_break_reason::reached_target_uarch_cycle;
    }
    const uint64_t halt = a.read_uarch_halt();
    if (halt != 0) {
        return uarch_halt_to_interpreter_break_reason(halt);
    }
    if (cycle >= UARCH_CYCLE_MAX) {
        a.write_uarch_halt(UARCH_HALT_CYCLE_OVERFLOW);
        return uarch_interpreter_break_reason::uarch_cycle_overflow;
    }
    while (cycle < cycle_end) {
        const UArchStepStatus status = uarch_step(a);
        switch (status) {
            case UArchStepStatus::Success:
                cycle += 1;
                break;
            case UArchStepStatus::UArchHalted:
                return uarch_interpreter_break_reason::uarch_halted;
            case UArchStepStatus::UArchCycleOverflow:
                return uarch_interpreter_break_reason::uarch_cycle_overflow;
        }
    }
    return uarch_interpreter_break_reason::reached_target_uarch_cycle;
}

// Explicit instantiation for uarch_state_access
template uarch_interpreter_break_reason uarch_interpret(const uarch_state_access a, uint64_t uarch_cycle_end);

// Explicit instantiation for collect_uarch_cycle_hashes_state_access
template uarch_interpreter_break_reason uarch_interpret(const collect_uarch_cycle_hashes_state_access a,
    uint64_t uarch_cycle_end);

} // namespace cartesi
