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

#include <stdexcept>

#include "machine.h"
#include "uarch-execute-insn.h"
#include "uarch-interpret.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-state-access.h"

namespace cartesi {

template <typename STATE_ACCESS>
uarch_interpreter_break_reason uarch_interpret(STATE_ACCESS &a, uint64_t cycle_end) {
    // This must be the first read because we assume the first log access is a
    // uarch_cycle read in machine::verify_state_transition
    auto cycle = readCycle(a);
    while (cycle < cycle_end) {
        if (readHaltFlag(a)) {
            return uarch_interpreter_break_reason::halted;
        }
        auto pc = readPc(a);
        auto insn = readUint32(a, pc);
        uarchExecuteInsn(a, insn, pc);
        cycle = cycle + 1;
        writeCycle(a, cycle);
    }
    return uarch_interpreter_break_reason::reached_target_cycle;
}

// Explicit instantiation for uarch_state_access
template uarch_interpreter_break_reason uarch_interpret(uarch_state_access &a, uint64_t uarch_cycle_end);

// Explicit instantiation for uarch_record_state_access
template uarch_interpreter_break_reason uarch_interpret(uarch_record_state_access &a, uint64_t uarch_cycle_end);

// Explicit instantiation for uarch_replay_state_access
template uarch_interpreter_break_reason uarch_interpret(uarch_replay_state_access &a, uint64_t uarch_cycle_end);

} // namespace cartesi
