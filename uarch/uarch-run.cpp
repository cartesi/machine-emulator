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

#define MICROARCHITECTURE 1

#include "uarch-runtime.h" // must be included first, because of assert

#include "interpret.h"
#include "uarch-machine-state-access.h"
#include <cinttypes>

using namespace cartesi;

static void set_uarch_halt_flag() {
    volatile uint64_t *uarch_halt_flag = reinterpret_cast<uint64_t *>(shadow_state_csr::uarch_halt_flag);
    *uarch_halt_flag = uarch_halt_flag_halt_value;
}

/// \brief  Advances one mcycle by executing the "big machine interpreter" compiled to the microarchitecture
/// \return This function never returns
extern "C" NO_RETURN void interpret_next_mcycle_with_uarch() {
    uarch_machine_state_access a;
    uint64_t mcycle_end = a.read_mcycle() + 1;
    interpret(a, mcycle_end);
    // Finished executing a whole mcycle: halt the microarchitecture
    set_uarch_halt_flag();
    // The micro interpreter will never execute this line because the micro machine is halted
    __builtin_trap();
}
