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

#include "uarch-runtime.h" // must be included first, because of assert

#include "compiler-defines.h"
#include "interpret.h"
#include "machine-uarch-bridge-state-access.h"
#include "mock-address-range.h"
#include "uarch-constants.h"
#include "uarch-ecall.h"

#include <array>
#include <cstdint>
#include <optional>

using namespace cartesi;

namespace cartesi {

// Declaration of explicit instantiation in module interpret.cpp when compiled with microarchitecture
extern template interpreter_break_reason interpret(machine_uarch_bridge_state_access a, uint64_t mcycle_end);

} // namespace cartesi

/// \brief  Advances one mcycle by executing the "big machine interpreter" compiled to the microarchitecture
/// \return This function never returns
extern "C" NO_RETURN void interpret_next_mcycle_with_uarch() {
    // Let the state accessor be on static memory storage to speed up uarch initialization
    static mock_address_ranges ars;
    const machine_uarch_bridge_state_access a(ars);
    const uint64_t mcycle_end = a.read_mcycle() + 1;
    interpret(a, mcycle_end);
    // Finished executing a whole mcycle: halt the microarchitecture
    ua_halt_ECALL();
    // The micro interpreter will never execute this line because the micro machine is halted
    __builtin_trap();
}
