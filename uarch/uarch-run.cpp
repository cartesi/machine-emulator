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

// Must be included first, because of assert
#include "uarch-runtime.hpp" // IWYU pragma: keep

#include "compiler-defines.hpp"
#include "interpret.hpp"
#include "lazy-address-ranges.hpp"
#include "uarch-bridge-state-access.hpp"
#include "uarch-ecall.hpp"

#include <cstdint>

using namespace cartesi;

namespace cartesi {

// Declaration of explicit instantiation in module interpret.cpp when compiled with uarch
extern template interpreter_break_reason interpret(uarch_bridge_state_access a, uint64_t mcycle_end);

} // namespace cartesi

// Address ranges of the machine whose mcycle is being advanced. Guest RAM returns to its pristine contents
// before every mcycle, so each one starts with no range created. Each guest instruction and each page
// touched is paid for in the proof: page-aligned, the ranges occupy one page, and constant-initialized at
// namespace scope, they need no initialization or destructor registration at run time.
static_assert(sizeof(lazy_address_ranges) <= AR_PAGE_SIZE);
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
alignas(AR_PAGE_SIZE) static constinit lazy_address_ranges ranges;

/// \brief  Advances one mcycle by executing the "big machine interpreter" compiled to the uarch
/// \return This function never returns
extern "C" NO_RETURN void interpret_next_mcycle_with_uarch() {
    const uarch_bridge_state_access a(ranges);
    const uint64_t mcycle_end = a.read_mcycle() + 1;
    interpret(a, mcycle_end);
    // Finished executing a whole mcycle: halt the uarch
    ua_halt_ECALL();
    // The uarch interpreter will never execute this line because the uarch is halted
    __builtin_trap();
}
