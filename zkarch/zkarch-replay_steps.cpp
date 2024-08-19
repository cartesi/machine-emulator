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

#define ZKARCHITECTURE 1

#include "zkarch-runtime.h"
#include "interpret.h"
#include "replay-multi-step-state-access.h"
#include <cinttypes>

using namespace cartesi;

extern "C" uint64_t zkarch_replay_steps(uint64_t steps, page_info *pages) {
    replay_multi_step_state_access a(pages);
    auto current_mcycle = a.read_mcycle();
    auto mcycle_end = current_mcycle + steps;
    interpret(a, mcycle_end);
    current_mcycle = a.read_mcycle();
    return (int)current_mcycle;
}
