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
#include "replay-step-state-access.h"
#include <cinttypes>

using namespace cartesi;

extern "C" void zkarch_replay_steps(
    interop_hash_type root_hash_before,
    unsigned char* step_log_image,
    uint64_t step_log_image_size,
    uint64_t mcycle_count, 
    interop_hash_type root_hash_after) 
{
    replay_step_state_access a(step_log_image, step_log_image_size, *reinterpret_cast<const replay_step_state_access::hash_type*>(root_hash_before));
    uint64_t mcycle_end{};
    (void) __builtin_add_overflow(a.read_mcycle(), mcycle_count, &mcycle_end);
    interpret(a, mcycle_end);
    a.finish(*reinterpret_cast<const replay_step_state_access::hash_type*>(root_hash_after));
}
