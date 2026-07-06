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

//#define ZKARCHITECTURE 1

#include "zk-runtime.hpp"
#include "machine-hash.hpp"
#include "interpret.hpp"
#include "replay-step-state-access.hpp"
#include <cinttypes>
#include <cstring>

using namespace cartesi;

extern "C" void risc0_replay_steps(
    unsigned char* step_log_image,
    uint64_t step_log_image_size,
    unsigned char* out_root_hash_before,
    uint64_t* out_mcycle_count,
    unsigned char* out_root_hash_after)
{
    replay_step_state_access::context context{};
    replay_step_state_access a(context, step_log_image, step_log_image_size);
    uint64_t mcycle_end{};
    // Saturate on overflow, matching machine::verify_step's saturating_add, so the RISC0
    // guest and the host replayer agree on the cycle target.
    if (__builtin_add_overflow(a.read_mcycle(), context.log.requested_cycle_count, &mcycle_end)) {
        mcycle_end = UINT64_MAX;
    }
    interpret<replay_step_state_access&>(a, mcycle_end);
    a.finish();
    std::memcpy(out_root_hash_before, context.log.root_hash_before.data(), 32);
    *out_mcycle_count = context.log.requested_cycle_count;
    std::memcpy(out_root_hash_after, context.log.root_hash_after.data(), 32);
}
