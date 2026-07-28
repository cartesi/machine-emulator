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

#include "zk-runtime.hpp"

#include "interpret.hpp"
#include "machine-hash.hpp"
#include "replay-step-state-access.hpp"
#include <cinttypes>
#include <cstring>

using namespace cartesi;

// eth-act IO interface, implemented by libzkevm.a. The host must push the
// whole step log in a single stdin.write_slice() -- read_input returns only
// the first chunk of the hint stream.
extern "C" void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern "C" void write_output(const uint8_t *output, size_t size);

int main() {
    const uint8_t *input = nullptr;
    size_t input_size = 0;
    read_input(&input, &input_size);
    // step_log::decode reinterprets the buffer as structs with uint64 fields; the wire
    // layout keeps every field 8-aligned relative to the buffer start.
    if ((reinterpret_cast<uintptr_t>(input) % 8) != 0) {
        zk_abort_with_msg("log buffer is not 8-byte aligned");
    }
    // The replay mutates the log in place (writes page data and re-zeroes the
    // per-page scratch hash slots); the input region is ordinary guest memory.
    auto *step_log_image = const_cast<uint8_t *>(input);

    replay_step_state_access::context context{};
    replay_step_state_access a(context, step_log_image, input_size);
    uint64_t mcycle_end{};
    // Saturate on overflow, matching machine::verify_step's saturating_add, so the
    // guest and the host replayer agree on the cycle target.
    if (__builtin_add_overflow(a.read_mcycle(), context.log.requested_cycle_count, &mcycle_end)) {
        mcycle_end = UINT64_MAX;
    }
    interpret<replay_step_state_access &>(a, mcycle_end);
    a.finish();

    // Public values are ABI-encoded as abi.encode(bytes32, uint64, bytes32) -- 96
    // bytes, identical to the RISC0 journal.
    uint8_t journal[96]{};
    std::memcpy(journal, context.log.root_hash_before.data(), 32);
    const uint64_t mcycle_count = context.log.requested_cycle_count;
    for (int i = 0; i < 8; i++) {
        journal[56 + i] = static_cast<uint8_t>(mcycle_count >> (56 - 8 * i));
    }
    std::memcpy(journal + 64, context.log.root_hash_after.data(), 32);
    write_output(journal, sizeof(journal));
    return 0;
}
