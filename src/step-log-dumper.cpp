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

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "hex.hpp"
#include "machine.hpp"
#include "step-log-data.hpp"
#include "step-log-dumper.hpp"
#include "uarch-replay-step-state-access.hpp"
#include "uarch-reset-state.hpp"
#include "uarch-step.hpp"

namespace cartesi {

void step_log_dumper::read(const char *name, uint64_t paddr, uint64_t val) {
    if (m_muted) {
        return;
    }
    line() << "read " << (name != nullptr ? name : machine::get_address_name(paddr)) << "@0x" << std::hex << paddr
           << ": 0x" << val << std::dec << '(' << val << ")\n";
}

void step_log_dumper::write(const char *name, uint64_t paddr, uint64_t old_val, uint64_t new_val) {
    if (m_muted) {
        return;
    }
    line() << "write " << (name != nullptr ? name : machine::get_address_name(paddr)) << "@0x" << std::hex << paddr
           << ": 0x" << old_val << std::dec << '(' << old_val << ") -> 0x" << std::hex << new_val << std::dec << '('
           << new_val << ")\n";
}

void step_log_dumper::write_hash(const char *name, uint64_t paddr, int log2_size, const_machine_hash_view old_hash,
    const_machine_hash_view new_hash) {
    if (m_muted) {
        return;
    }
    // Same shape the JSON access log printer used for big writes: abbreviated hashes with the size
    const auto abbreviated = [](const_machine_hash_view hash) { return encode_hex(hash).substr(0, 10); };
    line() << "write " << name << "@0x" << std::hex << paddr << std::dec << ": hash:\"" << abbreviated(old_hash)
           << "\"(2^" << log2_size << " bytes) -> hash:\"" << abbreviated(new_hash) << "\"(2^" << log2_size
           << " bytes)\n";
}

void step_log_dumper::revert(const_machine_hash_view root_hash) {
    if (m_muted) {
        return;
    }
    line() << "revert to root hash " << encode_hex(root_hash) << '\n';
}

std::string dump_step_uarch(std::span<const unsigned char> log, uint64_t skip_count, uint64_t uarch_cycle_count) {
    step_log_data image(log.begin(), log.end());
    uarch_replay_step_state_access<step_log_dumper>::context context;
    const uarch_replay_step_state_access<step_log_dumper> a(context, image.data(), image.size());
    // uarch_interpret's cycle-limit bookkeeping would open the dump with redundant uarch.cycle reads
    auto replay = [&](uint64_t count) {
        for (uint64_t i = 0; i < count; ++i) {
            context.dumper.begin_bracket("uarch cycle");
            const auto status = uarch_step(a);
            context.dumper.end_bracket("uarch cycle");
            if (status != UArchStepStatus::Success) {
                return false;
            }
        }
        return true;
    };
    context.dumper.set_muted(true);
    if (replay(skip_count)) {
        context.dumper.set_muted(false);
        replay(uarch_cycle_count);
    }
    return context.dumper.str();
}

std::string dump_reset_uarch(std::span<const unsigned char> log) {
    step_log_data image(log.begin(), log.end());
    uarch_replay_step_state_access<step_log_dumper>::context context;
    uarch_replay_step_state_access<step_log_dumper> a(context, image.data(), image.size());
    context.dumper.begin_bracket("uarch reset");
    uarch_reset_state(a);
    context.dumper.end_bracket("uarch reset");
    return context.dumper.str();
}

} // namespace cartesi
