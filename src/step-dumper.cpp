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

#include "step-dumper.hpp"
#include "step-log-data.hpp"
#include "uarch-replay-step-state-access.hpp"
#include "uarch-step.hpp"

namespace cartesi {

std::string dump_step_uarch(std::span<const unsigned char> log, uint64_t skip_count, uint64_t uarch_cycle_count) {
    step_log_data image(log.begin(), log.end());
    uarch_replay_step_state_access<step_dumper>::context context;
    const uarch_replay_step_state_access<step_dumper> a(context, image.data(), image.size());
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

} // namespace cartesi
