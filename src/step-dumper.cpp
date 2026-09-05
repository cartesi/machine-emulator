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
#include "uarch-replay-step-state-access.hpp"
#include "uarch-step.hpp"

namespace cartesi {

std::string dump_step_uarch(std::span<const unsigned char> log, uint64_t uarch_cycle_count) {
    std::vector<unsigned char> image(log.begin(), log.end());
    uarch_replay_step_state_access<step_dumper>::context context;
    const uarch_replay_step_state_access<step_dumper> a(context, image.data(), image.size());
    // uarch_interpret's cycle-limit bookkeeping would open the printout with redundant uarch.cycle reads
    for (uint64_t i = 0; i < uarch_cycle_count; ++i) {
        if (uarch_step(a) != UArchStepStatus::Success) {
            break;
        }
    }
    return context.printer.str();
}

} // namespace cartesi
