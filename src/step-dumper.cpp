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
#include <exception>
#include <string>

#include "os-filesystem.hpp"
#include "os-mapped-memory.hpp"
#include "step-dumper.hpp"
#include "uarch-replay-step-state-access.hpp"
#include "uarch-step.hpp"

namespace cartesi {

std::string dump_step_uarch(const std::string &filename) {
    auto data_length = os::file_size(filename);
    auto mapped_data = os::mapped_memory(data_length, os::mapped_memory_flags{}, filename);
    uarch_replay_step_state_access<step_dumper>::context context;
    uarch_replay_step_state_access<step_dumper> a(context, mapped_data.get_ptr(), data_length);
    // uarch_interpret's cycle-limit bookkeeping would open the printout with redundant uarch.cycle reads
    for (uint64_t i = 0; i < context.log.requested_cycle_count; ++i) {
        if (uarch_step(a) != UArchStepStatus::Success) {
            break;
        }
    }
    auto printout = context.printer.str();
    try {
        a.finish();
    } catch (const std::exception &e) {
        printout += "WARNING: replay does not verify: ";
        printout += e.what();
        printout += '\n';
    }
    return printout;
}

} // namespace cartesi
