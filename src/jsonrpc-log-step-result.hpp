// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef JSONRPC_LOG_STEP_RESULT_HPP
#define JSONRPC_LOG_STEP_RESULT_HPP

#include <cstdint>
#include <vector>

#include "interpret.hpp"
#include "uarch-interpret.hpp"

namespace cartesi {

struct jsonrpc_log_step_result final {
    std::vector<uint8_t> log;
    interpreter_break_reason break_reason{};
};

struct jsonrpc_log_step_uarch_result final {
    std::vector<uint8_t> log;
    uarch_interpreter_break_reason break_reason{};
};

} // namespace cartesi

#endif
