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

#ifndef INTERPRET_H
#define INTERPRET_H

#include <cstdint>

/// \file
/// \brief Interpreter implementation.

namespace cartesi {

/// \brief Instruction execution status code
enum execute_status : uint64_t {
    success,                      // Instruction execution succeed, the interpreter should continue normally
    failure,                      // Instruction execution failed, the interpreter should continue normally
    success_and_flush_fetch,      // Instruction execution succeed, the interpreter must flush fetch address translation
                                  // cache
    success_and_serve_interrupts, // Instruction execution succeed, the interpreter must serve pending interrupts
                                  // immediately
    success_and_yield, // Instruction execution succeed, the interpreter must stop and handle a yield externally
    success_and_halt,  // Instruction execution succeed, the interpreter must stop because the machine cannot continue
};

/// \brief Reasons for interpreter loop interruption
enum class interpreter_break_reason {
    failed, ///< This value is not really returned by the interpreter loop, but it's reserved for C API
    halted,
    yielded_manually,
    yielded_automatically,
    yielded_softly,
    reached_target_mcycle
};

/// \brief Tries to run the interpreter until mcycle hits a target
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param mcycle_end Target value for mcycle.
/// \returns Returns a reason code informing why the interpreter loop has been stopped.
/// \details The interpret may stop early if the machine halts permanently or becomes temporarily idle (waiting for
/// interrupts).
template <typename STATE_ACCESS>
interpreter_break_reason interpret(STATE_ACCESS &a, uint64_t mcycle_end);

} // namespace cartesi

#endif
