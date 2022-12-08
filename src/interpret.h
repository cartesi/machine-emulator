// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef INTERPRET_H
#define INTERPRET_H

#include <cstdint>

/// \file
/// \brief Interpreter implementation.

namespace cartesi {

/// \brief Instruction execution status code
enum execute_status : uint64_t {
    failure,                      // Instruction execution failed, the interpreter should continue normally
    success,                      // Instruction execution succeed, the interpreter should continue normally
    success_and_reload_mcycle,    // Instruction execution succeed, the interpreter must reload mcycle
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

#ifdef MICROARCHITECTURE
class uarch_machine_state_access;
// Declaration of explicit instantiation in module interpret.cpp when compiled with microarchitecture
extern template interpreter_break_reason interpret(uarch_machine_state_access &a, uint64_t mcycle_end);
#else
// Forward declarations
class state_access;
class machine;

// Declaration of explicit instantiation in module interpret.cpp
extern template interpreter_break_reason interpret(state_access &a, uint64_t mcycle_end);

#endif // MICROARCHITECTURE
} // namespace cartesi

#endif