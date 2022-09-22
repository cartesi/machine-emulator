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

/// \brief Interpreter status code
enum class interpreter_status : int {
    brk,    ///< brk is set, indicating the tight loop was broken
    success ///< mcycle reached target value
};

/// \brief Tries to run the interpreter until mcycle hits a target
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param mcycle_end Target value for mcycle.
/// \returns Returns a status code that tells if the loop hit the target mcycle or stopped early.
/// \details The interpret may stop early if the machine halts permanently or becomes temporarily idle (waiting for
/// interrupts).
template <typename STATE_ACCESS>
interpreter_status interpret(STATE_ACCESS &a, uint64_t mcycle_end);

#ifdef MICROARCHITECTURE
class uarch_machine_state_access;
extern template interpreter_status interpret(uarch_machine_state_access &a, uint64_t mcycle_end);
#else
// Forward declarations
class state_access;
class logged_state_access;
class step_state_access;
class machine;

// Declaration of explicit instantiation in module interpret.cpp
extern template interpreter_status interpret(state_access &a, uint64_t mcycle_end);

// Declaration of explicit instantiation in module interpret.cpp
extern template interpreter_status interpret(logged_state_access &a, uint64_t mcycle_end);

// Declaration of explicit instantiation in module interpret.cpp
extern template interpreter_status interpret(step_state_access &a, uint64_t mcycle_end);
#endif // MICROARCHITECTURE
} // namespace cartesi

#endif