#ifndef INTERPRET_H
#define INTERPRET_H

#include <cstdint>

/// \file
/// \brief Interpreter implementation.

// Forward declarations
class state_access;
class logged_state_access;
class machine;

/// \brief Interpreter status code
enum class interpreter_status: int {
    brk,    ///< brk is set, indicating the tight loop was broken
    success ///< mcycle reached target value
};

/// \brief Tries to run the interpreter until mcycle hits a target
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param mcycle_end Target value for mcycle.
/// \returns Returns a status code that tells if the loop hit the target mcycle or stopped early.
/// \details The interpret may stop early if the machine halts permanently or becomes temporarily idle (waiting for interrupts).
template <typename STATE_ACCESS>
interpreter_status interpret(STATE_ACCESS &a, uint64_t mcycle_end);

// Declaration of explicit instantiation in module interpret.cpp
extern template
interpreter_status
interpret(state_access &a, uint64_t mcycle_end);

// Declaration of explicit instantiation in module interpret.cpp
extern template
interpreter_status
interpret(state_access &a, uint64_t mcycle_end);

#endif
