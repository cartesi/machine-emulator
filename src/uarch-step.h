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

#ifndef UARCH_STEP_H
#define UARCH_STEP_H

namespace cartesi {

/// \brief Microarchitecture step execution status code
enum class uarch_step_status : int {
    success,                  // one micro instruction was executed successfully
    success_and_uarch_halted, // one micro instruction was executed successfully and microarchitecture was halted
    cycle_overflow,           // already at fixed point: uarch cycle has reached its maximum value
    uarch_halted,             // already at fixed point: microarchitecture is halted
    halted,                   // already at fixed point: iflags.H is set
    yielded_manually          // already at fixed point: iflags.Y is set
};

/// \brief Advances the microarchitecture by one micro cycle
/// \tparam Microarchitecture state accessor class
/// \returns Returns a status code indicating whether and how the microarchitecure was advanced
/// \details The microarchitecture will not advance if it is at a fixed point
template <typename STATE_ACCESS>
uarch_step_status uarch_step(STATE_ACCESS &a);

class uarch_state_access;
class uarch_record_state_access;
class uarch_replay_state_access;

// Declaration of explicit instantiation in module uarch-step.cpp
extern template uarch_step_status uarch_step(uarch_state_access &a);

// Declaration of explicit instantiation in module uarch-step.cpp
extern template uarch_step_status uarch_step(uarch_record_state_access &a);

// Declaration of explicit instantiation in module uarch-step.cpp
extern template uarch_step_status uarch_step(uarch_replay_state_access &a);

} // namespace cartesi

#endif
