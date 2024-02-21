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

#ifndef LOAD_CMIO_INPUT_H
#define LOAD_CMIO_INPUT_H

namespace cartesi {

/// \brief Load CMIO input from a buffer
/// \tparam STATE_ACCESS State accessor type
/// \param a State accessor
/// \param reason Reason code
/// \param data Data buffer
/// \param length Data buffer length
template <typename STATE_ACCESS>
void load_cmio_input(STATE_ACCESS &a, uint16_t reason, const unsigned char *data, uint32_t length);

class state_access;
class record_state_access;
class replay_state_access;

// Declaration of explicit instantiation in module load_cmio_input.cpp
extern template void load_cmio_input(state_access &a, uint16_t reason, const unsigned char *data, uint32_t length);

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void load_cmio_input(record_state_access &a, uint16_t reason, const unsigned char *data,
    uint32_t length);

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void load_cmio_input(replay_state_access &a, uint16_t reason, const unsigned char *data,
    uint32_t length);

} // namespace cartesi

#endif
