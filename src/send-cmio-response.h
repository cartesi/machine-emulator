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

#ifndef SEND_CMIO_RESPONSE_H
#define SEND_CMIO_RESPONSE_H

#include <cstdint>

namespace cartesi {

/// \brief Sends cmio response
/// \tparam STATE_ACCESS State accessor type
/// \param a State accessor
/// \param reason Reason for sending the response
/// \param data Response data
/// \param length Response data length
template <typename STATE_ACCESS>
void send_cmio_response(STATE_ACCESS &a, uint16_t reason, const unsigned char *data, uint32_t dataLength);

class state_access;
class record_state_access;
class replay_state_access;

// Declaration of explicit instantiation in module send_cmio_response.cpp
extern template void send_cmio_response(state_access &a, uint16_t reason, const unsigned char *data,
    uint32_t dataLength);

// Declaration of explicit instantiation in module send_cmio_response.cpp
extern template void send_cmio_response(record_state_access &a, uint16_t reason, const unsigned char *data,
    uint32_t dataLength);

// Declaration of explicit instantiation in module send_cmio_response.cpp
extern template void send_cmio_response(replay_state_access &a, uint16_t reason, const unsigned char *data,
    uint32_t dataLength);

} // namespace cartesi

#endif
