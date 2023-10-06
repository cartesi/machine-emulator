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

#ifndef GRPC_CONFIG_H
#define GRPC_CONFIG_H

namespace cartesi {

/// \brief GRPC customization argument allowing larger messages
/// \brief Currently, the biggest message is reset uarch with large_data: 2x 4MB + small data + overhead
static constexpr int GRPC_MAX_RECEIVE_MESSAGE_SIZE = 0xc00000;

} // namespace cartesi
#endif
