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

#ifndef JSONRPC_CMIO_REQUEST_HPP
#define JSONRPC_CMIO_REQUEST_HPP

#include <cstdint>

#include "access-log.hpp"

namespace cartesi {

struct jsonrpc_cmio_request final {
    uint8_t cmd{};
    uint16_t reason{};
    uint64_t available_length{};
    access_data data;
};

} // namespace cartesi

#endif // JSONRPC_CMIO_REQUEST_HPP
