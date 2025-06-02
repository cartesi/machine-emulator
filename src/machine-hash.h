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

#ifndef MACHINE_HASH_H
#define MACHINE_HASH_H

/// \file
/// \brief Storage for a hash

#include <array>
#include <span>

namespace cartesi {

static constexpr size_t MACHINE_HASH_SIZE = 32;
using machine_hash = std::array<unsigned char, MACHINE_HASH_SIZE>;
using machine_hash_view = std::span<unsigned char, MACHINE_HASH_SIZE>;
using const_machine_hash_view = std::span<const unsigned char, MACHINE_HASH_SIZE>;

} // namespace cartesi

#endif
