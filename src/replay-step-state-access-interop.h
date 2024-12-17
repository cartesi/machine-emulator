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

#ifndef REPLAY_STEP_STATE_ACCESS_INTEROP_H
#define REPLAY_STEP_STATE_ACCESS_INTEROP_H

#include "compiler-defines.h"
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

const static uint64_t interop_log2_root_size = 64;
constexpr size_t interop_machine_hash_byte_size = 32;

using interop_hash_type = unsigned char (*)[interop_machine_hash_byte_size];
using interop_const_hash_type = const unsigned char (*)[interop_machine_hash_byte_size];

NO_RETURN inline void interop_throw_runtime_error(const char *msg) {
    throw std::runtime_error(msg);
}

extern "C" void interop_merkle_tree_hash(const unsigned char *data, size_t size, interop_hash_type hash);

extern "C" void interop_concat_hash(interop_const_hash_type left, interop_const_hash_type right,
    interop_hash_type result);

#endif