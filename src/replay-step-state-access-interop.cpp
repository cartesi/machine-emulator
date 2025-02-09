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

#include "replay-step-state-access-interop.h"

#include <cstddef>
#include <type_traits>

#include "i-hasher.h"
#include "machine-merkle-tree.h"

using namespace cartesi;

static_assert(interop_log2_root_size == machine_merkle_tree::get_log2_root_size(),
    "interop_log2_root_size must match machine_merkle_tree::get_log2_root_size()");
static_assert(sizeof(cartesi::machine_merkle_tree::hash_type) == sizeof(std::remove_pointer_t<interop_hash_type>),
    "hash_type size mismatch");

extern "C" void interop_merkle_tree_hash(const unsigned char *data, size_t size, interop_hash_type hash) {
    machine_merkle_tree::hasher_type hasher{};
    get_merkle_tree_hash(hasher, data, size, machine_merkle_tree::get_word_size(),
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        *reinterpret_cast<machine_merkle_tree::hash_type *>(hash));
}

extern "C" void interop_concat_hash(interop_const_hash_type left, interop_const_hash_type right,
    interop_hash_type result) {
    machine_merkle_tree::hasher_type hasher{};
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    get_concat_hash(hasher, *reinterpret_cast<const machine_merkle_tree::hash_type *>(left),
        *reinterpret_cast<const machine_merkle_tree::hash_type *>(right),
        *reinterpret_cast<machine_merkle_tree::hash_type *>(result));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}
