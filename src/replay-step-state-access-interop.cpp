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
#include <span>
#include <type_traits>

#include "hash-tree.h"
#include "i-hasher.h"

using namespace cartesi;

static_assert(interop_log2_root_size == HASH_TREE_LOG2_ROOT_SIZE,
    "interop_log2_root_size must match HASH_TREE_LOG2_ROOT_SIZE");
static_assert(sizeof(cartesi::machine_hash) == sizeof(std::remove_pointer_t<interop_hash_type>),
    "hash_type size mismatch");

extern "C" void interop_merkle_tree_hash(const unsigned char *data, size_t size, interop_hash_type hash) {
    hash_tree::hasher_type hasher{};
    get_merkle_tree_hash(hasher, std::span<const unsigned char>{data, size}, HASH_TREE_WORD_SIZE,
        machine_hash_view{*hash, interop_machine_hash_byte_size});
}

extern "C" void interop_concat_hash(interop_const_hash_type left, interop_const_hash_type right,
    interop_hash_type result) {
    hash_tree::hasher_type hasher{};
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    get_concat_hash(hasher, *reinterpret_cast<const machine_hash *>(left),
        *reinterpret_cast<const machine_hash *>(right), *reinterpret_cast<machine_hash *>(result));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}
