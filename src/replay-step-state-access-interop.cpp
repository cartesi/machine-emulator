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
#include "machine-merkle-tree.h"

using namespace cartesi;

static i_hasher make_hasher(uint64_t target) {
    auto maybe_hash_tree_target = parse_hash_tree_target(target);
    if (!maybe_hash_tree_target) {
        interop_throw_runtime_error("unsupported hash tree target");
    }
    return i_hasher::make(*maybe_hash_tree_target);
}

static_assert(interop_log2_root_size == machine_merkle_tree::get_log2_root_size(),
    "interop_log2_root_size must match machine_merkle_tree::get_log2_root_size()");
static_assert(sizeof(cartesi::machine_hash) == sizeof(std::remove_pointer_t<interop_hash_type>),
    "machine_hash size mismatch");

extern "C" void interop_merkle_tree_hash(uint64_t hash_tree_target, const unsigned char *data, size_t size,
    interop_hash_type hash) {
    auto hasher = make_hasher(hash_tree_target);
    hasher.get_merkle_tree_hash(data, size, machine_merkle_tree::get_word_size(),
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        *reinterpret_cast<machine_hash *>(hash));
}

extern "C" void interop_concat_hash(uint64_t hash_tree_target, interop_const_hash_type left,
    interop_const_hash_type right, interop_hash_type result) {
    auto hasher = make_hasher(hash_tree_target);
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    hasher.get_concat_hash(*reinterpret_cast<const machine_hash *>(left),
        *reinterpret_cast<const machine_hash *>(right), *reinterpret_cast<machine_hash *>(result));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}
