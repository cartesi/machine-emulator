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

#ifndef STEP_LOG_HASH_HPP
#define STEP_LOG_HASH_HPP

/// \file
/// \brief Hashing primitives for step logs, with the backend chosen by build target.
/// \details On the host they run the emulator's hasher. Under ZKARCHITECTURE they call
/// zk_merkle_tree_hash and zk_concat_hash, which the zkVM guest runtime exports (typically onto
/// its hash accelerator); a guest may reject hash functions it does not support.

#include <cstddef>
#include <span>

#include "hash-tree-constants.hpp"
#include "i-hasher.hpp"
#include "machine-hash.hpp"
#include "variant-hasher.hpp"

namespace cartesi {

using hash_type = unsigned char (*)[MACHINE_HASH_SIZE];
using const_hash_type = const unsigned char (*)[MACHINE_HASH_SIZE];

#ifdef ZKARCHITECTURE

extern "C" void zk_merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size,
    hash_type hash);

extern "C" void zk_concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result);

inline void merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size, hash_type hash) {
    zk_merkle_tree_hash(hash_function, data, size, hash);
}

inline void concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result) {
    zk_concat_hash(hash_function, left, right, result);
}

#else

inline void merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size, hash_type hash) {
    variant_hasher h{hash_function};
    get_merkle_tree_hash(h, std::span<const unsigned char>{data, size}, HASH_TREE_WORD_SIZE,
        machine_hash_view{*hash, MACHINE_HASH_SIZE});
}

inline void concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result) {
    variant_hasher h{hash_function};
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    get_concat_hash(h, *reinterpret_cast<const machine_hash *>(left), *reinterpret_cast<const machine_hash *>(right),
        *reinterpret_cast<machine_hash *>(result));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}

#endif

} // namespace cartesi

#endif
