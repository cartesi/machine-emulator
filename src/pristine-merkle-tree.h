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

#ifndef PRISTINE_MERKLE_TREE_H
#define PRISTINE_MERKLE_TREE_H

#include <cstdint>
#include <vector>

#include "machine-hash.h"
#include "variant-hasher.h"

/// \file
/// \brief Pristine Merkle tree interface.

namespace cartesi {

/// \brief Hashes of pristine subtrees for a range of sizes
class pristine_merkle_tree {
public:
    /// \brief Constructor
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_word_size Log<sub>2</sub> of word
    pristine_merkle_tree(int log2_root_size, int log2_word_size, hash_function_type hash_function);

    /// \brief Returns hash of pristine subtree
    /// \param log2_size Log<sub>2</sub> of subtree size. Must be between
    /// log2_word_size (inclusive) and log2_root_size (inclusive) passed
    /// to constructor.
    const machine_hash &get_hash(int log2_size) const;

private:
    int m_log2_root_size;               ///< Log<sub>2</sub> of tree size
    int m_log2_word_size;               ///< Log<sub>2</sub> of word size
    std::vector<machine_hash> m_hashes; ///< Vector with hashes
};

} // namespace cartesi

#endif
