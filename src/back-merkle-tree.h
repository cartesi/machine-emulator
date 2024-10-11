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

#ifndef BACK_MERKLE_TREE_H
#define BACK_MERKLE_TREE_H

#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "pristine-merkle-tree.h"

/// \file
/// \brief Back Merkle tree interface.

namespace cartesi {

/// \brief Incremental way of maintaining a Merkle tree for a stream of
/// leaf hashes
/// \details This is surprisingly efficient in both time and space.
/// Adding the next leaf takes O(log(n)) in the worst case, but is
/// this is amortized to O(1) time when adding n leaves.
/// Obtaining the proof for the current leaf takes theta(log(n)) time.
/// Computing the tree root hash also takes theta(log(n)) time.
/// The class only ever stores log(n) hashes (1 for each tree level).
class back_merkle_tree {
public:
    /// \brief Hasher class.
    using hasher_type = keccak_256_hasher;

    /// \brief Storage for a hash.
    using hash_type = hasher_type::hash_type;

    /// \brief Storage for a hash.
    using address_type = uint64_t;

    /// \brief Storage for the proof of a word value.
    using proof_type = merkle_tree_proof<hash_type, address_type>;

    /// \brief Constructor
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word node
    back_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size);

    /// \brief Appends a new hash to the tree
    /// \param new_leaf_hash Hash of new leaf data
    /// \details
    /// Consider the tree down to the leaf level.
    /// The tree is only complete after 2^(log2_root_size-log2_leaf_size)
    /// leaves have been added.
    /// Before that, when leaf_count leaves have been added, we assume the rest
    /// of the leaves are filled with zeros (i.e., they are pristine).
    /// The trick is that we do not need to store the hashes of all leaf_count
    /// leaves already added to the stream.
    /// This is because, whenever a subtree is complete, all we need is its
    /// root hash.
    /// The complete subtrees are disjoint, abutting, and appear in decreasing
    /// size.
    /// In fact, there is exactly one complete subtree for each bit set in
    /// leaf_count.
    /// We only need log2_root_size-log2_leaf_size+1 bits to represent
    /// leaf_count.
    /// So our context is a vector with log2_root_size-log2_leaf_size+1 entries,
    /// where entry i contains the hash for a complete subtree of
    /// size 2^i leaves.
    /// We will only use the entries i if the corresponding bit is set
    /// in leaf_count.
    /// Adding a new leaf hash exactly like adding 1 to leaf_count.
    /// We scan from least to most significant bit in leaf_count.
    /// We start with the right = leaf_hash and i = 0.
    /// If the bit i is set in leaf_count, we replace
    /// context[i] = hash(context[i], right) and move up a bit.
    /// If the bit is not set, we simply store context[i] = right and break
    /// In other words, we can update the context in
    /// log time (log2_root_size-log2_leaf_size)
    void push_back(const hash_type &new_leaf_hash);

    /// \brief Appends a number of padding hashes to the tree
    /// \param leaf_count Number of padding hashes to append
    /// \details
    /// Recall that a bit i set in leaf_count represents a complete subtree
    /// of size 2^i for which we have a hash in context[i].
    /// The remaining entries in the context are unused.
    /// The base case is when the least significant bit set in leaf_count is
    /// bigger than new_leaf_count.
    /// We can simply add to context[j] a pristine subtree of size 2^j
    /// for each bit j set in new_leaf_count.
    /// No used used entry in the context will be overwritten.
    /// We can then simply add new_leaf_count to leaf_count and we are done.
    /// In the general case, the least significant bit set i in leaf_count is
    /// less than or equal to new_leaf_count.
    /// Here, we add a pristine subtree of size 2^i to the context and
    /// bubble up.
    /// We add 2^i to leaf_count and subtract 2^i from new_leaf_count.
    /// Then we repeat this process until we reach the base case.
    void pad_back(uint64_t new_leaf_count);

    /// \brief Returns the root tree hash
    /// \returns Root tree hash
    /// \details
    /// We can produce the tree root hash from the context at any time, also
    /// in log time
    /// Ostensibly, we add pristine leaves until the leaf_count
    /// hits 2^(log2_root_size-log2_leaf_size)
    /// To do this in log time, we start by precomputing the hashes for all
    /// completely pristine subtree sizes
    /// If leaf_count is already 2^(log2_root_size-log2_leaf_size), we
    /// return context[i]
    /// Otherwise, we start with i = 0 and root = pristine[i+log2_leaf_size]
    /// (i.e., the invariant is that root contains the hash of the rightmost
    /// subtree whose log size is i + log2_leaf_size)
    /// If bit i is set, we set root = hash(context[i], root) and move up a bit
    /// (i.e., the subtree we are growing is to the right of what is
    /// in the context)
    /// If bit i is not set, we set
    /// root = hash(root, pristine[i+log2_leaf_size]) and move up a bit
    /// (i.e., to grow our subtree, we need to pad it on the right with
    /// a pristine subtree of the same size)
    hash_type get_root_hash(void) const;

    /// \brief Returns proof for the next pristine leaf
    /// \returns Proof for leaf at given index, or throws exception
    /// \details This is basically the same algorithm as
    /// back_merkle_tree::get_root_hash.
    proof_type get_next_leaf_proof(void) const;

private:
    int m_log2_root_size;                   ///< Log<sub>2</sub> of tree size
    int m_log2_leaf_size;                   ///< Log<sub>2</sub> of leaf size
    address_type m_leaf_count{0};           ///< Number of leaves already added
    address_type m_max_leaves;              ///< Maximum number of leaves
    std::vector<hash_type> m_context;       ///< Hashes of bits set in leaf_count
    pristine_merkle_tree m_pristine_hashes; ///< Hash of pristine subtrees of all sizes
};

} // namespace cartesi

#endif
