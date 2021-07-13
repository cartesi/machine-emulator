// Copyright 2021 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef FULL_MERKLE_TREE_H
#define FULL_MERKLE_TREE_H

#include <limits>
#include "keccak-256-hasher.h"
#include "pristine-merkle-tree.h"
#include "merkle-tree-proof.h"

/// \file
/// \brief Full Merkle tree interface.

namespace cartesi {

/// \brief Full Merkle tree
/// \details This class implements a full merkle tree
class full_merkle_tree {
public:

    /// \brief Hasher class.
    using hasher_type = keccak_256_hasher;

    /// \brief Storage for a hash.
    using hash_type = hasher_type::hash_type;

    /// \brief Storage for an address.
    using address_type = uint64_t;

    /// \brief Storage for a proof.
    using proof_type = merkle_tree_proof<hash_type, address_type>;

    /// \brief Constructor for a pristine tree
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word
    full_merkle_tree(int log2_root_size, int log2_leaf_size,
        int log2_word_size);

    /// \brief Constructor for list of consecutive leaf hashes
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word
    /// \param leaves List of leaf hashes
    full_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size,
        const std::vector<hash_type> &leaves);

    /// \brief Returns log<sub>2</sub> of size of tree
    int get_log2_root_size(void) const {
        return m_log2_root_size;
    }

    /// \brief Returns log<sub>2</sub> of size of leaf
    int get_log2_leaf_size(void) const {
        return m_log2_leaf_size;
    }

    /// \brief Returns the tree's root hash
    /// \returns Root hash
    const hash_type &get_root_hash(void) const {
        return get_node_hash(0, get_log2_root_size());
    }

    /// \brief Returns the hash of a node at a given address of a given size
    /// \param address Node address
    /// \param log2_size Log<sub>2</sub> size subintended by node
    const hash_type &get_node_hash(address_type address, int log2_size) const {
        return m_tree[get_node_index(address, log2_size)];
    }

    /// \brief Returns proof for a given node
    /// \param address Node address
    /// \param log2_size Log<sub>2</sub> size subintended by node
    /// \returns Proof, or throws exception
    proof_type get_proof(address_type address, int log2_size) const;

private:

    /// \brief Throws exception if log<sub>2</sub> sizes are inconsistent
    ///  with one another
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word
    static void check_log2_sizes(int log2_root_size, int log2_leaf_size,
        int log2_word_size);

    /// \brief Returns the index of the left child of node at given index
    static constexpr int left_child_index(int index) {
        return 2*index;
    }

    /// \brief Returns the index of the right child of node at given index
    static constexpr int right_child_index(int index) {
        return 2*index+1;
    }

    /// \brief Initialize all nodes for the pristine subtree with root
    /// at a given index
    /// \param pristine Hashes for pristine subtree nodes of all sizes
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    void init_pristine_subtree(const pristine_merkle_tree &pristine,
        int index, int log2_size);

    /// \brief Initialize all nodes for the subtree with root at a given index
    /// \param h Hasher object
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    /// \details The nodes corresponding to subtrees of size log2_leaf_size
    /// are assumed to have already been set prior to calling this function
    void init_subtree(hasher_type &h, int index, int log2_size);

    /// \brief Initialize tree from a list of consecutive page hashes
    /// \param leaves List of page hashes
    /// \details The page hashes in leaves are copied to the appropriate
    /// subtree nodes, in order, and the rest are filled with pristine
    /// page hashes
    void init_tree(const pristine_merkle_tree &pristine,
        const std::vector<hash_type> &leaves);

    /// \brief Returns index of a node in the tree array
    /// \param address Node address
    /// \param log2_size
    address_type get_node_index(address_type address, int log2_size) const;

    int m_log2_root_size;            ///< Log<sub>2</sub> of tree size
    int m_log2_leaf_size;            ///< Log<sub>2</sub> of leaf size
    address_type m_max_leaves;       ///< Maximum number of leaves
    std::vector<hash_type> m_tree;   ///< Binary heap with tree node hashes

};

} // namespace cartesi

#endif
