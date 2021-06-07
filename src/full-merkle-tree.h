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
        int log2_word_size):
        m_log2_root_size{log2_root_size},
        m_log2_leaf_size{log2_leaf_size},
        m_max_leaves{address_type{1} << std::max(0,
            log2_root_size-log2_leaf_size)} {
        check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
        m_tree.resize(2*m_max_leaves);
        init_pristine_subtree(pristine_merkle_tree{log2_root_size,
            log2_word_size}, 1, log2_root_size);
    }

    /// \brief Constructor for list of consecutive leaf hashes
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word
    /// \param leaves List of leaf hashes
    full_merkle_tree(
        int log2_root_size,
        int log2_leaf_size,
        int log2_word_size,
        const std::vector<hash_type> &leaves):
        m_log2_root_size(log2_root_size),
        m_log2_leaf_size(log2_leaf_size),
        m_max_leaves{address_type{1} << std::max(0,
            log2_root_size-log2_leaf_size)} {
        check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
        if (leaves.size() > m_max_leaves) {
            throw std::out_of_range{"too many leaves"};
        }
        m_tree.resize(2*m_max_leaves);
        init_tree(pristine_merkle_tree{log2_root_size, log2_word_size}, leaves);
    }

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
    proof_type get_proof(address_type address, int log2_size) const {
        if (log2_size < get_log2_leaf_size() ||
            log2_size > get_log2_root_size()) {
            throw std::out_of_range{"log2_size is out of bounds"};
        }
        proof_type proof{get_log2_root_size(), log2_size};
        proof.set_root_hash(get_root_hash());
        proof.set_target_address(address);
        proof.set_target_hash(get_node_hash(address, log2_size));
        for (int log2_sibling_size = log2_size;
            log2_sibling_size < get_log2_root_size();
            ++log2_sibling_size) {
            auto sibling_address = address ^
                (address_type{1} << log2_sibling_size);
            proof.set_sibling_hash(
                get_node_hash(sibling_address, log2_sibling_size),
                log2_sibling_size);
        }
#ifndef NDEBUG
        if (!proof.verify(hasher_type{})) {
            throw std::runtime_error{"produced invalid proof"};
        }
#endif
        return proof;
    }

private:

    /// \brief Throws exception if log<sub>2</sub> sizes are inconsistent
    ///  with one another
    /// \param log2_root_size Log<sub>2</sub> of root node
    /// \param log2_leaf_size Log<sub>2</sub> of leaf node
    /// \param log2_word_size Log<sub>2</sub> of word
    void check_log2_sizes(int log2_root_size, int log2_leaf_size,
        int log2_word_size) {
        if (log2_root_size < 0) {
            throw std::out_of_range{"log2_root_size is negative"};
        }
        if (log2_leaf_size < 0) {
            throw std::out_of_range{"log2_leaf_size is negative"};
        }
        if (log2_word_size < 0) {
            throw std::out_of_range{"log2_word_size is negative"};
        }
        if (log2_leaf_size > log2_root_size) {
            throw std::out_of_range{
                "log2_leaf_size is greater than log2_root_size"};
        }
        if (log2_word_size > log2_leaf_size) {
            throw std::out_of_range{
                "log2_word_size is greater than log2_word_size"};
        }
        if (log2_root_size >= std::numeric_limits<address_type>::digits) {
            throw std::out_of_range{"tree is too large for address type"};
        }
    }

    /// \brief Returns the index of the left child of node at given index
    int left_child_index(int index) const {
        return 2*index;
    }

    /// \brief Returns the index of the right child of node at given index
    int right_child_index(int index) const {
        return 2*index+1;
    }

    /// \brief Initialize all nodes for the pristine subtree with root
    /// at a given index
    /// \param pristine Hashes for pristine subtree nodes of all sizes
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    void init_pristine_subtree(const pristine_merkle_tree &pristine,
        int index, int log2_size) {
        if (log2_size >= get_log2_leaf_size()) {
            m_tree[index] = pristine.get_hash(log2_size);
            init_pristine_subtree(pristine, left_child_index(index),
                log2_size-1);
            init_pristine_subtree(pristine, right_child_index(index),
                log2_size-1);
        }
    }

    /// \brief Initialize all nodes for the subtree with root at a given index
    /// \param h Hasher object
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    /// \details The nodes corresponding to subtrees of size log2_leaf_size
    /// are assumed to have already been set prior to calling this function
    void init_subtree(hasher_type &h, int index, int log2_size) {
        if (log2_size > get_log2_leaf_size()) {
            init_subtree(h, left_child_index(index), log2_size-1);
            init_subtree(h, right_child_index(index), log2_size-1);
            get_concat_hash(h, m_tree[left_child_index(index)],
                m_tree[right_child_index(index)], m_tree[index]);
        }
    }

    /// \brief Initialize tree from a list of consecutive page hashes
    /// \param leaves List of page hashes
    /// \details The page hashes in leaves are copied to the appropriate
    /// subtree nodes, in order, and the rest are filled with pristine
    /// page hashes
    void init_tree(const pristine_merkle_tree &pristine,
        const std::vector<hash_type> &leaves) {
        std::copy(leaves.begin(), leaves.end(), &m_tree[m_max_leaves]);
        std::fill_n(&m_tree[m_max_leaves+leaves.size()],
            m_max_leaves-leaves.size(),
            pristine.get_hash(get_log2_leaf_size()));
        hasher_type h;
        init_subtree(h, 1, get_log2_root_size());
    }

    /// \brief Returns index of a node in the tree array
    /// \param address Node address
    /// \param log2_size
    address_type get_node_index(address_type address, int log2_size) const {
        if (log2_size < get_log2_leaf_size() ||
            log2_size > get_log2_root_size()) {
            throw std::out_of_range{"log2_size is out of bounds"};
        }
        address_type base = address_type{1} << (get_log2_root_size()-log2_size);
        // Nodes of log2_size live in indices [base, 2*base)
        // 0 <unused>
        // 1 log2_root_size
        // 2 log2_root_size-1
        // 3 log2_root_size-1
        // 4 log2_root_size-2
        // 5 log2_root_size-2
        // 6 log2_root_size-2
        // 7 log2_root_size-2
        // 0 ...
        address >>= log2_size;
        if (address >= base) {
            throw std::out_of_range{"address is out of bounds"};
        }
        return base+address;
    }

    int m_log2_root_size;            ///< Log<sub>2</sub> of tree size
    int m_log2_leaf_size;            ///< Log<sub>2</sub> of leaf size
    address_type m_max_leaves;       ///< Maximum number of leaves
    std::vector<hash_type> m_tree;   ///< Binary heap with tree node hashes

};

} // namespace cartesi

#endif
