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

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>

#include "machine-hash.h"
#include "variant-hasher.h"

/// \file
/// \brief Back back_hash_tree tree interface.

namespace cartesi {

/// \brief Incremental hash tree that efficiently maintains hashes for a stream of leaves
/// \details Space-efficient design stores only O(log n) hashes (one per tree level).
/// Leaf insertion is O(log n) worst-case but amortizes to O(1) over n operations.
class back_merkle_tree {
public:
    /// \brief Constructor from an existing leaves context
    /// \param log2_max_leaves Log base 2 of maximum amount of leaves
    /// \param hash_function Hash function to use
    /// \param leaf_count Amount of leaves already added to the tree
    /// \param context Context representing the leaves hashes
    back_merkle_tree(int log2_max_leaves, hash_function_type hash_function, uint64_t leaf_count = 0,
        machine_hashes context = {}) :
        m_hash_function(hash_function),
        m_leaf_count{leaf_count},
        m_context(std::max(1, log2_max_leaves + 1)) {
        if (log2_max_leaves < 0) {
            throw std::out_of_range{"log2_max_leaves is negative"};
        }
        if (log2_max_leaves >= std::numeric_limits<uint64_t>::digits) {
            throw std::out_of_range{"log2_max_leaves is too large"};
        }
        if (leaf_count >= get_max_leaves()) {
            throw std::out_of_range{"leaf count is greater than or equal to max leaves"};
        }
        // Unpack context
        size_t j = 0;
        if (leaf_count > 0) {
            for (int i = 0; i <= log2_max_leaves; ++i) {
                const auto i_span = UINT64_C(1) << i;
                if ((leaf_count & i_span) != 0) {
                    if (j >= context.size()) {
                        throw std::out_of_range{"leaves context is incompatible"};
                    }
                    m_context[i] = context[j++];
                }
            }
        }
        if (j != context.size()) {
            throw std::out_of_range{"leaves context is incompatible"};
        }
    }
    /// \brief Constructor from known root, leaf and word sizes
    /// \param log2_root_size Log base 2 of root node
    /// \param log2_leaf_size Log base 2 of leaf node
    /// \param log2_word_size Log base 2 of word node
    /// \param hash_function Hash function to use
    back_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size, hash_function_type hash_function) :
        back_merkle_tree(validate_log2_max_leaves_size(log2_root_size, log2_leaf_size, log2_word_size), hash_function) {
    }

    /// \brief Appends a new hash to the tree
    /// \param new_leaf_hash Hash of new leaf data
    /// \details
    /// The algorithm efficiently maintains only the root hashes of complete subtrees.
    /// Each bit set in leaf_count corresponds to a complete subtree of size 2^i,
    /// with its hash stored in context[i].
    ///
    /// Adding a leaf is equivalent to binary addition: scan bits from LSB to MSB.
    /// For each set bit i in leaf_count, combine context[i] with the new hash
    /// and propagate upward. Store the result at the first unset bit position.
    /// This achieves O(log n) worst-case, O(1) amortized time complexity.
    void push_back(const machine_hash &new_leaf_hash);

    /// \brief Appends a number of padding hashes to the tree
    /// \param new_leaf_count Number of padding hashes to append
    /// \param pad_hashes Array containing the padding hashes
    /// \details
    /// Uses binary representation of leaf counts to efficiently add padding.
    /// Each set bit i in leaf_count represents a complete subtree of size 2^i.
    ///
    /// Base case: When the least significant set bit in leaf_count exceeds new_leaf_count,
    /// directly place pad subtrees at positions corresponding to bits set in new_leaf_count.
    ///
    /// General case: When overlap exists, combine the smallest existing subtree with
    /// a matching pad subtree, bubble up the result, and repeat until base case is reached.
    void pad_back(uint64_t new_leaf_count, const machine_hashes &pad_hashes);

    /// \brief Returns the root tree hash
    /// \returns Root tree hash
    /// \details The tree must be complete, otherwise an exception is thrown
    machine_hash get_root_hash() const {
        if (!full()) {
            throw std::runtime_error{"attempt to get root hash of an incomplete back tree"};
        }
        return m_context.back();
    }

    /// \brief Clears the tree, making it empty (as if no leaves were added)
    void clear() noexcept {
        m_leaf_count = 0;
    }

    /// \brief Returns true if the tree is complete (reached maximum amount of leaves)
    bool full() const noexcept {
        return m_leaf_count >= get_max_leaves();
    }

    /// \brief Returns true if the tree is empty (no leaves were added)
    bool empty() const noexcept {
        return m_leaf_count == 0;
    }

    /// \brief Returns log base 2 of maximum amount of leaves that can be held by the tree
    int get_log2_max_leaves() const noexcept {
        return static_cast<int>(m_context.size()) - 1;
    }

    /// \brief Returns maximum amount of leaves that can be held by the tree
    uint64_t get_max_leaves() const noexcept {
        return static_cast<uint64_t>(1) << get_log2_max_leaves();
    }

    /// \brief Returns the hash function used by the tree
    hash_function_type get_hash_function() const noexcept {
        return m_hash_function;
    }

    /// \brief Returns amount of leaves already added to the tree
    uint64_t get_leaf_count() const noexcept {
        return m_leaf_count;
    }

    /// \brief Returns amount of leaves that can yet be added to the tree
    uint64_t get_remaining_leaf_count() const noexcept {
        return get_max_leaves() - m_leaf_count;
    }

    /// \brief Returns the leaves context
    machine_hashes get_context() const {
        // Pack context
        machine_hashes context;
        if (m_leaf_count > 0) {
            const int log2_max_leaves = get_log2_max_leaves();
            for (int i = 0; i <= log2_max_leaves; ++i) {
                const auto i_span = UINT64_C(1) << i;
                if ((m_leaf_count & i_span) != 0) {
                    context.push_back(m_context[i]);
                }
            }
        }
        return context;
    }

    /// \brief Creates an array of pad hashes to be used with pad_back()
    /// \param leaf_hash Hash of the leaf node
    /// \param log2_max_leaves Log base 2 of maximum amount of leaves
    /// \param hash_function Hash function to use
    /// \returns Array of pad hashes
    static machine_hashes make_pad_hashes(const machine_hash &leaf_hash, int log2_max_leaves,
        hash_function_type hash_function);

    /// \brief Creates an array of pristine pad hashes to be used with pad_back()
    /// \param log2_root_size Log base 2 of root node
    /// \param log2_leaf_size Log base 2 of leaf node
    /// \param log2_word_size Log base 2 of word node
    /// \param hash_function Hash function to use
    /// \returns Array of pad hashes
    static machine_hashes make_pristine_pad_hashes(int log2_root_size, int log2_leaf_size, int log2_word_size,
        hash_function_type hash_function);

    /// \brief Validates and computes log2_max_leaves from root, leaf and word sizes
    /// \param log2_root_size Log base 2 of root node
    /// \param log2_leaf_size Log base 2 of leaf node
    /// \param log2_word_size Log base 2 of word node
    /// \returns Log base 2 of maximum amount of leaves
    static int validate_log2_max_leaves_size(int log2_root_size, int log2_leaf_size, int log2_word_size);

private:
    hash_function_type m_hash_function; ///< Hash function
    uint64_t m_leaf_count;              ///< Number of leaves already added
    machine_hashes m_context;           ///< Hashes of bits set in leaf_count
};

} // namespace cartesi

#endif
