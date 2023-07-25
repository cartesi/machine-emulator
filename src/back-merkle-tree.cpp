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

#include "back-merkle-tree.h"
#include <iomanip>
#include <iostream>
#include <limits>

/// \file
/// \brief Back Merkle tree implementation.

namespace cartesi {

back_merkle_tree::back_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size) :
    m_log2_root_size{log2_root_size},
    m_log2_leaf_size{log2_leaf_size},
    m_leaf_count{0},
    m_max_leaves{address_type{1} << (log2_root_size - log2_leaf_size)},
    m_context(std::max(1, log2_root_size - log2_leaf_size + 1)),
    m_pristine_hashes{log2_root_size, log2_word_size} {
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
        throw std::out_of_range{"log2_leaf_size is greater than log2_root_size"};
    }
    if (log2_word_size > log2_leaf_size) {
        throw std::out_of_range{"log2_word_size is greater than log2_word_size"};
    }
    if (log2_root_size - m_log2_leaf_size >= std::numeric_limits<address_type>::digits) {
        throw std::out_of_range{"tree is too large for address type"};
    }
}

void back_merkle_tree::push_back(const hash_type &new_leaf_hash) {
    hasher_type h;
    hash_type right = new_leaf_hash;
    if (m_leaf_count >= m_max_leaves) {
        throw std::out_of_range{"too many leaves"};
    }
    const int depth = m_log2_root_size - m_log2_leaf_size;
    for (int i = 0; i <= depth; ++i) {
        if (m_leaf_count & (address_type{1} << i)) {
            const auto &left = m_context[i];
            get_concat_hash(h, left, right, right);
        } else {
            m_context[i] = right;
            break;
        }
    }
    ++m_leaf_count;
}

void back_merkle_tree::pad_back(uint64_t new_leaf_count) {
    hasher_type h;
    if (new_leaf_count > m_max_leaves || m_leaf_count + new_leaf_count > m_max_leaves) {
        throw std::invalid_argument("too many leaves");
    }
    const int depth = m_log2_root_size - m_log2_leaf_size;
    int j = 0;
    while (j <= depth) {
        const uint64_t j_span = address_type{1} << j;
        if (j_span > new_leaf_count) {
            break;
        }
        // is our smallest tree at depth j?
        if ((m_leaf_count & j_span) != 0) {
            // if so, we can add 2^j pristine leaves directly
            auto right = m_pristine_hashes.get_hash(m_log2_leaf_size + j);
            for (int i = j; i <= depth; ++i) {
                const uint64_t i_span = address_type{1} << i;
                if ((m_leaf_count & i_span) != 0) {
                    const auto &left = m_context[i];
                    get_concat_hash(h, left, right, right);
                } else {
                    m_context[i] = right;
                    // outer loop continues where we left off
                    j = i;
                    break;
                }
            }
            new_leaf_count = new_leaf_count - j_span;
            m_leaf_count = m_leaf_count + j_span;
        } else {
            ++j;
        }
    }
    // now add the rest of the padding directly to the context
    for (int i = 0; i <= depth; ++i) {
        const uint64_t i_span = address_type{1} << i;
        if ((new_leaf_count & i_span) != 0) {
            m_context[i] = m_pristine_hashes.get_hash(m_log2_leaf_size + i);
            new_leaf_count = new_leaf_count - i_span;
            m_leaf_count = m_leaf_count + i_span;
        }
    }
}

back_merkle_tree::hash_type back_merkle_tree::get_root_hash(void) const {
    hasher_type h;
    assert(m_leaf_count <= m_max_leaves);
    const int depth = m_log2_root_size - m_log2_leaf_size;
    if (m_leaf_count < m_max_leaves) {
        auto root = m_pristine_hashes.get_hash(m_log2_leaf_size);
        for (int i = 0; i < depth; ++i) {
            if (m_leaf_count & (address_type{1} << i)) {
                const auto &left = m_context[i];
                get_concat_hash(h, left, root, root);
            } else {
                const auto &right = m_pristine_hashes.get_hash(m_log2_leaf_size + i);
                get_concat_hash(h, root, right, root);
            }
        }
        return root;
    } else {
        return m_context[depth];
    }
}

back_merkle_tree::proof_type back_merkle_tree::get_next_leaf_proof(void) const {
    const int depth = m_log2_root_size - m_log2_leaf_size;
    if (m_leaf_count >= m_max_leaves) {
        throw std::out_of_range{"tree is full"};
    }
    hasher_type h;
    proof_type proof{m_log2_root_size, m_log2_leaf_size};
    proof.set_target_address(m_leaf_count << m_log2_leaf_size);
    proof.set_target_hash(m_pristine_hashes.get_hash(m_log2_leaf_size));
    hash_type hash = m_pristine_hashes.get_hash(m_log2_leaf_size);
    for (int i = 0; i < depth; ++i) {
        if (m_leaf_count & (address_type{1} << i)) {
            const auto &left = m_context[i];
            proof.set_sibling_hash(left, m_log2_leaf_size + i);
            get_concat_hash(h, left, hash, hash);
        } else {
            const auto &right = m_pristine_hashes.get_hash(m_log2_leaf_size + i);
            proof.set_sibling_hash(right, m_log2_leaf_size + i);
            get_concat_hash(h, hash, right, hash);
        }
    }
    proof.set_root_hash(hash);
#ifndef NDEBUG
    if (!proof.verify(h)) {
        throw std::runtime_error{"produced invalid proof"};
    }
#endif
    return proof;
}

} // namespace cartesi
