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

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <vector>

#include "full-merkle-tree.h"
#include "i-hasher.h"
#include "pristine-merkle-tree.h"

/// \file
/// \brief Full Merkle tree implementation.

namespace cartesi {

full_merkle_tree::full_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size) :
    m_log2_root_size{log2_root_size},
    m_log2_leaf_size{log2_leaf_size},
    m_max_leaves{address_type{1} << std::max(0, log2_root_size - log2_leaf_size)} {
    check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
    m_tree.resize(2 * m_max_leaves);
    init_pristine_subtree(pristine_merkle_tree{log2_root_size, log2_word_size}, 1, log2_root_size);
}

full_merkle_tree::full_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size,
    const std::vector<hash_type> &leaves) :
    m_log2_root_size(log2_root_size),
    m_log2_leaf_size(log2_leaf_size),
    m_max_leaves{address_type{1} << std::max(0, log2_root_size - log2_leaf_size)} {
    check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
    if (leaves.size() > m_max_leaves) {
        throw std::out_of_range{"too many leaves"};
    }
    m_tree.resize(2 * m_max_leaves);
    init_tree(pristine_merkle_tree{log2_root_size, log2_word_size}, leaves);
}

full_merkle_tree::proof_type full_merkle_tree::get_proof(address_type address, int log2_size) const {
    if (log2_size < get_log2_leaf_size() || log2_size > get_log2_root_size()) {
        throw std::out_of_range{"log2_size is out of bounds"};
    }
    auto aligned_address = (address >> log2_size) << log2_size;
    if (address != aligned_address) {
        throw std::out_of_range{"address is misaligned"};
    }
    proof_type proof{get_log2_root_size(), log2_size};
    proof.set_root_hash(get_root_hash());
    proof.set_target_address(address);
    proof.set_target_hash(get_node_hash(address, log2_size));
    for (int log2_sibling_size = log2_size; log2_sibling_size < get_log2_root_size(); ++log2_sibling_size) {
        auto sibling_address = address ^ (address_type{1} << log2_sibling_size);
        proof.set_sibling_hash(get_node_hash(sibling_address, log2_sibling_size), log2_sibling_size);
    }
#ifndef NDEBUG
    hasher_type h{};
    if (!proof.verify(h)) {
        throw std::runtime_error{"produced invalid proof"};
    }
#endif
    return proof;
}

void full_merkle_tree::check_log2_sizes(int log2_root_size, int log2_leaf_size, int log2_word_size) {
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
    if (log2_root_size >= std::numeric_limits<address_type>::digits) {
        throw std::out_of_range{"tree is too large for address type"};
    }
}

void full_merkle_tree::init_pristine_subtree(const pristine_merkle_tree &pristine, int index, int log2_size) {
    if (log2_size >= get_log2_leaf_size()) {
        m_tree[index] = pristine.get_hash(log2_size);
        init_pristine_subtree(pristine, left_child_index(index), log2_size - 1);
        init_pristine_subtree(pristine, right_child_index(index), log2_size - 1);
    }
}

void full_merkle_tree::init_subtree(hasher_type &h, int index, int log2_size) {
    if (log2_size > get_log2_leaf_size()) {
        init_subtree(h, left_child_index(index), log2_size - 1);
        init_subtree(h, right_child_index(index), log2_size - 1);
        get_concat_hash(h, m_tree[left_child_index(index)], m_tree[right_child_index(index)], m_tree[index]);
    }
}

void full_merkle_tree::init_tree(const pristine_merkle_tree &pristine, const std::vector<hash_type> &leaves) {
    std::copy(leaves.begin(), leaves.end(), &m_tree[m_max_leaves]);
    std::fill_n(&m_tree[m_max_leaves + leaves.size()], m_max_leaves - leaves.size(),
        pristine.get_hash(get_log2_leaf_size()));
    hasher_type h;
    init_subtree(h, 1, get_log2_root_size());
}

full_merkle_tree::address_type full_merkle_tree::get_node_index(address_type address, int log2_size) const {
    if (log2_size < get_log2_leaf_size() || log2_size > get_log2_root_size()) {
        throw std::out_of_range{"log2_size is out of bounds"};
    }
    const address_type base = address_type{1} << (get_log2_root_size() - log2_size);
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
    return base + address;
}

} // namespace cartesi
