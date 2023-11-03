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

#include "complete-merkle-tree.h"
#include <limits>
#include <utility>

/// \file
/// \brief Complete Merkle tree implementation.

namespace cartesi {

complete_merkle_tree::complete_merkle_tree(int log2_root_size, int log2_leaf_size, int log2_word_size) :
    m_log2_root_size{log2_root_size},
    m_log2_leaf_size{log2_leaf_size},
    m_pristine{log2_root_size, log2_word_size},
    m_tree(std::max(0, log2_root_size - log2_leaf_size + 1)) {
    check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
}

/// \brief Returns proof for a given node
/// \param address Node address
/// \param log2_size Log<sub>2</sub> size subintended by node
/// \returns Proof, or throws exception
complete_merkle_tree::proof_type complete_merkle_tree::get_proof(address_type address, int log2_size) const {
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
    return proof;
}

/// \brief Appends a new leaf hash to the tree
/// \param hash Hash to append
void complete_merkle_tree::push_back(const hash_type &hash) {
    auto &leaves = get_level(get_log2_leaf_size());
    if (leaves.size() >= address_type{1} << (get_log2_root_size() - get_log2_leaf_size())) {
        throw std::out_of_range{"tree is full"};
    }
    leaves.push_back(hash);
    bubble_up();
}

void complete_merkle_tree::check_log2_sizes(int log2_root_size, int log2_leaf_size, int log2_word_size) {
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

const complete_merkle_tree::hash_type &complete_merkle_tree::get_node_hash(address_type address, int log2_size) const {
    const auto &level = get_level(log2_size);
    address >>= log2_size;
    if (address >= (address_type{1} << (get_log2_root_size() - log2_size))) {
        throw std::out_of_range{"log2_size is out of bounds"};
    }
    if (address < level.size()) {
        return level[address];
    } else {
        return m_pristine.get_hash(log2_size);
    }
}

void complete_merkle_tree::bubble_up(void) {
    hasher_type h;
    // Go bottom up, updating hashes
    for (int log2_next_size = get_log2_leaf_size() + 1; log2_next_size <= get_log2_root_size(); ++log2_next_size) {
        auto log2_prev_size = log2_next_size - 1;
        auto &prev = get_level(log2_prev_size);
        auto &next = get_level(log2_next_size);
        // Redo last entry (if any) because it may have been constructed
        // from the last non-pristine entry in the previous level paired
        // with a pristine entry (i.e., the previous level was odd).
        auto first_entry = !next.empty() ? next.size() - 1 : next.size();
        // Next level needs half as many (rounded up) as previous
        next.resize((prev.size() + 1) / 2);
        assert(first_entry <= next.size());
        // Last safe entry has two non-pristine leafs
        auto last_safe_entry = prev.size() / 2;
        // Do all entries for which we have two non-pristine children
        for (; first_entry < last_safe_entry; ++first_entry) {
            get_concat_hash(h, prev[2 * first_entry], prev[2 * first_entry + 1], next[first_entry]);
        }
        // Maybe do last odd entry
        if (prev.size() > 2 * last_safe_entry) {
            get_concat_hash(h, prev.back(), m_pristine.get_hash(log2_prev_size), next[last_safe_entry]);
        }
    }
}

const complete_merkle_tree::level_type &complete_merkle_tree::get_level(int log2_size) const {
    if (log2_size < get_log2_leaf_size() || log2_size > get_log2_root_size()) {
        throw std::out_of_range{"log2_size is out of bounds"};
    }
    return m_tree[m_log2_root_size - log2_size];
}

complete_merkle_tree::level_type &complete_merkle_tree::get_level(int log2_size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<level_type &>(std::as_const(*this).get_level(log2_size));
}

} // namespace cartesi
