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

#ifndef HASH_TREE_H
#define HASH_TREE_H

#include <iosfwd>
#include <vector>

#include "address-range.h"
#include "hash-tree-constants.h"
#include "keccak-256-hasher.h"
#include "machine-hash.h"
#include "merkle-tree-proof.h"
#include "unique-c-ptr.h"

namespace cartesi {

class machine;

#if 0

class i_hash_tree {
public:
    using hasher_type = keccak_256_hasher;
    using hash_type = hasher_type::hash_type;
    using sibling_hashes_type = std::vector<hash_type>;

    /// \brief Returns root hash without updating it first.
    /// \returns Corresponding hash.
    const hash_type &get_root_hash() const {
        return do_get_root_hash();
    }

    /// \brief Returns node hash without updating it first.
    /// \param m Machine to get data from.
    /// \param target_address Starting address of data subintended by target node.
    /// \param log2_target_size Log<sub>2</sub> of number of bytes subintended by target note.
    /// \returns Corresponding hash.
    hash_type get_node_hash(const machine &m, uint64_t target_address, int log2_target_size) const {
        return do_get_node_hash(m, target_address, log2_target_size);
    }

    /// \brief Update the root hash, and then return it.
    /// \returns A pair with, first, the updated hash and, second, a boolean that is true if the call
    /// may have changed the root hash since the last call to this method.
    const hash_type &update_and_get_root_hash() {
        do_update();
        return get_root_hash();
    }

    /// \brief Appends the list of sibling hashes to vector
    /// \param log2_root_size Log<sub>2</sub> of number of bytes subintended by subtree of interest.
    /// \param target_address Starting address of data subintended by target node.
    /// \param log2_target_size Log<sub>2</sub> of number of bytes subintended by target note.
    /// \param siblings Receives the sibling hashes
    /// \details \p log2_target_size cannot be smaller than get_log2_word_size().
    /// \p log2_target_size cannot be larger than \p get_log2_root_size().
    /// \p target_address must be aligned to 2^(\p log2_target_size).
    /// The hash of all siblings in the path that starts at (\p target_address):(get_log2_root_size()-1) and ends at
    /// node (\p target_address):(\p log2_target_size) are appended, in this order.
    /// In total, (\p get_log2_root_size() - \p log2_target_size) sibling hashes are appended.
    void append_sibling_hashes(uint64_t target_address, int log2_target_size, sibling_hashes_type &siblings) const {
        return do_get_sibling_hashes(target_address, log2_target_size, siblings);
    }

    /// \brief Return the size of data subintended by this tree
    /// \returns Log<sub>2</sub> of number of bytes subintended by entire tree.
    int get_log2_root_size() {
        return do_get_log2_root_size();
    }

    /// \brief Return the size of data subintended by a word
    /// \returns Log<sub>2</sub> of number of bytes subintended by word.
    /// \details A word is the amount of data that is hashed to produce a leaf in the tree.
    static constexpr int get_log2_word_size() {
        return LOG2_MERKLE_WORD_SIZE;
    }

private:
    virtual const hash_type &do_get_root_hash() const = 0;
    virtual void do_update() = 0;
    virtual void do_append_sibling_hashes(int log2_root_size, uint64_t target_address, int log2_target_size,
        sibling_hashes_type &siblings) const = 0;
};

class sparse_hash_tree : public i_hash_tree {

    using child_indices_type = std::array<uint64_t, 2>;

    struct sparse_hash_tree_node_type {
        child_indices_type child_index;
        hash_type hash;
    };

private:

    static inline uint64_t get_left_index(const node_t &node) {
        return node.child[0];
    }

    static inline uint64_t get_right_index(const node_t &node) {
        return node.child[1];
    }

    static constexpr auto is_address_range(const node_t &node) {
        return get_left_index(node) == UINT64_MAX;
    }

    static inline uint64_t get_address_range_index(const node_t &node) {
        return get_right_index(node);
    }

    static constexpr auto is_pristine(uint64_t index) {
        return index == 0;
    }

    /// \brief Update the root hash, and then return it.
    /// \returns A pair with, first, the updated hash and, second, a boolean that is true if the call
    /// may have changed the root hash since the last call to this method.
    std::pair<const hash_type &, bool> update_and_get_root_hash(uint64_t index, int log2_size) {
        if (is_pristine(index)) {
            return {get_pristine_hash(log2_size), false};
        }
        auto &node = m_nodes.at(index);
        if (is_address_range(node) {
            return update_and_get_address_ranges_root_hash(get_address_range_index(node));
        }
        const auto [left, left_updated] = update_and_get_root_hash(get_left_index(node), log2_size-1);
        const auto [right, right_updated] = update_and_get_root_hash(get_right_index(node), log2_size-1);
        const auto updated = left_updated || right_updated;
        if (updated) {
            get_concat_hash(left, right, node.hash);
        }
        return { node.hash, updated };
    }

    const hash_type &get_node_hash(uint64_t index, int log2_size) const {
        if (is_pristine(index)) {
            return get_pristine_hash(log2_size);
        }
        return m_nodes.at(index).hash;
    }

    void append_pristine_sibling_hashes(int log2_root_size, int log2_target_size, sibling_hashes_types &siblings) {
        while (log2_root_size != log2_target_size) {
            --log2_root_size;
            siblings.push_back(get_pristine_hash(log2_root_size));
        }
    }

    // -----
    // i_machine_hash_tree interface implementation
    // -----

    const hash_type &do_update_and_get_root_hash() override {
#pragma omp parallel
#pragma omp single
        {
            return update_and_get_root(1, 64);
        }
    }

    const hash_type &do_get_root_hash() override {
        returm m_nodes[1].hash;
    }

    /// \brief Appends the list of sibling hashes to an array
    /// \param log2_root_size Log<sub>2</sub> of number of bytes subintended by subtree of interest.
    /// \param target_address Starting address of data subintended by target node.
    /// \param log2_target_size Log<sub>2</sub> of number of bytes subintended by target note.
    /// \param siblings Receives the sibling hashes
    /// \details \p log2_root_size cannot be larger than get_log2_root_size().
    /// \p log2_target_size cannot be smaller than get_log2_word_size().
    /// \p log2_target_size cannot be larger than \p log2_root_size.
    /// \p target_address must be aligned to 2^(\p log2_target_size).
    /// The hash of all siblings in the path that starts at (\p target_address):(\p log2_root_size-1) and ends at
    /// node (\p target_address):(\p log2_root_size) are appended, in this order.
    /// In total, (\p log2_root_size - \p log2_target_size) sibling hashes are appended.
    void do_get_sibling_hashes(int log2_root_size, uint64_t target_address, int log2_target_size,
        sibling_hashes_t &siblings) {
        if (log2_root_size < log2_target_size) {
            throw std::domain_error{"log2_root_size cannot be smaller than log2_target_size"};
        }
        if (log2_root_size > get_log2_root_size()) {
            throw std::domain_error{"log2_root_size is too large"};
        }
        if (log2_target_size < get_log2_word_size()) {
            throw std::domain_error{"log2_target_size is too small"};
        }
        siblings.clear();
        siblings.reserve(log2_root_size - log2_target_size);
        uint64_t index = 1;
        // Go down on tree until we hit a PMA node, a pristine node, or the target node
        while (log2_root_size != log2_target_size) {
            if (is_pristine(index)) {
                append_pristine_sibling_hashes(log2_root_size, log2_target_size, siblings);
                return;
            }
            const auto &node = m_nodes.at(index);
            if (is_address_range(node)) {
                m_pmas.at(get_address_range_index(node))
                    ->append_sibling_hashes(log2_root_size, target_address, log2_target_size, siblings);
                return;
            }
            --log2_root_size;
            const auto in_path_to_target = (target_address >> log2_root_size) & 1;
            const auto sibling = in_path_to_target ^ 1;
            siblings.push_back(get_node_hash(node.child[sibling], log2_root_size));
            index = node.child[in_path_to_target];
        }
    }

    int do_get_log2_root_size() {
        return 64;
    }
};

class pmas_hash_tree : public i_hash_tree {
private:
    mmapped_vector<hashes_t> m_hashes;
    mmapped_vector<uint8_t> m_dirty;

    const hash_type &get_root_hash() const {
        return m_nodes[1];
    }

    /// \brief Update the root hash, and return it
    /// \returns A pair with, first, the updated hash and, second, a boolean that is true if the call
    /// may have changed the root hash
    std::pair<const hash_type &, bool> update_and_get_root_hash() {}

    void get_sibling_hashes(uint64_t paddr, int log2_root_size, int log2_target_size,
        sibling_hashes_t &siblings) const {
        return do_get_sibling_hashes(paddr, log2_root_size, log2_target_size, siblings);
    }

    int do_get_log2_root_size() {
        return // pma length rounded up to next power of two
    }
};

#endif

class hash_tree {
public:
    using hasher_type = keccak_256_hasher;
    using proof_type = merkle_tree_proof;
    using child_indices_type = std::array<uint64_t, 2>;
    struct node_type {
        child_indices_type child_index{};
        machine_hash hash{};
    };
    using nodes_type = std::vector<node_type>;
    using sibling_hashes_type = std::vector<machine_hash>;

    static nodes_type create_nodes(const machine &m, uint64_t ar_index_end);
    static void dump_nodes(const machine &m, const nodes_type &nodes, std::ostream &out);

private:
    static void check_address_ranges(const machine &m, uint64_t ar_index_end);
    static uint64_t append_nodes(const machine &m, uint64_t begin_page_index, uint64_t log2_page_count,
        uint64_t &ar_index, uint64_t ar_index_end, nodes_type &nodes);
};

} // namespace cartesi

#endif // HASH_TREE_H
