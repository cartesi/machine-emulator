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
#include "machine-address-ranges.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "merkle-tree-proof.h"
#include "page-hash-tree-cache.h"
#include "unique-c-ptr.h"

namespace cartesi {

class hash_tree {

    using page_entry = std::pair<const address_range &, page_hash_tree_cache::borrowed_entry>;
    using page_entries = std::vector<page_entry>;
    using dense_node_entry = std::pair<i_dense_hash_tree &, uint64_t>;
    using dense_node_entries = std::vector<dense_node_entry>;
    using pristine_hashes = std::array<machine_hash, HASH_TREE_LOG2_ROOT_SIZE + 1>;

    // This is ensures we use the hash_tree_view of machine_address_ranges everywhere
    template <typename MAR>
    class hash_tree_view : public std::ranges::view_interface<hash_tree_view<MAR>> {
        using V = decltype(std::declval<MAR>().hash_tree_view());
        static_assert(std::ranges::random_access_range<V>, "not a random access range");
        static_assert(std::ranges::view<V>, "not a view");
        V m_view;

    public:
        /// \brief Automatic construction from object of type MAR
        explicit(false) hash_tree_view(MAR &ars) : m_view{ars.hash_tree_view()} {}
        auto begin() const
            requires std::ranges::range<const V>
        {
            return std::ranges::begin(m_view);
        }
        auto end() const
            requires std::ranges::range<const V>
        {
            return std::ranges::end(m_view);
        }
        auto begin() {
            return std::ranges::begin(m_view);
        }
        auto end() {
            return std::ranges::end(m_view);
        }
    };
    using address_ranges = hash_tree_view<machine_address_ranges>;
    using const_address_ranges = hash_tree_view<const machine_address_ranges>;

public:
    using hasher_type = keccak_256_hasher;
    using proof_type = merkle_tree_proof;

    struct node_type {
        uint64_t left{};
        uint64_t right{};
        uint64_t parent{};
        uint64_t log2_size{};
        machine_hash hash{};
    };

    using nodes_type = std::vector<node_type>;
    using sibling_hashes_type = std::vector<machine_hash>;

    hash_tree(const hash_tree_config &config, const_address_ranges ars);

    bool update(address_ranges ars);

    void get_root_hash(machine_hash_view hash) const noexcept;

    void dump(address_ranges ars, std::ostream &out);

private:
    pristine_hashes get_pristine_hashes() const;

    bool update_page_entry(hasher_type &h, const address_range &ar,
        page_hash_tree_cache::entry &entry);
    bool return_updated_page_entries(page_entries &entries);
    bool update_dense_trees(address_ranges ars);
    bool update_sparse_tree(address_ranges ars);
    const_machine_hash_view get_node_hash_view(uint64_t node_index, int log2_size) const noexcept;
    bool update_page_hashes(address_ranges ars);
    void update_and_clear_dense_node_entries(dense_node_entries &batch, int log2_size);

    template <std::random_access_iterator Iter, std::sentinel_for<Iter> Sent>
        requires(std::same_as<std::remove_cvref_t<std::iter_reference_t<Iter>>, address_range> &&
            std::is_reference_v<std::iter_reference_t<Iter>>)
    static uint64_t append_nodes(uint64_t begin_page_index, uint64_t log2_page_count, Iter &ar_curr /* modifiable! */,
        Iter ar_begin, Sent ar_sent, hash_tree::nodes_type &nodes, uint64_t parent);

    static nodes_type create_nodes(const_address_ranges ars);
    static void check_address_ranges(const_address_ranges ars);

    nodes_type m_nodes;
    page_hash_tree_cache m_cache;
    const pristine_hashes m_pristine_hashes;
    const page_hash_tree_cache::page_hash_tree m_pristine_page_hash_tree;
};

} // namespace cartesi

#endif // HASH_TREE_H
