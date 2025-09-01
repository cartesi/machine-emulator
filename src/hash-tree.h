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

#include <array>
#include <concepts>
#include <cstdint>
#include <iosfwd>
#include <iterator>
#include <memory_resource>
#include <ranges>
#include <type_traits>
#include <vector>

#include "unordered_dense.h"

#include "address-range.h"
#include "hash-tree-constants.h"
#include "hash-tree-proof.h"
#include "hash-tree-stats.h"
#include "i-dense-hash-tree.h"
#include "machine-address-ranges.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "page-hash-tree-cache-stats.h"
#include "page-hash-tree-cache.h"
#include "variant-hasher.h"

#ifdef HAS_SIGNPOSTS
#include "signposts.h"
#endif

namespace cartesi {

class hash_tree {

    struct dirty_page {
        int ar_index; ///< Source address range
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
        page_hash_tree_cache::entry &br; ///< Borrowed page hash-tree cache entry
        bool changed;                    ///< Whether the update operation really changed the page
    };

    using dirty_pages = std::pmr::vector<dirty_page>;
    struct dense_node_entry {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
        i_dense_hash_tree &dht;
        uint64_t offset;
        bool operator==(const dense_node_entry &other) const {
            return &dht == &other.dht && offset == other.offset;
        }
    };
    using dense_node_entries = std::pmr::vector<dense_node_entry>;
    using pristine_hashes = std::array<machine_hash, HASH_TREE_LOG2_ROOT_SIZE + 1>;

    using index_type = int64_t;

    static constexpr index_type AR_NODE_TAG{-1};
    static constexpr index_type PRISTINE_NODE_TAG{0};

    struct node_type {
        index_type left{};
        index_type right{};
        index_type parent{};
        uint32_t log2_size{};
        uint32_t marked{};
        machine_hash hash{};
    };

    static bool is_ar_node(const node_type &node) {
        return node.left == AR_NODE_TAG;
    }

    static bool is_pristine(index_type index) {
        return index == PRISTINE_NODE_TAG;
    }

    static index_type get_ar_sparse_node_index(index_type ar_index) {
        return ar_index + 2;
    }

    // This is ensures we use the hash_tree_view of machine_address_ranges everywhere
    template <typename MAR>
    class hash_tree_view final : public std::ranges::view_interface<hash_tree_view<MAR>> {
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
    using proof_type = hash_tree_proof;

    using dirty_words_type = ankerl::unordered_dense::set<uint64_t>;
    using dirty_pages_type = ankerl::unordered_dense::set<uint64_t>;
    using nodes_type = std::vector<node_type>;
    using sibling_hashes_type = std::vector<machine_hash>;

    hash_tree(const hash_tree_config &config, uint64_t concurrency, const_address_ranges ars,
        hash_function_type hash_function);

    hash_tree(const hash_tree &other) = delete;
    hash_tree(hash_tree &&other) = delete;
    hash_tree &operator=(hash_tree &&other) = delete;
    hash_tree &operator=(const hash_tree &other) = delete;

    ~hash_tree();

    bool update(address_ranges ars);

    bool update_words(address_ranges ars, const dirty_words_type &dirty_words);

    bool update_page(address_ranges ars, uint64_t paddr_page);

    bool verify(address_ranges ars) const;

    machine_hash get_root_hash() const noexcept;
    machine_hash get_node_hash(address_ranges ars, uint64_t address, int log2_size);
    proof_type get_proof(address_ranges ars, uint64_t address, int log2_size);

    void dump(const_address_ranges ars, std::ostream &out);

    hash_tree_stats get_stats(bool clear = false) noexcept;

private:
    using changed_address_ranges = std::pmr::vector<int>;

    void get_pristine_proof(int curr_log2_size, proof_type &proof) const;
    void get_dense_proof(address_range &ar, int ar_log2_size, uint64_t address, proof_type &proof);
    void get_page_proof(address_range &ar, uint64_t address, proof_type &proof);

    machine_hash get_dense_node_hash(address_range &ar, uint64_t address, int log2_size);

    static pristine_hashes get_pristine_hashes(hash_function_type hash_function);

    bool update_dirty_pages(address_ranges ars, changed_address_ranges &changed_ars);
    bool update_dirty_page(address_range &ar, page_hash_tree_cache::entry &entry, bool &changed);
    bool enqueue_hash_dirty_page(page_hash_tree_cache::simd_page_hasher<variant_hasher> &queue, address_range &ar,
        page_hash_tree_cache::entry &entry, page_hash_tree_cache_stats &stats);
    bool return_updated_dirty_pages(address_ranges ars, dirty_pages &batch, changed_address_ranges &changed_ars);

    bool update_dense_trees(address_ranges ars, const changed_address_ranges &changed_ars);
    void update_and_clear_dense_node_entries(dense_node_entries &batch, int log2_size);

    const_machine_hash_view get_sparse_node_hash_view(index_type node_index, int log2_size) const noexcept;
    bool update_sparse_tree(address_ranges ars, const changed_address_ranges &changed_ars);

    template <std::random_access_iterator Iter, std::sentinel_for<Iter> Sent>
        requires(std::same_as<std::remove_cvref_t<std::iter_reference_t<Iter>>, address_range> &&
            std::is_reference_v<std::iter_reference_t<Iter>>)
    static index_type append_nodes(uint64_t begin_page_index, uint64_t log2_page_count, Iter &ar_curr /* modifiable! */,
        Iter ar_begin, Sent ar_sent, hash_tree::nodes_type &nodes, index_type parent);

    static nodes_type create_nodes(const_address_ranges ars);
    static void check_address_ranges(const_address_ranges ars);

#ifdef HAS_SIGNPOSTS
    os_log_t m_log;
    os_signpost_id_t m_spid_update;
    os_signpost_id_t m_spid_update_page_hashes;
    os_signpost_id_t m_spid_update_dense_trees;
    os_signpost_id_t m_spid_update_sparse_tree;
#endif

    mutable page_hash_tree_cache m_page_cache;
    //??D Replace std::vector so entries can live on disk
    nodes_type m_sparse_nodes;
    const pristine_hashes m_pristine_hashes;
    int m_concurrency;
    hash_function_type m_hash_function;
    std::pmr::unsynchronized_pool_resource m_memory_pool;
    uint64_t m_sparse_node_hashes{0};
    std::array<uint64_t, HASH_TREE_LOG2_ROOT_SIZE> m_dense_node_hashes{};
};

} // namespace cartesi

#endif // HASH_TREE_H
