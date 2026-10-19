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

#ifndef PAGE_HASH_TREE_CACHE_HPP
#define PAGE_HASH_TREE_CACHE_HPP

/// \file
/// \brief Page hash-tree cache interface

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <ranges>
#include <span>
#include <utility>
#include <vector>

#include <boost/container/static_vector.hpp>
#include <boost/interprocess/offset_ptr.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/list_hook.hpp>

#include "algorithm.hpp"
#include "assert-printf.hpp"
#include "concepts.hpp"
#include "hash-tree-constants.hpp"
#include "i-hasher.hpp"
#include "is-pristine.hpp"
#include "machine-hash.hpp"
#include "os-mapped-memory.hpp"
#include "page-hash-tree-cache-stats.hpp"
#include "ranges.hpp"
#include "simd-hasher.hpp"
#include "unordered_dense.h"

namespace cartesi {

/// \class page_hash_tree_cache
/// \brief Page hash-tree cache implementation
class page_hash_tree_cache {

    static constexpr int m_page_size = HASH_TREE_PAGE_SIZE;
    static constexpr int m_word_size = HASH_TREE_WORD_SIZE;
    static constexpr int m_page_word_count = m_page_size / m_word_size; ///< Number of words in a page
    static constexpr int m_page_hash_tree_size = 2 * m_page_word_count; ///< Number of words in a page hash-tree

    using address_type = uint64_t;

public:
    using page = std::array<unsigned char, m_page_size>;
    using page_view = std::span<unsigned char, m_page_size>;
    using const_page_view = std::span<const unsigned char, m_page_size>;

    using page_hash_tree = std::array<machine_hash, m_page_hash_tree_size>;
    using page_hash_tree_view = std::span<machine_hash, m_page_hash_tree_size>;
    static_assert(POD<page>, "hash_tree must be trivially copyable and standard layout");
    static_assert(POD<machine_hash>, "machine_hash must be trivially copyable and standard layout");
    static_assert(POD<page_hash_tree>, "page_hash_tree must be trivially copyable and standard layout");

    enum initialized_tag : uint64_t {
        uninitialized = 0,
        initialized = 0x0250485443, // PHTC, layout version 2
    };

    /// \class entry_metadata
    /// \brief Metadata for a page hash-tree cache entry
    class alignas(sizeof(uint64_t)) entry_metadata final :
        public boost::intrusive::list_base_hook<boost::intrusive::void_pointer<
            boost::interprocess::offset_ptr<void, int64_t, uint64_t, sizeof(uint64_t)>>> {
        using ref = std::reference_wrapper<entry_metadata>;

        address_type m_paddr_page{}; ///< Physical page address
        uint64_t m_borrowed{};       ///< Whether entry is borrowed
        uint64_t m_payload_index{};  ///< Index in the separate payload array

        friend page_hash_tree_cache;

        /// \brief Sets physical page address for entry
        /// \param paddr_page Physical page address
        /// \returns Reference to entry
        entry_metadata &set_paddr_page(address_type paddr_page) noexcept {
            m_paddr_page = paddr_page;
            return *this;
        }

        /// \brief Sets borrowed flag for entry
        /// \param borrowed Whether entry is borrowed
        /// \returns Reference to entry
        entry_metadata &set_borrowed(bool borrowed) noexcept {
            m_borrowed = static_cast<uint64_t>(borrowed);
            return *this;
        }

        /// \brief Returns whether entry is borrowed
        bool get_borrowed() const noexcept {
            return m_borrowed != 0;
        }

    public:
        entry_metadata() = default;
        entry_metadata(const entry_metadata &other) = delete;
        entry_metadata(entry_metadata &&other) = delete;
        entry_metadata &operator=(const entry_metadata &other) = delete;
        entry_metadata &operator=(entry_metadata &&other) = delete;
        ~entry_metadata() = default;

        /// \brief Returns physical page address for entry
        address_type get_paddr_page() const noexcept {
            return m_paddr_page;
        }
    };

    /// \class entry_payload
    /// \brief Cached page and its page hash tree
    class alignas(m_page_size) entry_payload final {
        page m_page{};
        page_hash_tree m_hash_tree{};

        friend page_hash_tree_cache;

        /// \brief Makes cached page pristine
        void clear_page() noexcept {
            std::ranges::fill(m_page, 0);
        }

        /// \brief Makes cached page hash tree pristine
        /// \param pristine Pristine page hash tree
        void clear_hash_tree(const page_hash_tree &pristine) noexcept {
            m_hash_tree = pristine;
        }

        /// \brief Makes cached page and its hash tree pristine
        /// \param pristine Pristine page hash tree
        void clear(const page_hash_tree &pristine) noexcept {
            clear_page();
            clear_hash_tree(pristine);
        }

        /// \brief Returns index of left child of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's left child
        static constexpr int left_child(int i) noexcept {
            return 2 * i;
        }

        /// \brief Returns index of right child of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's right child
        static constexpr int right_child(int i) noexcept {
            return (2 * i) + 1;
        }

        /// \brief Returns index of parent of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's parent
        static constexpr int parent(int i) noexcept {
            return i / 2;
        }

        /// \brief Returns a pristine page tree for a given hasher
        /// \tparam H Hasher type
        /// \param h Hasher object
        /// \returns Pristine page hash tree
        template <IHasher H>
        // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
        static page_hash_tree get_pristine_page_hash_tree(H &&h) noexcept {
            page_hash_tree tree{};
            std::array<unsigned char, m_word_size> zero{};
            machine_hash hash = get_hash(h, zero);
            auto start = m_page_word_count;
            while (start > 0) {
                for (auto i = start; i < 2 * start; ++i) {
                    tree[i] = hash;
                }
                start /= 2;
                get_concat_hash(h, hash, hash, hash);
            }
            return tree;
        }

    public:
        /// \brief Returns cached page hash tree
        /// \returns Reference to cached page hash tree
        const auto &get_page_hash_tree() const noexcept {
            return m_hash_tree;
        }

        /// \brief Returns cached page hash tree
        /// \returns Reference to cached page hash tree
        auto &get_page_hash_tree() noexcept {
            return m_hash_tree;
        }

        /// \brief Returns cached page
        /// \returns Reference to cached page
        const auto &get_page() const noexcept {
            return m_page;
        }

        /// \brief Returns cached page
        /// \returns Reference to cached page
        auto &get_page() noexcept {
            return m_page;
        }

        /// \brief Returns view to root hash from cached page hash tree
        /// \returns View to root hash
        const_machine_hash_view root_hash_view() const noexcept {
            return m_hash_tree[1];
        }

        /// \brief Returns view to node hash from cached page hash tree
        /// \param offset Node offset within page
        /// \param log2_size Log<sub>2</sub> of node size. Must be between log<sub>2</sub> of word and page sizes
        /// \returns View to node hash
        const_machine_hash_view node_hash_view(address_type offset, int log2_size) const noexcept {
            static constexpr machine_hash no_hash{};
            if (log2_size < HASH_TREE_LOG2_WORD_SIZE || log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
                assert(false && "log2_size is out of range");
                return no_hash;
            }
            auto start = address_type{1} << (HASH_TREE_LOG2_PAGE_SIZE - log2_size);
            auto index = offset >> log2_size;
            if (index > start || (index << log2_size) != offset) {
                assert(false && "offset is out of range");
                return no_hash;
            }
            return m_hash_tree[start + index];
        }
    };

    /// \brief Doubly-linked list of cache entries used for LRU (Least Recently Used) management.
    /// \details The underlying data structure maintains three uint64_t values:
    /// - An offset pointer to the list head
    /// - An offset pointer to the list tail
    /// - The current size of the list
    using lru = boost::intrusive::list<entry_metadata, boost::intrusive::size_type<uint64_t>>;

    // Ensure LRU, entry, and payload sizes are the same across all platforms we support
    static_assert(sizeof(lru) == 3 * sizeof(uint64_t), "unexpected LRU size");
    static_assert(sizeof(entry_metadata) == 5 * sizeof(uint64_t), "unexpected entry size");
    static_assert(sizeof(entry_payload) == m_page_size + (m_page_hash_tree_size * MACHINE_HASH_SIZE),
        "unexpected payload size");

    template <IHasher hasher_type>
    class simd_page_hasher {
        struct leaf_entry {
            const_hash_tree_word_view data;
            machine_hash_view result;
        };

        struct node_entry {
            const_machine_hash_view left;
            const_machine_hash_view right;
            machine_hash_view result;
        };

        struct dirty_entry {
            page_hash_tree_view page_tree;
            int node_index{0};
            bool operator==(const dirty_entry &other) const noexcept {
                return page_tree.data() == other.page_tree.data() && node_index == other.node_index;
            }
        };

        static constexpr size_t QUEUE_MAX_SIZE =
            (UINT64_C(1) << ((HASH_TREE_LOG2_PAGE_SIZE - HASH_TREE_LOG2_WORD_SIZE) - 1)) * hasher_type::MAX_LANE_COUNT;

        simd_data_hasher<hasher_type, const_hash_tree_word_view> m_leaves_queue;
        simd_concat_hasher<hasher_type, const_machine_hash_view> m_concat_queue;
        boost::container::static_vector<dirty_entry, QUEUE_MAX_SIZE> m_dirty_queue;

    public:
        static constexpr int QUEUE_MAX_PAGE_COUNT = hasher_type::MAX_LANE_COUNT;

        explicit simd_page_hasher(hasher_type &hasher) : m_leaves_queue{hasher}, m_concat_queue{hasher} {}

        /// \brief Enqueues a leaf for hashing
        // NOLINTNEXTLINE(bugprone-exception-escape)
        void enqueue_leaf(const_hash_tree_word_view data, page_hash_tree_view page_tree, int word_index) noexcept {
            m_leaves_queue.enqueue(data, page_tree[word_index]);
            try_push_back(m_dirty_queue,
                dirty_entry{.page_tree = page_tree, .node_index = entry_payload::parent(word_index)});
        }

        /// \brief Flushes the entire queue
        // NOLINTNEXTLINE(bugprone-exception-escape)
        int flush() noexcept {
            m_leaves_queue.flush();
            int hashes = 0;

            decltype(m_dirty_queue) next_dirty_queue;
            while (!m_dirty_queue.empty()) {
                for (const dirty_entry &d : m_dirty_queue) {
                    ++hashes;
                    m_concat_queue.enqueue(d.page_tree[entry_payload::left_child(d.node_index)],
                        d.page_tree[entry_payload::right_child(d.node_index)], d.page_tree[d.node_index]);
                    if (d.node_index > 1) [[likely]] {
                        try_push_back(next_dirty_queue,
                            dirty_entry{.page_tree = d.page_tree, .node_index = entry_payload::parent(d.node_index)});
                    }
                }
                m_concat_queue.flush();
                m_dirty_queue.clear();
                std::swap(m_dirty_queue, next_dirty_queue);
            }
            return hashes;
        }
    };

    /// \brief Enqueue entry to be hashed with new page data
    /// \tparam H Hasher type
    /// \tparam D Data range type
    /// \param h Hasher object
    /// \param d Contiguous range with new page data
    /// \param e Entry to update
    /// \returns True if update succeeded, false otherwise
    template <IHasher H, ContiguousRangeOfByteLike D>
    // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
    bool enqueue_hash_entry(page_hash_tree_cache::simd_page_hasher<H> &queue, D &&d, entry_metadata &e,
        page_hash_tree_cache_stats &stats) noexcept {
        if (std::ranges::size(d) != m_page_size) [[unlikely]] {
            return false;
        }
        auto &payload = get_payload(e);
        if (is_pristine(d)) {
            payload.clear_hash_tree(m_pristine_page_hash_tree);
            payload.clear_page();
            ++stats.pristine_pages;
            return true;
        }
        const const_page_view page{std::ranges::data(d), std::ranges::size(d)};
        // Go over all words in the entry page, comparing with updated page,
        // and updating the hashes for the modified words
        //??D In C++23, we would use std::views::slide and std::views::zip to write this in declarative style.
        const page_view entry_page{payload.get_page()};
        int hit = 0;
        int miss = 0;
        auto &page_tree = payload.get_page_hash_tree();
        for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
            const auto entry_word = std::span<unsigned char, m_word_size>{entry_page.subspan(offset, m_word_size)};
            const auto page_word = std::span<const unsigned char, m_word_size>{page.subspan(offset, m_word_size)};
            if (!std::ranges::equal(entry_word, page_word)) [[unlikely]] {
                std::ranges::copy(page_word, entry_word.begin());
                queue.enqueue_leaf(page_word, page_tree, index);
                ++miss;
            } else {
                ++hit;
            }
        }
        stats.word_hits += hit;
        stats.word_misses += miss;
        ++stats.non_pristine_pages;
        return true;
    }

    template <IHasher H>
    // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
    bool verify_entry(H &&h, entry_metadata &e) noexcept {
        std::cerr << "verifying entry\n";
        const auto &payload = get_payload(e);
        const const_page_view entry_page{payload.get_page()};
        const auto &page_tree = payload.get_page_hash_tree();
        for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
            const auto page_word = std::span<const unsigned char, m_word_size>{entry_page.subspan(offset, m_word_size)};
            const auto page_word_hash = get_hash(h, page_word);
            if (page_word_hash != page_tree[index]) {
                const int log2_size = HASH_TREE_LOG2_WORD_SIZE;
                std::cerr << "hash mismatch in index " << std::dec << index << ":" << log2_size << '\n';
                return false;
            }
        }
        int start = m_page_word_count / 2;
        const int log2_size = HASH_TREE_LOG2_WORD_SIZE + 1;
        while (start != 0) {
            for (int index = start; index < 2 * start; ++index) {
                const auto node_hash = get_concat_hash(h, page_tree[entry_payload::left_child(index)],
                    page_tree[entry_payload::right_child(index)]);
                if (node_hash != page_tree[index]) {
                    std::cerr << "hash mismatch in index " << std::dec << index << ":" << log2_size << '\n';
                    return false;
                }
            }
            start /= 2;
        }
        return true;
    }

    /// \brief Constructor from hasher and number of entries
    /// \tparam H Hasher type
    /// \param h Hasher object
    /// \param num_entries Number of entries in cache
    template <IHasher H>
    page_hash_tree_cache(H &&h, size_t num_entries, const std::string &backing_filename, bool shared) :
        m_mapped_memory{get_storage_length(num_entries), os::mapped_memory_flags{.shared = shared}, backing_filename},
        // get_storage_length() checks all layout arithmetic before mapping, and mapped_memory
        // requires an exact backing-file length. All following regions fit within that mapping.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_initialized{*reinterpret_cast<initialized_tag *>(m_mapped_memory.get_ptr())},
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_lru{*reinterpret_cast<lru *>(m_mapped_memory.get_ptr() + sizeof(initialized_tag))},
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_entries{reinterpret_cast<entry_metadata *>(m_mapped_memory.get_ptr() + sizeof(initialized_tag) + sizeof(lru)),
            num_entries},
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_payloads{reinterpret_cast<entry_payload *>(m_mapped_memory.get_ptr() + get_payloads_offset(num_entries)),
            num_entries},
        m_pristine_page_hash_tree{entry_payload::get_pristine_page_hash_tree(std::forward<H>(h))} {
        m_map.reserve(num_entries);

        // Initialize mapped memory if needed
        if (m_initialized == initialized_tag::uninitialized) {
            // Use placement new to initialize the mapped list, entries, and payloads.
            new (&m_lru) lru;
            new (m_entries.data()) entry_metadata[num_entries];
            new (m_payloads.data()) entry_payload[num_entries];
            for (size_t i = 0; i < num_entries; ++i) {
                m_entries[i].m_payload_index = i;
                m_payloads[i].clear_hash_tree(m_pristine_page_hash_tree);
            }
            m_initialized = initialized_tag::initialized;
        } else {
            // Validate if the file type is correct
            if (m_initialized != initialized_tag::initialized) {
                throw std::runtime_error{"corrupted page hash-tree cache: file tag mismatch"};
            }

            check_metadata();
            // The active entries occupy an array prefix, regardless of their LRU order.
            for (auto &e : m_entries.first(m_lru.size())) {
                if (!m_map.emplace(e.get_paddr_page(), e).second) {
                    throw std::runtime_error{"corrupted page hash-tree cache: duplicate page address"};
                }
            }
        }
    }

    page_hash_tree_cache(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache(page_hash_tree_cache &&other) = delete;
    page_hash_tree_cache &operator=(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache &operator=(page_hash_tree_cache &&other) = delete;

    static uint64_t get_storage_length(size_t num_entries) {
        constexpr auto header_length = sizeof(initialized_tag) + sizeof(lru);
        constexpr auto entry_length = sizeof(entry_metadata) + sizeof(entry_payload);
        // Bound allocation size and pointer differences, including padding before the payload array.
        constexpr auto max_length = static_cast<size_t>(std::numeric_limits<ptrdiff_t>::max());
        if (num_entries == 0) {
            throw std::invalid_argument{"page hash-tree cache must have at least one entry"};
        }
        if (num_entries > (max_length - header_length - (m_page_size - 1)) / entry_length) {
            throw std::invalid_argument{"invalid page hash-tree cache capacity"};
        }
        return get_payloads_offset(num_entries) + (num_entries * sizeof(entry_payload));
    }

    std::span<const unsigned char> get_storage_data() const noexcept {
        return m_mapped_memory.get_storage_data();
    }

    /// \brief Returns payload for a cache entry
    /// \param e Cache entry
    /// \returns Reference to entry payload
    entry_payload &get_payload(entry_metadata &e) noexcept {
        return m_payloads[e.m_payload_index];
    }

    /// \brief Returns payload for a cache entry
    /// \param e Cache entry
    /// \returns Reference to entry payload
    const entry_payload &get_payload(const entry_metadata &e) const noexcept {
        return m_payloads[e.m_payload_index];
    }

    /// \brief Tries to borrow a cache entry
    /// \param paddr_page Target physical address of page to borrow
    /// \returns Entry for page if in cache, nothing otherwise
    std::optional<entry_metadata::ref> borrow_entry_if_hit(address_type paddr_page) {
        // Found entry for page in map?
        if (auto it = m_map.find(paddr_page); it != m_map.end()) {
            entry_metadata &e = it->second;
            if (e.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            // Return borrowed entry
            return std::ref(e.set_borrowed(true));
        }
        return {};
    }

    /// \brief Tries to borrow a cache entry
    /// \param paddr_page Target physical address of page to borrow
    /// \param hit Receives true if page was found in cache, false if another page was evicted and its entry returned
    /// \returns Entry for page, nothing if all pages have already been borrowed
    std::optional<entry_metadata::ref> borrow_entry(address_type paddr_page, bool &hit) {
        // Found entry for page in map?
        if (auto it = m_map.find(paddr_page); it != m_map.end()) {
            entry_metadata &e = it->second;
            if (e.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            // Make it most recently used
            m_lru.splice(m_lru.begin(), m_lru, m_lru.iterator_to(e));
            hit = true;
            ++m_stats.page_hits;
            // Return borrowed entry
            return std::ref(e.set_borrowed(true));
        }
        hit = false;
        // Not in map, but we still have unused entries to lend
        if (m_lru.size() < m_entries.size()) {
            ++m_stats.page_misses;
            entry_metadata &e = m_entries[m_lru.size()];
            if (e.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            m_lru.push_front(e);
            m_map.emplace(paddr_page, e);
            // Return borrowed
            return std::ref(e.set_borrowed(true).set_paddr_page(paddr_page));
        }
        // Evict least recently used
        auto &e = m_lru.back();
        // If even that has been borrowed, we are out of entries to lend
        if (e.get_borrowed()) {
            return {};
        }
        ++m_stats.page_misses;
        m_map.erase(e.get_paddr_page());
        m_lru.pop_back();
        m_lru.push_front(e);
        m_map.emplace(paddr_page, e);
        return std::ref(e.set_borrowed(true).set_paddr_page(paddr_page));
    }

    /// \brief Tries to borrow a cache entry
    /// \param paddr_page Target physical address of page to borrow
    /// \returns Entry for page, nothing if all pages have already been borrowed
    auto borrow_entry(address_type paddr_page) {
        bool hit = false;
        return borrow_entry(paddr_page, hit);
    }

    /// \brief Returns entry that has been borrowed
    /// \param e Entry to return
    static bool return_entry(entry_metadata &e) {
        if (!e.get_borrowed()) {
            throw std::runtime_error{"returning page hash-tree cache entry that is not borrowed"};
        }
        e.set_borrowed(false);
        return true;
    }

    /// \brief Returns maximum number of entries in cache
    constexpr auto capacity() const noexcept {
        return m_entries.size();
    }

    /// \brief Evicts entries whose page addresses satisfy a predicate
    /// \param predicate Predicate over physical page addresses
    template <typename Predicate>
    void evict_entries_if(Predicate predicate) {
        for (size_t i = 0; i < m_lru.size();) {
            auto &e = m_entries[i];
            if (!predicate(e.get_paddr_page())) {
                ++i;
                continue;
            }
            auto &last = m_entries[m_lru.size() - 1];
            if (e.get_borrowed() || last.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            m_map.erase(e.get_paddr_page());
            m_lru.erase(m_lru.iterator_to(e));
            if (&e != &last) {
                // Keep active entries in the array prefix used by borrow_entry().
                std::swap(e.m_payload_index, last.m_payload_index);
                e.set_paddr_page(last.get_paddr_page());
                m_lru.insert(m_lru.iterator_to(last), e);
                m_lru.erase(m_lru.iterator_to(last));
                m_map.at(e.get_paddr_page()) = std::ref(e);
            }
        }
    }

    /// \brief Clears entire cache
    void clear() noexcept {
        m_lru.clear();
        m_map.clear();
        for (auto &e : m_entries) {
            get_payload(e).clear(m_pristine_page_hash_tree);
            e.set_paddr_page(0).set_borrowed(false);
        }
    }

    /// \brief Returns current statistics
    /// \param clear Whether to clear statistics after retrieving them
    /// \returns Statistics
    page_hash_tree_cache_stats get_stats(bool clear = false) noexcept {
        auto stats = m_stats;
        if (clear) {
            m_stats = page_hash_tree_cache_stats{};
        }
        return stats;
    }

    page_hash_tree_cache_stats &get_stats_ref() noexcept {
        return m_stats;
    }

    /// \brief Destructor
    ~page_hash_tree_cache() {
#ifdef DUMP_HASH_TREE_STATS
        auto s = get_stats();
        auto pages_all = s.page_hits + s.page_misses;
        if (pages_all > 0) {
            std::cerr << "page hits: " << s.page_hits << '\n';
            std::cerr << "page misses: " << s.page_misses << '\n';
            std::cerr << "page hit rate: " << 100.0 * static_cast<double>(s.page_hits) / static_cast<double>(pages_all)
                      << '\n';
        }
        auto word_all = s.word_hits + s.word_misses;
        if (word_all > 0) {
            std::cerr << "word hits: " << s.word_hits << '\n';
            std::cerr << "word misses: " << s.word_misses << '\n';
            std::cerr << "word hit rate: " << 100.0 * static_cast<double>(s.word_hits) / static_cast<double>(word_all)
                      << '\n';
        }
        std::cerr << "changed pages: " << s.page_changes << '\n';
        std::cerr << "inner page hashes: " << s.inner_page_hashes << '\n';
        auto pristine_all = s.pristine_pages + s.non_pristine_pages;
        if (pristine_all > 0) {
            std::cerr << "pristine pages: " << s.pristine_pages << '\n';
            std::cerr << "non-pristine pages: " << s.non_pristine_pages << '\n';
            std::cerr << "pristine page ratio: "
                      << 100.0 * static_cast<double>(s.pristine_pages) / static_cast<double>(pristine_all) << '\n';
        }
#endif
    }

private:
    /// \brief Returns the payload array offset aligned to the machine page size for a checked capacity
    static size_t get_payloads_offset(size_t num_entries) noexcept {
        const auto metadata_length = sizeof(initialized_tag) + sizeof(lru) + (num_entries * sizeof(entry_metadata));
        constexpr auto page_mask = static_cast<size_t>(m_page_size - 1);
        return (metadata_length + page_mask) & ~page_mask;
    }

    /// \brief Checks that a link points to the LRU sentinel or an active entry node
    /// \param link Link from a known LRU node
    /// \returns Checked link
    lru::node_ptr check_lru_link(const lru::node_ptr &link) const {
        const auto sentinel = m_lru.end().pointed_node();
        if (link == sentinel) {
            return link;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto node_address = reinterpret_cast<uintptr_t>(link.get());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto nodes_begin = reinterpret_cast<uintptr_t>(lru::value_traits::to_node_ptr(m_entries.front()).get());
        if (node_address < nodes_begin || (node_address - nodes_begin) % sizeof(entry_metadata) != 0 ||
            (node_address - nodes_begin) / sizeof(entry_metadata) >= m_lru.size()) {
            throw std::runtime_error{"corrupted page hash-tree cache: invalid LRU link"};
        }
        return link;
    }

    /// \brief Checks persisted entry metadata and LRU links before accessing the cache
    void check_metadata() const {
        if (m_lru.size() > m_entries.size()) {
            throw std::runtime_error{"corrupted page hash-tree cache: LRU size exceeds capacity"};
        }
        // Distinct payloads are required because borrowed entries can be hashed in parallel.
        std::vector<bool> used_payloads(m_payloads.size());
        for (size_t i = 0; i < m_entries.size(); ++i) {
            const auto &e = m_entries[i];
            if (e.m_payload_index >= m_payloads.size() || used_payloads[e.m_payload_index]) {
                throw std::runtime_error{"corrupted page hash-tree cache: invalid payload index"};
            }
            used_payloads[e.m_payload_index] = true;
            if (e.get_borrowed()) {
                throw std::runtime_error{"corrupted page hash-tree cache: borrowed entry"};
            }
            if (i >= m_lru.size()) {
                const auto node = lru::value_traits::to_node_ptr(m_entries[i]);
                if (lru::node_traits::get_next(node) || lru::node_traits::get_previous(node)) {
                    throw std::runtime_error{"corrupted page hash-tree cache: linked unused entry"};
                }
            }
        }
        const auto sentinel = m_lru.end().pointed_node();
        auto previous = sentinel;
        auto current = check_lru_link(lru::node_traits::get_next(sentinel));
        for (uint64_t i = 0; i < m_lru.size(); ++i) {
            if (current == sentinel || check_lru_link(lru::node_traits::get_previous(current)) != previous) {
                throw std::runtime_error{"corrupted page hash-tree cache: inconsistent LRU links"};
            }
            previous = current;
            current = check_lru_link(lru::node_traits::get_next(current));
        }
        if (current != sentinel || check_lru_link(lru::node_traits::get_previous(sentinel)) != previous) {
            throw std::runtime_error{"corrupted page hash-tree cache: inconsistent LRU size or tail"};
        }
    }

    void dump_lru() const {
        std::cerr << "lru: " << std::hex;
        for (const auto &p : m_lru) {
            std::cerr << "0x" << p.get_paddr_page() << " ";
        }
        std::cerr << "\n";
    }

    template <RangeOfByteLike D>
    // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
    void dump_hex(D &&bytes, std::ostream &out, size_t limit = -1) {
        out << std::hex << std::setw(2) << std::setfill('0') << std::uppercase;
        for (auto b :
            bytes | views::cast_to<unsigned int> | std::views::take(std::min(limit, std::ranges::size(bytes)))) {
            out << b;
        }
    }

    void dump_map() const {
        std::cerr << "map: " << std::hex;
        for (const auto &[key, val] : m_map) {
            std::cerr << "0x" << key << " ";
        }
        std::cerr << "\n";
    }

    os::mapped_memory m_mapped_memory; ///< Mapped memory containing the header, entries, and payloads

    // The following fields may already be initialized by existing mapped memory
    initialized_tag &m_initialized;      ///< Whether cache has been initialized
    lru &m_lru;                          ///< Recently used entries
    std::span<entry_metadata> m_entries; ///< Compact metadata, with active entries in a prefix
    std::span<entry_payload> m_payloads; ///< Cached pages and hashes

    // The following fields are always initialized from scratch
    ankerl::unordered_dense::map<address_type, entry_metadata::ref>
        m_map;                          ///< Map from page addresses to corresponding entries
    page_hash_tree_cache_stats m_stats; ///< Statistics

    // ??(edubart): we could compute this on demand (on first use)
    const page_hash_tree m_pristine_page_hash_tree; ///< Pristine page hash tree for hasher in use
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_HPP
