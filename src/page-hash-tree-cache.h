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

#ifndef PAGE_HASH_TREE_CACHE_H
#define PAGE_HASH_TREE_CACHE_H

/// \file
/// \brief Page hash-tree cache interface

#include <bit>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <span>
#include <unordered_map>

#include <boost/container/static_vector.hpp>
#include <boost/intrusive/list.hpp>

#include "address-range-constants.h"
#include "circular-buffer.h"
#include "compiler-defines.h"
#include "hash-tree-constants.h"
#include "i-hasher.h"
#include "is-pristine.h"
#include "machine-hash.h"
#include "meta.h"
#include "page-hash-tree-cache-stats.h"
#include "ranges.h"
#include "signposts.h"
#include "simd-hasher.h"
#include "strict-aliasing.h"

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

    /// \class entry
    /// \brief Page hash-tree cache entry implementation
    class entry : public boost::intrusive::list_base_hook<> {

        page m_page{};                ///< Page data for entry
        page_hash_tree m_hash_tree{}; ///< Hash-tree of data

        // First hash is not used, so we use its storage for some fields
        static constexpr uint64_t m_paddr_page_offset = 0;              ///< Offset where paddr_page is stored
        static constexpr uint64_t m_borrowed_offset = sizeof(uint64_t); ///< Offset where borrowee flag is stored

        friend page_hash_tree_cache;

        /// \brief Sets page address for entry
        /// \param paddr_page Target physical address of page
        /// \returns Reference to entry (for composition of operations)
        entry &set_paddr_page(address_type paddr_page) noexcept {
            aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_paddr_page_offset], static_cast<uint64_t>(paddr_page));
            return *this;
        }

        /// \brief Sets borrowed flag for entry
        /// \param borrowed True if entry was borrowed
        /// \returns Reference to entry (for composition of operations)
        entry &set_borrowed(bool borrowed) noexcept {
            aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_borrowed_offset], static_cast<uint64_t>(borrowed));
            return *this;
        }

        /// \brief Gets borrowed flag for entry
        /// \returns Reference true if entry is borrowed
        bool get_borrowed() const noexcept {
            return static_cast<bool>(aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_borrowed_offset]));
        }

        /// \brief Make entry's page pristine
        void clear_page() noexcept {
            std::ranges::fill(m_page, 0);
        }

        /// \brief Make entry's hash tree pristine
        /// \param pristine Pristine hash tree
        void clear_hash_tree(const page_hash_tree &pristine) noexcept {
            auto paddr_page = get_paddr_page();
            auto borrowed = get_borrowed();
            m_hash_tree = pristine;
            set_paddr_page(paddr_page);
            set_borrowed(borrowed);
        }

        /// \brief Make entry's page and hash tree pristine, clear page address and borrowed flag
        /// \param pristine Pristine hash tree
        void clear(const page_hash_tree &pristine) noexcept {
            clear_hash_tree(pristine);
            clear_page();
            set_borrowed(false);
            set_paddr_page(0);
        }

        /// \brief Returns index of left child of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's left child
        static int left_child(int i) {
            return 2 * i;
        }

        /// \brief Returns index of right child of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's right child
        static int right_child(int i) {
            return (2 * i) + 1;
        }

        /// \brief Returns index of parent of node in page hash tree
        /// \param i Node index
        /// \returns Index of node's parent
        static int parent(int i) {
            return i / 2;
        }

        /// \brief Returns the log2 level of a node in the page hash tree (its height in the tree)
        /// \param i Node index
        /// \returns Log 2 level of the node
        static int log2_level(int i) {
            return std::countl_zero(static_cast<uint32_t>(i)) - 24;
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

        /// \brief Returns entry's page
        /// \returns Reference to entry's page
        const auto &get_page() const noexcept {
            return m_page;
        }

        /// \brief Returns entry's page
        /// \returns Reference to entry's page
        auto &get_page() noexcept {
            return m_page;
        }

        /// \brief Returns entry's page hash tree
        /// \returns Reference to entry's page hash tree
        const auto &get_page_hash_tree() const noexcept {
            return m_hash_tree;
        }

        /// \brief Returns entry's page hash tree
        /// \returns Reference to entry's page hash tree
        auto &get_page_hash_tree() noexcept {
            return m_hash_tree;
        }

    public:
        /// \brief Constructor from pristine page
        /// \param pristine Pristine page hash tree for hasher in use
        explicit entry(const page_hash_tree &pristine) : m_hash_tree{pristine} {}

        entry(const entry &other) = default;
        entry(entry &&other) = default;
        entry &operator=(const entry &other) = default;
        entry &operator=(entry &&other) = default;
        ~entry() = default;

        /// \brief Returns page address for entry
        /// \returns Target physical address of page
        address_type get_paddr_page() const noexcept {
            return static_cast<address_type>(aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_paddr_page_offset]));
        }

        /// \brief Returns view to root hash from entry's page hash tree
        /// \returns View to root hash
        const_machine_hash_view root_hash_view() const noexcept {
            return m_hash_tree[1];
        }

        /// \brief Returns view to node hash from entry's page hash tree
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

    template <IHasher hasher_type>
    class simd_hasher {
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
            ((UINT64_C(1) << ((HASH_TREE_LOG2_PAGE_SIZE - HASH_TREE_LOG2_WORD_SIZE) - 1))) *
            hasher_type::MAX_LANE_COUNT;

        hasher_type m_hasher;
        simd_data_hasher<hasher_type, const_hash_tree_word_view> m_leaves_queue;
        simd_concat_hasher<hasher_type, const_machine_hash_view> m_concat_queue;
        circular_buffer<dirty_entry, QUEUE_MAX_SIZE> m_dirty_queue;

    public:
        static constexpr int QUEUE_MAX_PAGE_COUNT = hasher_type::MAX_LANE_COUNT;

        /// \brief Enqueues a leaf for hashing
        void enqueue_leaf(const_hash_tree_word_view data, page_hash_tree_view page_tree, int word_index) noexcept {
            m_leaves_queue.enqueue(data, page_tree[word_index]);
            m_dirty_queue.try_push_back(dirty_entry{.page_tree = page_tree, .node_index = entry::parent(word_index)});
        }

        /// \brief Flushes the entire queue
        int flush() noexcept {
            m_leaves_queue.flush();
            int hashes = 0;

            while (!m_dirty_queue.empty()) {
                for (size_t i = 0, n = m_dirty_queue.size(); i < n; ++i) {
                    const auto &d = m_dirty_queue.front();
                    const auto node_index = d.node_index;
                    const auto page_tree = d.page_tree;
                    m_dirty_queue.pop_front();
                    ++hashes;
                    m_concat_queue.enqueue(page_tree[entry::left_child(node_index)],
                        page_tree[entry::right_child(node_index)], page_tree[node_index]);
                    if (node_index > 1) [[likely]] {
                        m_dirty_queue.try_push_back(
                            dirty_entry{.page_tree = page_tree, .node_index = entry::parent(node_index)});
                    }
                }
                m_concat_queue.flush();
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
    bool enqueue_hash_entry(page_hash_tree_cache::simd_hasher<H> &queue, D &&d, entry &e,
        page_hash_tree_cache_stats &stats) noexcept {
        if (std::ranges::size(d) != m_page_size) {
            return false;
        }
        {
            SCOPED_SIGNPOST(m_log, m_spid_pristine_check_and_update, "phtc: pristine check and update", "");
            if (is_pristine(d)) {
                SCOPED_SIGNPOST(m_log, m_spid_pristine_update, "phtc: pristine update", "");
                e.clear_hash_tree(m_pristine_page_hash_tree);
                e.clear_page();
                ++stats.pristine_pages;
                return true;
            }
        }
        SCOPED_SIGNPOST(m_log, m_spid_non_pristine_update, "phtc: non-pristine update", "");
        const const_page_view page{std::ranges::data(d), std::ranges::size(d)};
        // Go over all words in the entry page, comparing with updated page,
        // and updating the hashes for the modified words
        //??D In C++23, we would use std::views::slide and std::views::zip to write this in declarative style.
        const page_view entry_page{e.get_page()};
        int hit = 0;
        int miss = 0;
        auto &page_tree = e.get_page_hash_tree();
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
    bool verify_entry(H &&h, entry &e) noexcept {
        std::cerr << "verifying entry\n";
        const page_view entry_page{e.get_page()};
        auto &page_tree = e.get_page_hash_tree();
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
                const auto node_hash =
                    get_concat_hash(h, page_tree[e.left_child(index)], page_tree[e.right_child(index)]);
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
#ifndef HAS_SIGNPOSTS
    page_hash_tree_cache(H &&h, size_t num_entries) :
#else
    page_hash_tree_cache(os_log_t log, H &&h, size_t num_entries) :
        m_log{log},
        m_spid_borrow{os_signpost_id_generate(m_log)},
        m_spid_pristine_check_and_update{os_signpost_id_generate(m_log)},
        m_spid_pristine_update{os_signpost_id_generate(m_log)},
        m_spid_non_pristine_update{os_signpost_id_generate(m_log)},
#endif
        m_pristine_page_hash_tree{entry::get_pristine_page_hash_tree(std::forward<H>(h))},
        m_entries{num_entries, entry{m_pristine_page_hash_tree}} {
        m_map.reserve(num_entries);
    }

    page_hash_tree_cache(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache(page_hash_tree_cache &&other) = delete;
    page_hash_tree_cache &operator=(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache &operator=(page_hash_tree_cache &&other) = delete;

    /// \brief Tries to borrow a cache entry
    /// \param paddr_page Target physical address of page to borrow
    /// \param hit Receives true if page was found in cache, false if another page was evicted and its entry returned
    /// \returns Entry for page, nothing if all pages have already been borrowed
    std::optional<std::reference_wrapper<entry>> borrow_entry(address_type paddr_page, bool &hit) {
        SCOPED_SIGNPOST(m_log, m_spid_borrow, "phtc: borrow", "");
        // Found entry for page in map?
        if (auto it = m_map.find(paddr_page); it != m_map.end()) {
            entry &e = it->second.second;
            if (e.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            // Make it most recently used
            m_lru.splice(m_lru.begin(), m_lru, it->second.first);
            hit = true;
            ++m_stats.page_hits;
            // Return borrowed entry
            return std::ref(e.set_borrowed(true));
        }
        hit = false;
        // Not in map, but we still have unused entries to lend
        if (m_used < m_entries.size()) {
            ++m_stats.page_misses;
            entry &e = m_entries[m_used++];
            if (e.get_borrowed()) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            m_lru.push_front(e);
            m_map.emplace(paddr_page, map_value{m_lru.begin(), e});
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
        m_map.emplace(paddr_page, map_value{m_lru.begin(), e});
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
    static bool return_entry(entry &e) {
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

    /// \brief Clear entire cache
    void clear() noexcept {
        m_lru.clear();
        m_map.clear();
        for (auto &e : m_entries) {
            e.clear(m_pristine_page_hash_tree);
        }
        m_used = 0;
    }

    /// \brief Returns current statistics
    /// \param clear Whether to clear statistics after retrieving them
    /// \returns Statistics
    page_hash_tree_cache_stats get_stats(bool clear = false) noexcept {
        auto s = m_stats;
        if (clear) {
            m_stats.page_hits = 0;
            m_stats.page_misses = 0;
            m_stats.word_hits = 0;
            m_stats.word_misses = 0;
            m_stats.page_changes = 0;
            m_stats.inner_page_hashes = 0;
            m_stats.pristine_pages = 0;
            m_stats.non_pristine_pages = 0;
        }
        return s;
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

#ifdef HAS_SIGNPOSTS
    os_log_t m_log;
    os_signpost_id_t m_spid_borrow;
    os_signpost_id_t m_spid_pristine_check_and_update;
    os_signpost_id_t m_spid_pristine_update;
    os_signpost_id_t m_spid_non_pristine_update;
#endif

    using lru = boost::intrusive::list<entry>;           ///< Least-recently-used container type
    using map_value = std::pair<lru::iterator, entry &>; ///< Value type for map
    const page_hash_tree m_pristine_page_hash_tree;      ///< Pristine page hash tree for hasher in use
    //??D Replace std::vector so entries can live on disk
    std::vector<entry> m_entries; ///< Array of page hash-tree cache entries
    //??D Replace the boost intrusive list with index-based implementation so list can live on disk as well
    lru m_lru; ///< Least-recently-used list of entries
    //??D Only the map will be reloaded from disk
    //??D We *could* also replace the implementation, but I think this would be overkill
    std::unordered_map<address_type, map_value> m_map; ///< Map from page addresses to corresponding entries
    size_t m_used{0};                                  ///< How many entries have already been used

    // Statistics
    page_hash_tree_cache_stats m_stats;
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_H
