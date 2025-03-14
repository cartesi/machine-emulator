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

#include <atomic>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <span>
#include <unordered_map>

#include <boost/intrusive/list.hpp>

#include "address-range-constants.h"
#include "circular-buffer.h"
#include "hash-tree-constants.h"
#include "i-hasher.h"
#include "is-pristine.h"
#include "machine-hash.h"
#include "meta.h"
#include "ranges.h"
#include "strict-aliasing.h"

namespace cartesi {

class page_hash_tree_cache {

    static constexpr int m_page_size = HASH_TREE_PAGE_SIZE;
    static constexpr int m_word_size = HASH_TREE_WORD_SIZE;
    static constexpr int m_page_word_count = m_page_size / m_word_size;
    static constexpr int m_page_hash_tree_size = 2 * m_page_word_count;

    using address_type = uint64_t;

public:
    using page = std::array<unsigned char, m_page_size>;
    using page_view = std::span<unsigned char, m_page_size>;
    using const_page_view = std::span<const unsigned char, m_page_size>;

    using page_hash_tree = std::array<machine_hash, m_page_hash_tree_size>;
    static_assert(POD<page>, "hash_tree must be trivially copyable and standard layout");
    static_assert(POD<machine_hash>, "machine_hash must be trivially copyable and standard layout");
    static_assert(POD<page_hash_tree>, "page_hash_tree must be trivially copyable and standard layout");

    class entry : public boost::intrusive::list_base_hook<> {

        page m_page{};
        page_hash_tree m_hash_tree{};

        static constexpr uint64_t m_paddr_page_offset = 0;
        static constexpr uint64_t m_borrowed_offset = sizeof(uint64_t);

        friend page_hash_tree_cache;

        entry &set_paddr_page(uint64_t paddr_page) noexcept {
            aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_paddr_page_offset], paddr_page);
            return *this;
        }

        entry &set_borrowed(uint64_t borrowed) noexcept {
            aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_borrowed_offset], borrowed);
            return *this;
        }

        uint64_t get_borrowed() const noexcept {
            return aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_borrowed_offset]);
        }

        void clear_page() noexcept {
            std::ranges::fill(m_page, 0);
        }

        void clear_hash_tree(const page_hash_tree &pristine) noexcept {
            auto paddr_page = get_paddr_page();
            auto borrowed = get_borrowed();
            m_hash_tree = pristine;
            set_paddr_page(paddr_page);
            set_borrowed(borrowed);
        }

        void clear(const page_hash_tree &pristine) noexcept {
            clear_hash_tree(pristine);
            clear_page();
            set_borrowed(0);
            set_paddr_page(0);
        }

        static int left_child(int i) {
            return 2 * i;
        }

        static int right_child(int i) {
            return (2 * i) + 1;
        }

        static int parent(int i) {
            return i / 2;
        }

    public:
        explicit entry(const page_hash_tree &pristine) : m_hash_tree{pristine} {}

        entry(const entry &other) = default;
        entry(entry &&other) = default;
        entry &operator=(const entry &other) = default;
        entry &operator=(entry &&other) = default;
        ~entry() = default;

        uint64_t get_paddr_page() const noexcept {
            return aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_paddr_page_offset]);
        }

#ifdef DUMP_HASH_TREE_STATS
        static std::atomic<int> m_word_hit;
        static std::atomic<int> m_word_miss;
        static std::atomic<int> m_inner_page_node_hashes;
#endif

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

        const auto &get_page() const noexcept {
            return m_page;
        }

        const_machine_hash_view root_hash_view() const noexcept {
            return m_hash_tree[1];
        }

        const_machine_hash_view node_hash_view(uint64_t address, int log2_size) const noexcept {
            static constexpr machine_hash no_hash{};
            if (log2_size < HASH_TREE_LOG2_WORD_SIZE || log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
                assert(false && "log2_size is out of range");
                return no_hash;
            }
            auto start = UINT64_C(1) << (HASH_TREE_LOG2_PAGE_SIZE - log2_size);
            auto index = address >> log2_size;
            if (index > start || (index << log2_size) != address) {
                assert(false && "address is out of range");
                return no_hash;
            }
            return m_hash_tree[start + index];
        }

        template <IHasher H, ContiguousRangeOfByteLike D>
        // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
        bool update(H &&h, D &&d, const page_hash_tree &pristine) noexcept {
            if (std::ranges::size(d) != m_page_size) {
                return false;
            }
            if (is_pristine(d)) {
                clear_hash_tree(pristine);
                clear_page();
                return true;
            }
            const const_page_view page{std::ranges::data(d), std::ranges::size(d)};
            circular_buffer<int, m_page_word_count / 2> dirty_nodes;
            // Go over all words in the entry page, comparing with updated page,
            // and updating the hashes for the modified words
            //??D In C++23, we would use std::views::slide and std::views::zip to write this in declarative style.
            const page_view entry_page{m_page};
#ifdef DUMP_HASH_TREE_STATS
            int hit = 0;
            int miss = 0;
#endif
            for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
                const auto entry_word = entry_page.subspan(offset, m_word_size);
                const auto page_word = page.subspan(offset, m_word_size);
                if (!std::ranges::equal(entry_word, page_word)) {
                    get_hash(h, page_word, m_hash_tree[index]);
                    std::ranges::copy(page_word, entry_word.begin());
                    dirty_nodes.try_push_back(parent(index));
#ifdef DUMP_HASH_TREE_STATS
                    ++miss;
#endif
                } else {
#ifdef DUMP_HASH_TREE_STATS
                    ++hit;
#endif
                }
            }
#ifdef DUMP_HASH_TREE_STATS
            m_word_hit += hit;
            m_word_miss += miss;
#endif
            // Now go over fifo, taking a node, updating its from its children, and enqueueing its parent for update
#ifdef DUMP_HASH_TREE_STATS
            int inner_page_node_hashes = 0;
#endif
            while (!dirty_nodes.empty()) {
                const int index = dirty_nodes.front();
                dirty_nodes.pop_front();
#ifdef DUMP_HASH_TREE_STATS
                ++inner_page_node_hashes;
#endif
                get_concat_hash(h, m_hash_tree[left_child(index)], m_hash_tree[right_child(index)], m_hash_tree[index]);
                if (index != 1) {
                    dirty_nodes.try_push_back(parent(index));
                }
            }
#ifdef DUMP_HASH_TREE_STATS
            m_inner_page_node_hashes += inner_page_node_hashes;
#endif
            return true;
        }

        template <IHasher H>
        // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
        bool verify(H &&h) noexcept {
            std::cerr << "verifying entry\n";
            const page_view entry_page{m_page};
            for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
                const auto page_word = entry_page.subspan(offset, m_word_size);
                const auto page_word_hash = get_hash(h, page_word);
                if (page_word_hash != m_hash_tree[index]) {
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
                        get_concat_hash(h, m_hash_tree[left_child(index)], m_hash_tree[right_child(index)]);
                    if (node_hash != m_hash_tree[index]) {
                        std::cerr << "hash mismatch in index " << std::dec << index << ":" << log2_size << '\n';
                        return false;
                    }
                }
                start /= 2;
            }
            return true;
        }
    };

    // static_assert(POD<entry>, "entry must be trivially copyable and standard layout");

    template <IHasher H>
    page_hash_tree_cache(H &&h, size_t num_entries) :
        m_pristine_page_hash_tree{entry::get_pristine_page_hash_tree(std::forward<H>(h))},
        m_entries{num_entries, entry{m_pristine_page_hash_tree}} {
        m_map.reserve(num_entries);
    }

    page_hash_tree_cache(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache(page_hash_tree_cache &&other) = delete;
    page_hash_tree_cache &operator=(const page_hash_tree_cache &other) = delete;
    page_hash_tree_cache &operator=(page_hash_tree_cache &&other) = delete;

    const page_hash_tree &get_pristine_page_hash_tree() const {
        return m_pristine_page_hash_tree;
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

    std::optional<std::reference_wrapper<entry>> borrow_entry(uint64_t paddr_page, bool &hit) {
        // Found entry for page in map?
        if (auto it = m_map.find(paddr_page); it != m_map.end()) {
            entry &e = it->second.second;
            if (e.get_borrowed() != 0) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            // Make it most recently used
            m_lru.splice(m_lru.begin(), m_lru, it->second.first);
            hit = true;
#ifdef DUMP_HASH_TREE_STATS
            ++m_page_hit;
#endif
            // Return borrowed entry
            return std::ref(e.set_borrowed(1));
        }
        hit = false;
        // Not in map, but we still have unused entries to lend
        if (m_used < m_entries.size()) {
#ifdef DUMP_HASH_TREE_STATS
            ++m_page_miss;
#endif
            entry &e = m_entries[m_used++];
            if (e.get_borrowed() != 0) {
                throw std::runtime_error{"page hash-tree cache entry already borrowed"};
            }
            m_lru.push_front(e);
            m_map.emplace(paddr_page, map_value{m_lru.begin(), e});
            // Return borrowed
            return std::ref(e.set_borrowed(1).set_paddr_page(paddr_page));
        }
        // Evict least recently used
        auto &e = m_lru.back();
        // If even that has been borrowed, we are out of entries to lend
        if (e.get_borrowed() != 0) {
            return {};
        }
        m_map.erase(e.get_paddr_page());
        m_lru.pop_back();
        m_lru.push_front(e);
        m_map.emplace(paddr_page, map_value{m_lru.begin(), e});
        return std::ref(e.set_borrowed(1).set_paddr_page(paddr_page));
    }

    auto borrow_entry(uint64_t paddr_page) {
        bool hit = false;
        return borrow_entry(paddr_page, hit);
    }

    static bool return_entry(entry &e) {
        if (e.get_borrowed() == 0) {
            throw std::runtime_error{"returning page hash-tree cache entry that is not borrowed"};
        }
        e.set_borrowed(0);
        return true;
    }

    constexpr auto capacity() const noexcept {
        return m_entries.size();
    }

    void clear() noexcept {
        m_lru.clear();
        m_map.clear();
        for (auto &e : m_entries) {
            e.clear(m_pristine_page_hash_tree);
        }
        m_used = 0;
    }

    void clear_stats() noexcept {
#ifdef DUMP_HASH_TREE_STATS
        m_page_hit = 0;
        m_page_miss = 0;
        entry::m_inner_page_node_hashes = 0;
        entry::m_word_hit = 0;
        entry::m_word_miss = 0;
#endif
    }

    ~page_hash_tree_cache() {
#ifdef DUMP_HASH_TREE_STATS
        auto all = m_page_hit + m_page_miss;
        if (all > 0) {
            std::cerr << "page hits: " << m_page_hit << '\n';
            std::cerr << "page misses: " << m_page_miss << '\n';
            std::cerr << "page hit rate: " << 100.0 * static_cast<double>(m_page_hit) / static_cast<double>(all)
                      << '\n';
        }
        auto word_hit = entry::m_word_hit.load();
        auto word_miss = entry::m_word_miss.load();
        auto word_all = word_hit + word_miss;
        if (word_all > 0) {
            std::cerr << "word hits: " << word_hit << '\n';
            std::cerr << "word misses: " << word_miss << '\n';
            std::cerr << "word hit rate: " << 100.0 * static_cast<double>(word_hit) / static_cast<double>(word_all)
                      << '\n';
        }
        std::cerr << "inner page node hashes: " << entry::m_inner_page_node_hashes.load() << '\n';
#endif
    }

private:
    using lru = boost::intrusive::list<entry>;
    using map_value = std::pair<lru::iterator, entry &>;
    const page_hash_tree m_pristine_page_hash_tree;
    //??D Replace std::vector so entries can live on disk
    std::vector<entry> m_entries;
    //??D Replace the boost intrusive list with index-based implementation so list can live on disk as well
    lru m_lru;
    //??D Only the map will be reloaded from disk
    //??D We *could* also replace the implementation, but I think this would be overkill
    std::unordered_map<address_type, map_value> m_map;
    size_t m_used{0};
#ifdef DUMP_HASH_TREE_STATS
    size_t m_page_hit;
    size_t m_page_miss;
#endif
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_H
