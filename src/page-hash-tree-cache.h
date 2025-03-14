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

#include <iostream>
#include <optional>
#include <span>
#include <unordered_map>

#include "address-range-constants.h"
#include "borrowed-reference.h"
#include "circular-buffer.h"
#include "hash-tree-constants.h"
#include "i-hasher.h"
#include "is-pristine.h"
#include "machine-hash.h"
#include "meta.h"
#include "strict-aliasing.h"

namespace cartesi {

class page_hash_tree_cache {

    static constexpr int m_page_size = HASH_TREE_PAGE_SIZE;
    static constexpr int m_word_size = HASH_TREE_WORD_SIZE;
    static constexpr int m_page_word_count = m_page_size / m_word_size;
    static constexpr int m_page_hash_tree_size = 2 * m_page_word_count;

public:
    using page = std::array<unsigned char, m_page_size>;
    using page_view = std::span<unsigned char, m_page_size>;
    using const_page_view = std::span<const unsigned char, m_page_size>;

    using page_hash_tree = std::array<machine_hash, m_page_hash_tree_size>;
    static_assert(POD<page>, "hash_tree must be trivially copyable and standard layout");
    static_assert(POD<machine_hash>, "machine_hash must be trivially copyable and standard layout");
    static_assert(POD<page_hash_tree>, "page_hash_tree must be trivially copyable and standard layout");

    class entry {

        page m_page{};
        page_hash_tree m_hash_tree{};

        static constexpr uint64_t m_paddr_page_offset = 0;
        static constexpr uint64_t m_locked_flag_offset = sizeof(uint64_t);

        friend page_hash_tree_cache;

        auto &get_page() {
            return m_page;
        }

        auto &get_hash_tree() {
            return m_hash_tree;
        }

        void set_paddr_page(uint64_t paddr_page) {
            return aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_paddr_page_offset], paddr_page);
        }

        void lock() {
            m_hash_tree[0][m_locked_flag_offset] = 1;
        }

    public:
        template <IHasher H>
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

        const auto &get_hash_tree() const noexcept {
            return m_hash_tree;
        }

        const auto &get_page() const noexcept {
            return m_page;
        }

        const machine_hash &get_root_hash() const noexcept {
            return m_hash_tree[1];
        }

        uint64_t get_paddr_page() const noexcept {
            return aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_paddr_page_offset]);
        }

        bool is_locked() const noexcept {
            return m_hash_tree[0][m_locked_flag_offset] != 0;
        }

        void make_pristine(const page_hash_tree &pristine) noexcept {
            auto paddr_page = get_paddr_page();
            auto locked = is_locked();
            m_hash_tree = pristine;
            set_paddr_page(paddr_page);
            if (locked) {
                lock();
            }
            std::ranges::fill(m_page, 0);
        }

        template <IHasher H, ContiguousRangeOfByteLike D>
        bool update(H &&h, D &&d, const page_hash_tree &pristine) noexcept {
            if (std::ranges::size(d) != m_page_size) {
                return false;
            }
            if (is_pristine(d)) {
                make_pristine(pristine);
                return true;
            }
            const_page_view page{reinterpret_cast<const unsigned char *>(std::ranges::data(d)), std::ranges::size(d)};
            circular_buffer<int, m_page_word_count / 2> dirty_nodes;
            // Go over all words in the entry page, comparing with updated page,
            // and updating the hashes for the modified words
            //??D In C++23, we would use std::views::slide and std::views::zip to write this in declarative style.
            page_view entry_page{m_page};
            for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
                const auto entry_word = entry_page.subspan(offset, m_word_size);
                const auto page_word = page.subspan(offset, m_word_size);
                if (!std::ranges::equal(entry_word, page_word)) {
                    get_hash(h, page_word, m_hash_tree[index]);
                    //??D Maybe a single copy at the end is faster on average?
                    std::ranges::copy(page_word, entry_word.begin());
                    dirty_nodes.try_push_back(index / 2);
                }
            }
            // Now go over fifo, taking a node, updating its from its children, and enqueueing its parent for update
            while (!dirty_nodes.empty()) {
                auto index = dirty_nodes.front();
                dirty_nodes.pop_front();
                get_concat_hash(h, m_hash_tree[2 * index], m_hash_tree[2 * index + 1], m_hash_tree[index]);
                if (index != 1) {
                    dirty_nodes.try_push_back(index / 2);
                }
            }
            return true;
        }
    };

    static_assert(POD<entry>, "entry must be trivially copyable and standard layout");

    page_hash_tree_cache(size_t num_entries) : m_storage{num_entries}, m_fifo{num_entries}, m_used{0} {}

    using borrowed_entry = borrowed_reference<entry>;

    static borrowed_entry set_paddr_page(borrowed_entry &&e, uint64_t paddr_page) {
        e.get().set_paddr_page(paddr_page);
        return std::move(e);
    }

    std::optional<borrowed_entry> borrow_entry(uint64_t paddr_page) noexcept {
        // Found entry for paddr in cache?
        if (auto it = m_cache.find(paddr_page); it != m_cache.end()) {
            // Move it out of cache and return it
            auto e = std::move(it->second);
            m_cache.erase(it);
            return std::move(e);
        }
        // Not in cache, but we still have unused slots
        if (m_used < m_storage.size()) {
            return set_paddr_page(make_borrowed_reference(m_storage[m_used++]), paddr_page);
        }
        // Otherwise, try to evict an entry
        if (!m_fifo.empty()) {
            auto old_paddr_page = m_fifo.front();
            auto it = m_cache.find(old_paddr_page);
            // Should not happen unless page hash-tree cache is corrupted
            if (it == m_cache.end()) {
                return {};
            }
            m_fifo.pop_front();
            // Move it out of cache and return it
            auto e = std::move(it->second);
            m_cache.erase(it);
            return set_paddr_page(std::move(e), paddr_page);
        }
        // All pages that could be borrowed have already been borrowed
        return {};
    }

    bool return_entry(borrowed_reference<entry> &&e) noexcept {
        // Return entry to the cache
        const auto paddr_page = e.get().get_paddr_page();
        const auto is_locked = e.get().is_locked();
        m_cache.emplace(paddr_page, std::move(e));
        // Move to back of fifo, if page is not locked
        if (!is_locked) {
            // Should not happen unless page hash-tree cache is corrupted
            if (m_fifo.full()) {
                return false;
            }
            m_fifo.push_back(paddr_page);
        }
        return true;
    }

    constexpr auto capacity() const noexcept {
        return m_fifo.capacity();
    }

    void clear() noexcept {
        m_fifo.clear();
        m_cache.clear();
        m_used = 0;
    }

private:
    std::vector<entry> m_storage;
    circular_buffer<uint64_t> m_fifo;
    size_t m_used;
    std::unordered_map<uint64_t, borrowed_reference<entry>> m_cache;
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_H
