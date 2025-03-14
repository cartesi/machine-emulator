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

#include <optional>
#include <unordered_map>
#include <span>

#include "address-range-constants.h"
#include "borrowed-reference.h"
#include "circular-buffer.h"
#include "hash-tree-constants.h"
#include "i-hasher.h"
#include "machine-hash.h"
#include "meta.h"
#include "strict-aliasing.h"

namespace cartesi {

class page_hash_tree_cache {

    static constexpr int m_word_size = HASH_TREE_WORD_SIZE;
    static constexpr int m_page_size = HASH_TREE_PAGE_SIZE;
    static constexpr int m_page_word_count = m_page_size/m_word_size;
    static constexpr int m_page_hash_tree_size = 2*m_page_word_count;

public:

    static_assert(POD<machine_hash>, "machine_hash must be trivially copyable and standard layout");

    using page_hash_tree = std::array<machine_hash, m_page_hash_tree_size>;

    static_assert(POD<page_hash_tree>, "hash_tree must be trivially copyable and standard layout");

    using page = std::array<unsigned char, m_page_size>;

    static_assert(POD<page>, "hash_tree must be trivially copyable and standard layout");

    using page_view = std::span<unsigned char, m_page_size>;
    using const_page_view = std::span<const unsigned char, m_page_size>;

    class entry {

        page m_page{};
        page_hash_tree m_hash_tree{};

        static constexpr uint64_t m_paddr_page_offset = 0;
        static constexpr uint64_t m_locked_flag_offset = sizeof(uint64_t);

        friend page_hash_tree_cache;

    public:
        auto &get_page() {
            return m_page;
        }

        const auto &get_page() const {
            return m_page;
        }

        auto &get_hash_tree() {
            return m_hash_tree;
        }

        const auto &get_hash_tree() const {
            return m_hash_tree;
        }

    private:

        uint64_t get_paddr_page() const {
            return aliased_aligned_read<uint64_t>(&m_hash_tree[0][m_paddr_page_offset]);
        }

        void set_paddr_page(uint64_t paddr_page) {
            return aliased_aligned_write<uint64_t>(&m_hash_tree[0][m_paddr_page_offset], paddr_page);
        }

        bool is_locked() const {
            return m_hash_tree[0][m_locked_flag_offset] != 0;
        }

        void lock() {
            m_hash_tree[0][m_locked_flag_offset] = 1;
        }
    };

    static_assert(POD<entry>, "entry must be trivially copyable and standard layout");

    page_hash_tree_cache(size_t num_entries) : m_storage{num_entries}, m_fifo{num_entries}, m_used{0} {}

    std::optional<borrowed_reference<entry>> borrow_entry(uint64_t paddr_page) {
        // Found entry for paddr in cache?
        if (auto it = m_cache.find(paddr_page); it != m_cache.end()) {
            // Move it out of cache and return it
            auto e = std::move(it->second);
            m_cache.erase(it);
            return e;
        }
        // Not in cache, but we still have unused slots
        if (m_used < m_storage.size()) {
            return make_borrowed_reference(m_storage[m_used++]);
        }
        // Otherwise, try to evict an entry
        if (!m_fifo.empty()) {
            auto old_paddr_page = m_fifo.front();
            auto it = m_cache.find(old_paddr_page);
            if (it == m_cache.end()) {
                throw std::logic_error{"page hash-tree cache is corrupted"};
            }
            m_fifo.pop_front();
            // Move it out of cache and return it
            auto e = std::move(it->second);
            m_cache.erase(it);
            return e;
        }
        // All pages that could be borrowed have already been borrowed
        return {};
    }

    void return_entry(borrowed_reference<entry> &&e) {
        // Return entry to the cache
        const auto paddr_page = e.get().get_paddr_page();
        m_cache.emplace(paddr_page, std::move(e));
        // Move to back of fifo, if page is not locked
        const auto is_locked = e.get().is_locked();
        if (!is_locked) {
            if (m_fifo.full()) {
                throw std::logic_error{"too many pages returned to page hash-tree cache"};
            }
            m_fifo.push_back(paddr_page);
        }
    }

    template <IHasher H>
    void update_entry(H &h, const borrowed_reference<entry> &e, const_page_view page) {
        circular_buffer<int, m_page_word_count/2> dirty_nodes;
        page_view entry_page = e.get().get_page();
        auto &entry_hash_tree = e.get().get_hash_tree();
        //??D Still have to optimize for case in which entire page is pristine...
        // Go over all words in the entry page, comparing with updated page, updating the hashes for the modified words
        for (int offset = 0, index = m_page_word_count; offset < m_page_size; offset += m_word_size, ++index) {
            const auto entry_page_word = entry_page.subspan(offset, m_word_size);
            const auto page_word = page.subspan(offset, m_word_size);
            if (memcmp(entry_page_word.data(), page_word.data(), m_word_size) != 0) {
                get_hash(h, page_word, entry_hash_tree[index]);
                //??D Maybe a single memcpy at the end is faster?
                memcpy(entry_page_word.data(), page_word.data(), m_word_size);
                dirty_nodes.try_push_back(index/2);
            }
        }
        // Now go over entry entry in fifo, updating the node hash from both child hashes
        while (!dirty_nodes.empty()) {
            auto index = dirty_nodes.front();
            dirty_nodes.pop_back();
            get_concat_hash(h, entry_hash_tree[2*index], entry_hash_tree[2*index+1], entry_hash_tree[index]);
            dirty_nodes.try_push_back(index/2);
        }
    }

private:
    std::vector<entry> m_storage;
    circular_buffer<uint64_t> m_fifo;
    size_t m_used;
    std::unordered_map<uint64_t, borrowed_reference<entry>> m_cache;
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_H
