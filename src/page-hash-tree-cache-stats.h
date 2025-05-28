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

#ifndef PAGE_HASH_TREE_CACHE_STATS_H
#define PAGE_HASH_TREE_CACHE_STATS_H

#include <cstdint>

namespace cartesi {

struct page_hash_tree_cache_stats {
    uint64_t page_hits;          ///\< Number of pages looked up and found in cache
    uint64_t page_misses;        ///\< Number of pages looked up but missing from cache
    uint64_t word_hits;          ///\< Number of words equal to corresponding word in cache entry
    uint64_t word_misses;        ///\< Number of words differing from corresponding word in cache entry
    uint64_t inner_page_hashes;  ///\< Number of inner page hashing operations performed
    uint64_t pristine_pages;     ///\< Number of pages found to be pristine during updates
    uint64_t non_pristine_pages; ///\< Number of pages found not to be pristine during updates
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_STATS_H
