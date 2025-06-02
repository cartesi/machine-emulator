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

#ifndef HASH_TREE_STATS_H
#define HASH_TREE_STATS_H

#include "hash-tree-constants.h"
#include "page-hash-tree-cache-stats.h"

#include <array>
#include <cstdint>

namespace cartesi {

struct hash_tree_stats {
    page_hash_tree_cache_stats phtc;
    uint64_t sparse_node_hashes{0};
    std::array<uint64_t, HASH_TREE_LOG2_ROOT_SIZE> dense_node_hashes{};
};

} // namespace cartesi

#endif // HASH_TREE_STATS_H
