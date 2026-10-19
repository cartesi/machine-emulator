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

#ifndef STEP_LOG_SLICE_HPP
#define STEP_LOG_SLICE_HPP

#include <cstdint>
#include <utility>

#include "hash-tree-constants.hpp"
#include "uint128.hpp"

namespace cartesi {

/// Select the one aligned subtree containing all touched leaves, stopping at the floor.
/// A zero bitmap conservatively retains the page (e.g. a replay address-mapping dependency).
inline std::pair<uint64_t, int> select_page_slice(uint128_t touched, int log2_floor) {
    uint64_t offset = 0;
    int log2_size = HASH_TREE_LOG2_PAGE_SIZE;
    while (log2_size > log2_floor) {
        const auto half_leaves = UINT64_C(1) << (log2_size - HASH_TREE_LOG2_WORD_SIZE - 1);
        const auto left = touched & ((static_cast<uint128_t>(1) << half_leaves) - 1);
        const auto right = touched >> half_leaves;
        if ((left == 0) == (right == 0)) {
            break;
        }
        --log2_size;
        if (left == 0) {
            offset += UINT64_C(1) << log2_size;
            touched = right;
        } else {
            touched = left;
        }
    }
    return {offset, log2_size};
}

} // namespace cartesi
#endif
