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

#ifndef HASH_TREE_CONSTANTS_H
#define HASH_TREE_CONSTANTS_H

#include <cstdint>

namespace cartesi {

const constexpr int HASH_TREE_LOG2_ROOT_SIZE = 64;
const constexpr int HASH_TREE_LOG2_WORD_SIZE = 5;
const constexpr uint64_t HASH_TREE_WORD_SIZE = UINT64_C(1) << HASH_TREE_LOG2_WORD_SIZE;
const constexpr int HASH_TREE_LOG2_PAGE_SIZE = 12;
const constexpr uint64_t HASH_TREE_PAGE_SIZE = UINT64_C(1) << HASH_TREE_LOG2_PAGE_SIZE;

} // namespace cartesi

#endif
