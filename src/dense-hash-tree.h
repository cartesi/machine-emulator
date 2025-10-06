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

#ifndef DENSE_HASH_TREE_H
#define DENSE_HASH_TREE_H

#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>

#include "address-range-constants.h"
#include "hash-tree-constants.h"
#include "i-dense-hash-tree.h"
#include "machine-hash.h"
#include "os-mapped-memory.h"

namespace cartesi {

class dense_hash_tree final : public i_dense_hash_tree {

    using container_type = std::span<machine_hash>;
    using size_type = container_type::size_type;

    static constexpr auto invalid_index = std::numeric_limits<size_type>::max();

    static int check_level_count(int level_count, size_type leaf_count) {
        if (level_count < 0) {
            throw std::invalid_argument{"level count must be non-negative"};
        }
        if (level_count > 0 && leaf_count > (size_type{1} << (level_count - 1))) {
            throw std::invalid_argument{"too many leaves for level count"};
        }
        if (level_count == 0 && leaf_count != 0) {
            throw std::invalid_argument{"too many leaves for level count"};
        }
        // Make sure we can allocate a vector of size 1 << level_count
        if ((std::numeric_limits<container_type::size_type>::max() >> level_count) == 0) {
            throw std::invalid_argument{"too many levels"};
        }
        return level_count;
    }

    static constexpr int m_log2_page_size = HASH_TREE_LOG2_PAGE_SIZE;
    static constexpr int m_log2_word_size = HASH_TREE_LOG2_WORD_SIZE;

public:
    dense_hash_tree(int level_count, size_type leaf_count, const std::string &backing_filename, bool shared) :
        m_level_count{check_level_count(level_count, leaf_count)},
        m_mapped_memory{get_storage_length(level_count, leaf_count), os::mapped_memory_flags{.shared = shared},
            backing_filename},
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_tree{reinterpret_cast<machine_hash *>(m_mapped_memory.get_ptr()), size_type{1} << level_count} {}

    dense_hash_tree(const dense_hash_tree &) = delete;
    dense_hash_tree &operator=(const dense_hash_tree &) = delete;
    dense_hash_tree(dense_hash_tree &&) = delete;
    dense_hash_tree &operator=(dense_hash_tree &&) = delete;

    ~dense_hash_tree() override = default;

    static uint64_t get_storage_length(int level_count, size_type leaf_count) {
        return (UINT64_C(1) << check_level_count(level_count, leaf_count)) * sizeof(machine_hash);
    }

private:
    machine_hash_view do_node_hash_view(uint64_t offset, int log2_size) noexcept override {
        if (auto index = to_index(offset, log2_size); index != invalid_index) {
            return machine_hash_view{m_tree[index]};
        }
        return no_hash_view();
    }

    const_machine_hash_view do_node_hash_view(uint64_t offset, int log2_size) const noexcept override {
        if (auto index = to_index(offset, log2_size); index != invalid_index) {
            return const_machine_hash_view{m_tree[index]};
        }
        return no_hash_view();
    }

    const_machine_hash_view do_root_hash_view() const noexcept override {
        if (m_level_count != 0) {
            return m_tree[1];
        }
        return no_hash_view();
    }

    std::span<const unsigned char> do_get_storage_data() const noexcept override {
        return m_mapped_memory.get_storage_data();
    }

    /// \brief Converts a node size to its level in the tree
    /// \param log2_size Log<sub>2</sub> of node size
    /// \returns Corresponding level (which may be out of range)
    static int to_level(int log2_size) noexcept {
        return log2_size - static_cast<int>(AR_LOG2_PAGE_SIZE);
    }

    size_type to_index(uint64_t offset, int log2_size) const {
        const int level = to_level(log2_size);
        if (level < 0 || level >= m_level_count) {
            return invalid_index;
        }
        const size_type start = size_type{1} << (m_level_count - level - 1);
        const size_type index = offset >> log2_size;
        if (index >= start) {
            return invalid_index;
        }
        return start + index;
    }

    int m_level_count;                 ///< Number of levels in tree
    os::mapped_memory m_mapped_memory; ///< Mapped memory for tree storage
    container_type m_tree;             ///< Complete tree of hashes
};

} // namespace cartesi

#endif // PAGE_HASH_TREE_CACHE_H
