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

#ifndef I_DIRTY_PAGE_TREE_H
#define I_DIRTY_PAGE_TREE_H

/// \file
/// \brief Dirty map as a complete tree

#include <cstdint>
#include <iterator>
#include <limits>
#include <ranges>

#include "address-range-constants.h"

namespace cartesi {

/// \brief Dirty page tree interface
/// \detail This class maintains the dirty flags for a contiguous range of pages.
/// Page_size = 2^AR_LOG2_PAGE_SIZE.
/// The flags are structured as a tree.
/// In the public interface, each node is given by its starting offset and its log2_size.
/// The first page is (0, AR_LOG2_PAGE_SIZE), the second at (page_size, AR_LOG2_PAGE_SIZE) ...
/// So the parent of pages 0 and page_size is defined by (0, AR_LOG2_PAGE_SIZE+1) and so on.
/// Ostensibly, the tree is represented as a byte array, each node taking a single byte that
/// tells if that node is clean or dirty.
/// Each node is therefore also identified by its position in this array.
/// The the root is at position 1.
/// As usual, the left and right children of the node at pos are 2*position and (2*posision+1), respectively.
/// The tree maintains the following invariants:
///   1) When a node is dirty, all parent nodes in the path torwards the root are also dirty;
///   2) A node is clean only if all its children nodes are also clean.
/// The leaves (page nodes) are at level 0, and the root is at level log2_leaf_count.
/// The number level_count of levels in the tree is ceil(log2_page_count)+1.
/// The interface allows for derived classes to compactly model a tree that is always dirty using the same
/// interface .
class i_dirty_page_tree {
protected:
    using size_type = uint64_t;

    /// \brief View of all positions (in level, in entire tree etc)
    using positions_range = std::ranges::iota_view<size_type, size_type>;

    /// \brief Type used for positions of node in storage (no confusion with indices per level or page offsets)
    using position_iterator = std::ranges::iterator_t<positions_range>;
    static_assert(std::is_same_v<position_iterator::value_type, size_type>);

    static constexpr auto invalid_position = position_iterator{std::numeric_limits<size_type>::max()};

    /// \brief Returns view of all positions at a given level (for use with range-based for loops)
    /// \param level Desired level
    /// \returns Range of positions for level, or empty invalid range if level is out of bounds
    constexpr positions_range level_positions_view(int level) const {
        if (level >= 0 && level < level_count()) {
            const auto begin = position_iterator::value_type{1} << (level_count() - level - 1);
            return {begin, 2 * begin};
        }
        return {invalid_position, invalid_position};
    }

    /// \brief Returns number of levels in tree, from root to leaves
    constexpr int level_count() const noexcept {
        return m_level_count;
    }

    /// \brief Returns view of all levels (for use with range-based for loops)
    constexpr auto levels_view() const noexcept {
        return std::views::iota(0, level_count());
    }

    /// \brief Iterator over dirty nodes at a given level
    class dirty_iterator {
    public:
        using value_type = position_iterator;
        using reference = position_iterator;
        using difference_type = position_iterator::difference_type;

        using iterator_category = std::forward_iterator_tag;
        using iterator_concept = std::forward_iterator_tag;

        dirty_iterator() = default;

        dirty_iterator(const i_dirty_page_tree *dt, positions_range level) noexcept :
            m_dt{dt},
            m_level{level},
            m_pos{m_level.begin()} {
            // First position at level may not be dirty, so advance until first dirty or end
            while (!at_end() && !m_dt->is_dirty_position(m_pos)) {
                m_dt->advance_dirty_position(m_pos, m_level);
            }
        }

        constexpr position_iterator operator*() const noexcept {
            return m_pos;
        }

        dirty_iterator &operator++() noexcept {
            m_dt->advance_dirty_position(m_pos, m_level);
            return *this;
        }

        dirty_iterator operator++(int) noexcept {
            auto tmp = *this;
            ++(*this);
            return tmp;
        }

        constexpr bool operator==(const dirty_iterator &rhs) const noexcept {
            return m_pos == rhs.m_pos;
        }

        constexpr bool operator!=(const dirty_iterator &rhs) const noexcept {
            return !(*this == rhs);
        }

        constexpr bool at_end() const noexcept {
            return m_pos >= m_level.end();
        }

        const i_dirty_page_tree *m_dt{nullptr};
        positions_range m_level{invalid_position, invalid_position};
        position_iterator m_pos{invalid_position};
    };

    friend dirty_iterator;

    /// \brief Sentinel for dirty nodes iterator
    struct dirty_sentinel {
        constexpr bool operator==(const dirty_iterator &it) const noexcept {
            return it.at_end();
        }

        constexpr bool operator!=(const dirty_iterator &it) const noexcept {
            return !(*this == it);
        }

        friend constexpr bool operator==(const dirty_iterator &it, const dirty_sentinel &s) noexcept {
            return s == it;
        }

        friend constexpr bool operator!=(const dirty_iterator &it, const dirty_sentinel &s) noexcept {
            return !(s == it);
        }
    };

    // -----
    // Private methods that must be overriden by derived class
    // These will only ever be called by the base class, and always with valid arguments
    // -----

    /// \brief Advances a position to the next dirty position within a level
    /// \param pos Current position to advanced
    /// \param level Range of positions for level
    virtual void do_advance_dirty_position(position_iterator &pos, positions_range level) const noexcept = 0;

    /// \brief Marks the node at given position clean (and all its ancestors that only have clean descendants)
    /// \param pos Node position
    /// \detail The derived class is free to ignore the operation
    virtual void do_mark_clean_leaf_position_and_up(position_iterator pos) noexcept = 0;

    /// \brief Marks the node at a given position dirty (and all its ancestors as well)
    /// \param pos Node position
    /// \detail The derived class is free to ignore the operation
    virtual void do_mark_dirty_leaf_position_and_up(position_iterator pos) noexcept = 0;

    /// \brief Tells if the node at given position is dirty
    /// \param pos Node position
    /// \returns True if node is dirty, false otherwise
    virtual bool do_is_dirty_position(position_iterator pos) const noexcept = 0;

    /// \brief Cause tree ignore or honor attempts to mark positions clean.
    /// \param ignore If true, ignoring attempts. If false, honor them.
    /// \returns True if tree was previously ignoring attempts, false otherwise.
    /// \detail The derived class is free to ignore the operation
    virtual bool do_ignore_cleans(bool ignore) noexcept = 0;

    /// \brief Cleans entire tree
    /// \detail The derived class is free to ignore the operation
    virtual void do_clean(void) noexcept = 0;

    /// Non-Virtual Interface (NVI) pattern for do_is_dirty_position()
    bool is_dirty_position(position_iterator pos) const noexcept {
        return do_is_dirty_position(pos);
    }

    /// Non-Virtual Interface (NVI) pattern for do_advance_dirty_position()
    void advance_dirty_position(position_iterator &pos, positions_range lp) const noexcept {
        do_advance_dirty_position(pos, lp);
    }

    /// Non-Virtual Interface (NVI) pattern for do_mark_clean_position_and_up()
    void mark_clean_leaf_position_and_up(position_iterator pos) noexcept {
        do_mark_clean_leaf_position_and_up(pos);
    }

    /// Non-Virtual Interface (NVI) pattern for do_mark_dirty_position_and_up()
    void mark_dirty_leaf_position_and_up(position_iterator pos) noexcept {
        do_mark_dirty_leaf_position_and_up(pos);
    }

    // -----
    // Private interface
    // -----

    /// \brief View over dirty positions
    using dirty_range = std::ranges::subrange<dirty_iterator, dirty_sentinel, std::ranges::subrange_kind::unsized>;

    /// \brief Returns views over all dirty positions within a level
    /// \param lp Range of positions for desired level
    dirty_range dirty_positions_view(positions_range lp) const {
        return dirty_range{dirty_iterator{this, lp}, dirty_sentinel{}};
    }

    /// \brief Converts a node size to its level in the tree
    /// \param log2_size Log<sub>2</sub> of node size
    /// \returns Corresponding level (which may be out of range)
    int to_level(int log2_size) const {
        return log2_size - AR_LOG2_PAGE_SIZE;
    }

    /// \brief Converts a node offset/size to the corresponding position
    /// \param offset Offset in node
    /// \param log2_size Log<sub>2</sub> of node size
    /// \returns Corresponding position, or invalid position if out of range
    position_iterator to_position(uint64_t offset, int log2_size) const {
        const int level = to_level(log2_size);
        const auto lp = level_positions_view(level);
        offset >>= log2_size;
        if (offset < lp.size()) {
            return lp.begin() + offset;
        }
        return invalid_position;
    }

public:
    // -----
    // Public interface
    // -----

    /// \brief Constructor from number of leaves
    /// \param Number of pages in contiguous range
    explicit constexpr i_dirty_page_tree(int level_count) : m_level_count{level_count} {
        ;
    }

    i_dirty_page_tree(const i_dirty_page_tree &other) = default;
    i_dirty_page_tree &operator=(const i_dirty_page_tree &other) = default;
    i_dirty_page_tree(i_dirty_page_tree &&other) = default;
    i_dirty_page_tree &operator=(i_dirty_page_tree &&other) = default;

    // NOLINTNEXTLINE(hicpp-use-equals-default,modernize-use-equals-default)
    constexpr virtual ~i_dirty_page_tree() {}; // = default; // doesn't work due to bug in gcc

    /// \brief Returns view over the starting offset of all dirty nodes of a given log2_size
    /// \param log2_size Log<sub>2</sub> of node size
    /// \details If \p log2_size is out of bounds, returns an empty range
    auto dirty_offsets_view(int log2_size) const noexcept {
        const auto lp = level_positions_view(to_level(log2_size)); // Return empty range if level is out of bounds
        const auto os = lp.empty() ? 0 : lp.front();
        const int shl = log2_size;
        return std::views::transform(dirty_positions_view(lp), [os, shl](auto pos) { return (*pos - os) << shl; });
    }

    /// \brief Marks a page dirty (and all its ancestors as well)
    /// \param offset Offset within page
    /// \detail The derived class is free to ignore the operation
    void mark_dirty_page_and_up(uint64_t offset) noexcept {
        const auto pos = to_position(offset, AR_LOG2_PAGE_SIZE); // Returns invalid position if node is out of bounds
        if (pos != invalid_position) {
            mark_dirty_leaf_position_and_up(pos);
        }
    }

    /// \brief Cleans all nodes
    /// \detail The derived class is free to ignore the operation
    void clean() noexcept {
        do_clean();
    }

    /// \brief Marks a page clean (and all its ancestors that only have clean descendants)
    /// \param offset Offset within page
    /// \detail The derived class is free to ignore the operation
    void mark_clean_page_and_up(uint64_t offset) noexcept {
        const auto pos = to_position(offset, AR_LOG2_PAGE_SIZE); // Returns invalid position if node is out of bounds
        if (pos != invalid_position) {
            return mark_clean_leaf_position_and_up(pos);
        }
    }

    /// \brief Mark all pages in a range of interest as dirty (including their ancestors)
    /// \param offset Start of range of interest, relative to start of this range
    /// \param length Length of range of interest, in bytes
    void mark_dirty_pages_and_up(uint64_t offset, uint64_t length) noexcept {
        auto offset_aligned = offset & ~(AR_PAGE_SIZE - 1);
        const auto length_aligned = length + (offset - offset_aligned);
        for (; offset_aligned < length_aligned; offset_aligned += AR_PAGE_SIZE) {
            mark_dirty_page_and_up(offset_aligned);
        }
    }

    /// \brief Checks if a node is marked dirty
    /// \param offset Offset within node
    /// \param log2_size Log<sub>2</sub> of node size
    bool is_dirty(uint64_t offset, int log2_size) const noexcept {
        const auto pos = to_position(offset, log2_size); // Returns invalid position if node is out of bounds
        return (pos != invalid_position) && is_dirty_position(pos);
    }

    /// \brief Cause tree ignore or honor attempts to mark positions clean.
    /// \param ignore If true, ignoring attempts. If false, honor them.
    /// \returns True if tree was previously ignoring attempts, false otherwise.
    /// \detail Non-Virtual Interface (NVI) pattern for do_ignore_cleans()
    /// \detail The derived class is free to ignore the operation
    bool ignore_cleans(bool ignore) noexcept {
        return do_ignore_cleans(ignore);
    }

private:
    int m_level_count; // Number of levels in tree
};

/// \brief Dirty page tree that is forever dirty
class always_dirty_page_tree final : public i_dirty_page_tree {

    void do_advance_dirty_position(position_iterator &pos, positions_range) const noexcept override {
        ++pos;
    }

    void do_mark_dirty_leaf_position_and_up(position_iterator) noexcept override {
        ;
    }

    void do_mark_clean_leaf_position_and_up(position_iterator) noexcept override {
        ;
    }

    bool do_is_dirty_position(position_iterator) const noexcept override {
        return true;
    }

    void do_clean() noexcept override {
        ;
    }

    bool do_ignore_cleans(bool) noexcept override {
        return true;
    }

public:

    explicit always_dirty_page_tree(int level_count) noexcept : i_dirty_page_tree{level_count} {
        ;
    }

    always_dirty_page_tree(const always_dirty_page_tree &other) = default;
    always_dirty_page_tree &operator=(const always_dirty_page_tree &other) = default;
    always_dirty_page_tree(always_dirty_page_tree &&other) = default;
    always_dirty_page_tree &operator=(always_dirty_page_tree &&other) = default;

    // NOLINTNEXTLINE(hicpp-use-equals-default,modernize-use-equals-default)
    constexpr virtual ~always_dirty_page_tree() {}; // = default; // doesn't work due to bug in gcc
};

} // namespace cartesi

#endif // I_DIRTY_PAGE_TREE_H
