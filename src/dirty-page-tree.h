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

#ifndef DIRTY_PAGE_TREE_H
#define DIRTY_PAGE_TREE_H

/// \file
/// \brief Dirty map as a complete tree

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <ranges>
#include <span>
#include <stdexcept>
#include <vector>

#include "assert-printf.h"
#include "i-dirty-page-tree.h"
#include "ranges.h"

namespace cartesi {

/// \brief Dirty page tree
class dirty_page_tree final : public i_dirty_page_tree {
public:
    /// \brief Each node in tree is either clean or dirty
    enum class status_type : uint8_t { clean, dirty };

private:
    using container_type = std::vector<status_type>;

    /// \brief Checks if we can represent a tree with this many levels
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
        if ((container_type{}.max_size() >> level_count) == 0) {
            throw std::invalid_argument{"too many levels"};
        }
        // Make sure we can address position 1 << level_count
        if ((std::numeric_limits<position_iterator::value_type>::max() >> level_count) == 0) {
            throw std::invalid_argument{"too many levels"};
        }
        return level_count;
    }

    void build_from_leaves() {
        for (auto level : levels_view() | std::views::drop(1)) {
            for (auto pos : views::iterators(level_positions_view(level))) {
                if (do_is_dirty_position(get_left_child_position(pos)) ||
                    do_is_dirty_position(get_right_child_position(pos))) {
                    m_tree[*pos] = status_type::dirty;
                }
            }
        }
    }

public:
    /// \brief Constructor for leaves marked the same way
    /// \param leaf_count Number of leaves in tree. This is rounded up to the next power of 2.
    /// \param init Status of the first \p leaf_count leaves (the ones past leaf_count start clean)
    explicit dirty_page_tree(int level_count, size_type leaf_count, status_type init = status_type::dirty) :
        i_dirty_page_tree{check_level_count(level_count, leaf_count)},
        m_leaf_positions{level_positions_view(0)},
        m_valid_positions{position_iterator(1), position_iterator(position_iterator::value_type{1} << level_count)},
        m_tree{typename container_type::size_type{1} << level_count, status_type::clean} {
        const auto lp = m_leaf_positions;
        const auto first_leaf = *lp.begin();
        const auto first_pad = first_leaf + leaf_count;
        const auto pad_count = *lp.end() - first_pad;
        std::ranges::fill(std::span(m_tree).subspan(first_leaf, leaf_count), init);
        std::ranges::fill(std::span(m_tree).subspan(first_pad, pad_count), status_type::dirty);
        build_from_leaves();
    }

    /// \brief Constructor from initializer list
    /// \param leaves Status of first few leaves in tree.
    /// \details This is a constructor mostly used in simple tests
    explicit dirty_page_tree(int level_count, std::initializer_list<status_type> leaves) :
        i_dirty_page_tree{check_level_count(level_count, leaves.size())},
        m_leaf_positions{level_positions_view(0)},
        m_valid_positions{position_iterator(1), position_iterator(position_iterator::value_type{1} << level_count)},
        m_tree{typename container_type::size_type{1} << level_count, status_type::clean} {
        const auto lp = m_leaf_positions;
        std::ranges::copy(leaves, &m_tree[*lp.begin()]);
        build_from_leaves();
    }

    // Dump tree in DOT format
    void dump() const {
        std::cout << "digraph HashTree {\n";
        std::cout << "    node [shape=circle, width=0.5, height=0.5, fixedsize=true, style=filled];\n";
        std::cout << "  subgraph Dirty {\n";
        for (auto pos : views::iterators(valid_positions_view())) {
            if (do_is_dirty_position(pos)) {
                std::cout << "    A" << *pos << "[fillcolor=gray, label=\"" << *pos << "\"];\n";
            }
        }
        std::cout << "  }\n";
        std::cout << "  subgraph Clean {\n";
        for (auto pos : views::iterators(valid_positions_view())) {
            if (is_clean_position(pos)) {
                std::cout << "    A" << *pos << "[fillcolor=white, label=\"" << *pos << "\"];\n";
            }
        }
        std::cout << "  }\n";
        for (auto level : levels_view()) {
            std::cout << "  { rank = same; ";
            for (auto pos : level_positions_view(level)) {
                std::cout << "A" << pos << "; ";
            }
            std::cout << "}\n";
        }
        dump_edges();
        for (auto level : levels_view()) {
            const auto bounds = level_positions_view(level);
            for (auto pos : std::views::iota(bounds.begin(), bounds.end() - 1)) {
                std::cout << "  A" << *pos << " -> A" << *pos + 1 << " [style=invis];\n";
            }
        }
        std::cout << "}\n";
    }

private:
    /// \brief Returns view of all valid positions (for use with range-based for loops)
    positions_range leaf_positions_view() const {
        return m_leaf_positions;
    }

    /// \brief Returns position of left child of a node
    /// \param pos Position of node
    /// \returns Position of its left child
    static constexpr position_iterator get_left_child_position(position_iterator pos) {
        return position_iterator{(*pos) * 2};
    }

    /// \brief Returns position of right child of a node
    /// \param node Position of node
    /// \returns Position of its right child
    static constexpr position_iterator get_right_child_position(position_iterator pos) {
        return position_iterator{((*pos) * 2) + 1};
    }

    /// \brief Returns position of parent of a node
    /// \param node Position of node
    /// \returns Position of its parent
    static constexpr position_iterator get_parent_position(position_iterator pos) {
        return position_iterator{(*pos) / 2};
    }

    /// \brief Returns position of sibling a node
    /// \param node Position of node
    /// \returns Position of its sibling
    static constexpr position_iterator get_sibling_position(position_iterator pos) {
        return position_iterator{(*pos) ^ 1};
    }

    /// \brief Returns position of left sibling a node
    /// \param node Position of node
    /// \returns Position of its left sibling (which can be the node itself)
    static constexpr position_iterator get_left_sibling_position(position_iterator pos) {
        constexpr auto left_mask = ~position_iterator::value_type{1};
        return position_iterator{(*pos) & left_mask};
    }

    /// \brief Returns position of right sibling a node
    /// \param node Position of node
    /// \returns Position of its right sibling (which can be the node itself)
    static constexpr position_iterator get_right_sibling_position(position_iterator pos) {
        return position_iterator{(*pos) | 1};
    }

    /// \brief Returns position of root node
    /// \returns Position of root node
    static constexpr position_iterator get_root_position() {
        return position_iterator{1};
    }

    /// \brief Checks if a node belongs to a given level
    /// \param pos Position of node
    /// \param bounds Position bounds
    /// \returns True if node is within bounds, false otherwise
    static constexpr bool is_position_in(position_iterator pos, positions_range bounds) {
        return pos >= bounds.begin() && pos < bounds.end();
    }

    /// \brief Returns view of all valid positions (for use with range-based for loops)
    positions_range valid_positions_view() const {
        return m_valid_positions;
    }

    /// \brief Checks if position valid for a node
    /// \param node Position of node
    /// \returns True if valid, false otherwise
    bool is_valid_position(position_iterator pos) const {
        return is_position_in(pos, valid_positions_view());
    }

    /// \brief Skip over clean nodes to reach the next dirty node
    /// \details The idea is to go up the tree until we are at a left sibling with a dirty right sibling,
    /// then go down, going left whenever the left child is dirty, until we are back at the correct level
    void up_then_down(position_iterator &pos, positions_range level) const {
        if (!is_valid_position(pos)) {
            pos = invalid_position;
            return;
        }
        while (pos != get_root_position()) {
            if (pos == get_left_sibling_position(pos)) {
                const auto r = get_right_sibling_position(pos);
                if (do_is_dirty_position(r)) {
                    pos = r;
                    down(pos, level);
                    return;
                }
            }
            pos = get_parent_position(pos);
        }
        pos = invalid_position;
    }

    void down(position_iterator &pos, positions_range level) const {
        while (!is_position_in(pos, level)) {
            auto el = get_left_child_position(pos);
            if (!do_is_dirty_position(el)) {
                auto r = get_right_child_position(pos);
                if (!do_is_dirty_position(r)) {
                    // no more dirty entries
                    pos = invalid_position;
                    return;
                }
                pos = r;
            } else {
                pos = el;
            }
        }
    }

    /// \brief Checks if node at valid position is clean
    /// \param node Position of node
    /// \returns True if clean, false otherwise
    bool is_clean_position(position_iterator pos) const {
        return m_tree[*pos] == status_type::clean;
    }

    // Dump tree edges in DOT format
    void dump_edges(position_iterator pos = get_root_position()) const {
        if (is_valid_position(get_left_child_position(pos))) {
            auto el = get_left_child_position(pos);
            std::cout << "  A" << *pos << " -> A" << *el << ";\n";
            auto r = get_right_child_position(pos);
            std::cout << "  A" << *pos << " -> A" << *r << ";\n";
            dump_edges(el);
            dump_edges(r);
        }
    }

    // -----
    // i_dirty_page_tree interface
    // -----

    /// \brief Advances a position to the next dirty position within a level
    void do_advance_dirty_position(position_iterator &pos, positions_range level) const noexcept override {
        up_then_down(pos, level);
    }

    /// \brief Marks the node at given position clean (and all its ancestors that only have clean descendants)
    /// \param pos Leaf position
    /// \details Assumes \p pos points to a leaf position
    void do_mark_clean_leaf_position_and_up([[maybe_unused]] position_iterator pos) noexcept override {
        while (pos != get_root_position()) {
            m_tree[*pos] = status_type::clean;
            if (do_is_dirty_position(get_sibling_position(pos))) {
                return;
            }
            pos = get_parent_position(pos);
        }
        m_tree[*get_root_position()] = status_type::clean;
    }

    /// \brief Marks the leaf at a given position dirty (and all its ancestors as well)
    /// \param pos Position of leaf node
    /// \details Assumes \p pos points to a leaf position
    void do_mark_dirty_leaf_position_and_up(position_iterator pos) noexcept override {
        while (pos != get_root_position()) {
            if (do_is_dirty_position(pos)) {
                return;
            }
            m_tree[*pos] = status_type::dirty;
            pos = get_parent_position(pos);
        }
        m_tree[*get_root_position()] = status_type::dirty;
    }

    /// \brief Tells if the node at given position is dirty
    bool do_is_dirty_position(position_iterator pos) const noexcept override {
        return m_tree[*pos] == status_type::dirty;
    }

    /// \brief Clean entire tree
    void do_clean() noexcept override {
        for (auto pos : dirty_positions_view(leaf_positions_view())) {
            do_mark_clean_leaf_position_and_up(pos);
        }
        assert(m_tree[*get_root_position()] == status_type::clean);
    }

    // -----
    // Fields
    // -----

    positions_range m_leaf_positions;  // Bounds on leaf positions
    positions_range m_valid_positions; // Bounds on all positions
    //??(edubart): convert to std::span over mapped memory
    container_type m_tree; // Complete tree of flags
};

} // namespace cartesi

#endif // DIRTY_PAGE_TREE_H
