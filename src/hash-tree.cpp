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

#include "hash-tree.h"

#include <bit>
#include <iostream>
#include <ranges>
#include <string>

#include "machine.h"

namespace cartesi {

using namespace std::string_literals;

void hash_tree::check_address_ranges(const machine &m, const uint64_t ar_index_end) {
    if (ar_index_end == 0) {
        throw std::invalid_argument{"no address ranges"};
    }
    for (uint64_t ar_index = 0; ar_index != ar_index_end; ++ar_index) {
        const auto &ar = m.read_hash_tree_address_range(ar_index);
        // Empty ranges are not supported
        if (ar.is_empty()) {
            throw std::invalid_argument{"empty ranges are not supported"};
        }
        // Length must not overflow when rounded up to the next power of 2
        const auto length = ar.get_length();
        if (length > (UINT64_C(1) << 63)) {
            throw std::invalid_argument{
                "length of "s.append(ar.get_description()).append(" overflows when rounded up to a power of 2")};
        }
        const auto length_bit_ceil = std::bit_ceil(length);
        const auto start = ar.get_start();
        // Start must be aligned to length rounded up to the next power of 2
        if ((start & (length_bit_ceil - 1)) != 0) {
            throw std::invalid_argument{"start of "s.append(ar.get_description())
                    .append(" is not aligned to its length rounded up to a power of 2")};
        }
        // Range cannot overflow when length is rounded up to the next power of 2
        if (start >= UINT64_MAX - length_bit_ceil) {
            throw std::invalid_argument{"range "s.append(ar.get_description())
                    .append(" overflows when its length is rounded up to a power of 2")};
        }
        // Ranges must lot overlap, even when their lengths are rounded up to the next power of 2
        const auto end = start + length_bit_ceil;
        for (uint64_t prev_ar_index = 0; prev_ar_index != ar_index; ++prev_ar_index) {
            const auto &prev_ar = m.read_hash_tree_address_range(prev_ar_index);
            const auto prev_start = prev_ar.get_start();
            const auto prev_length_bit_ceil = std::bit_ceil(prev_ar.get_length());
            const auto prev_end = prev_start + prev_length_bit_ceil;
            if (start < prev_end && end > prev_start) {
                throw std::invalid_argument{"address range of "s.append(ar.get_description())
                        .append(" overlaps with address range of ")
                        .append(prev_ar.get_description())
                        .append(" when lengths are rounded up to powers of 2")};
            }
        }
    }
}

hash_tree::nodes_type hash_tree::create_nodes(const machine &m, uint64_t ar_index_end) {
    check_address_ranges(m, ar_index_end);
    nodes_type nodes;
    nodes.push_back(node_type{});
    const auto begin_page_index = 0;
    const auto log2_page_count = HASH_TREE_LOG2_ROOT_SIZE - HASH_TREE_LOG2_PAGE_SIZE;
    uint64_t ar_index = 0;
    auto root_index = append_nodes(m, begin_page_index, log2_page_count, ar_index, ar_index_end, nodes);
    if (root_index != 1) {
        throw std::logic_error{"expected root index to be 1 (got "s.append(std::to_string(root_index)).append(")")};
    }
    return nodes;
}

uint64_t hash_tree::append_nodes(const machine &m, uint64_t begin_page_index, uint64_t log2_page_count,
    uint64_t &ar_index, const uint64_t ar_index_end, nodes_type &nodes) {
    // We are past the last occupied address ranges
    const auto page_count = UINT64_C(1) << log2_page_count;
    const auto end_page_index = begin_page_index + page_count;
    if (ar_index >= ar_index_end) {
        // Entire subtree is pristine, simply return index to pristine node
        return 0;
    }
    const auto &ar = m.read_hash_tree_address_range(ar_index);
    const auto ar_begin_page_index = ar.get_start() >> HASH_TREE_LOG2_PAGE_SIZE;
    // We are before the next occupied address range
    if (ar_begin_page_index >= end_page_index) {
        // Entire subtree is pristine, simply return index to pristine node
        return 0;
    }
    const auto ar_page_count = std::bit_ceil(ar.get_length()) >> HASH_TREE_LOG2_PAGE_SIZE;
    // We hit the next address range exactly
    if (ar_begin_page_index == begin_page_index && ar_page_count == page_count) {
        const uint64_t ar_node_index = nodes.size();
        nodes.push_back(node_type{.child_index = {UINT64_MAX, ar_index}});
        // Consume range
        ++ar_index;
        return ar_node_index;
    }
    // We already subdivided to page level and found nothing
    if (log2_page_count == 0) {
        // Node is pristine, no need to allocate a node
        return 0;
    }
    const uint64_t inner_index = nodes.size();
    nodes.push_back(node_type{});
    // Otherwise, allocate inner node and recurse first left, then right
    nodes[inner_index].child_index[0] =
        append_nodes(m, begin_page_index, log2_page_count - 1, ar_index, ar_index_end, nodes);
    nodes[inner_index].child_index[1] =
        append_nodes(m, begin_page_index + (page_count >> 1), log2_page_count - 1, ar_index, ar_index_end, nodes);
    return inner_index;
}

void hash_tree::dump_nodes(const machine &m, const nodes_type &nodes, std::ostream &out) {
    out << "digraph HashTree {\n";
    out << "  node [shape=circle];\n";
    for (int index = 1; const auto &node : nodes | std::views::drop(1)) {
        if (node.child_index[0] == UINT64_MAX) {
            const auto &ar = m.read_hash_tree_address_range(node.child_index[1]);
            out << "  A" << index << " [label=\"" << ar.get_description() << "\"];\n";
        }
        ++index;
    }
    out << "  subgraph InnerNodesOneChild {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=black, "
           "fixedsize=true];\n";
    for (int index = 1; const auto &node : nodes | std::views::drop(1)) {
        if (node.child_index[0] != UINT64_MAX) {
            if (node.child_index[0] == 0 || node.child_index[1] == 0) {
                out << "    A" << index << ";\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph InnerNodesTwoChildren {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=red, fixedsize=true];\n";
    for (int index = 1; const auto &node : nodes | std::views::drop(1)) {
        if (node.child_index[0] != UINT64_MAX) {
            if (node.child_index[0] != 0 && node.child_index[1] != 0) {
                out << "    A" << index << ";\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph NullNodes {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=white, color=black, "
           "fixedsize=true];\n";
    for (int null_index = 0; const auto &node : nodes | std::views::drop(1)) {
        if (node.child_index[0] != UINT64_MAX) {
            if (node.child_index[0] == 0) {
                out << "    N" << ++null_index << ";\n";
            }
            if (node.child_index[1] == 0) {
                out << "    N" << ++null_index << ";\n";
            }
        }
    }
    out << "  }\n";
    for (int index = 1, null_index = 0; const auto &node : nodes | std::views::drop(1)) {
        if (node.child_index[0] != UINT64_MAX) {
            if (node.child_index[0] != 0) {
                out << "  A" << index << " -> A" << node.child_index[0] << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
            if (node.child_index[1] != 0) {
                out << "  A" << index << " -> A" << node.child_index[1] << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
        }
        ++index;
    }
    out << "}\n";
}

} // namespace cartesi
