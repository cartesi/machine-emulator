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

#include <atomic>
#include <bit>
#include <iostream>
#include <ranges>
#include <string>

#include "machine-address-ranges.h"

namespace cartesi {

using namespace std::string_literals;

bool hash_tree::update_page_entry(hasher_type &h, const address_range &ar, page_hash_tree_cache::entry &entry) {
    const auto paddr_page = entry.get_paddr_page();
    const auto *base = ar.get_host_memory();
    if (!ar.is_memory() || base == nullptr || !ar.contains_absolute(paddr_page, AR_PAGE_SIZE)) {
        return false;
    }
    const auto offset = paddr_page - ar.get_start();
    const auto page_view = std::span<const unsigned char, AR_PAGE_SIZE>{base+offset, AR_PAGE_SIZE};
    return entry.update(h, page_view, m_pristine_page_hash_tree);
}

//??D when we abolish peek, this will not need to receive the machine anymore
bool hash_tree::return_updated_page_entries(page_entries &batch) {
    std::atomic<int> update_failed{0};
    // #pragma omp parallel
    {
        hasher_type h;
        // #pragma omp for
        for (decltype(batch.size()) i = 0; i < batch.size(); ++i) {
            auto &[ar, br] = batch[i];
            if (!update_page_entry(h, ar, br.get())) {
                update_failed.store(1, std::memory_order_relaxed);
                // #pragma omp cancel for
            }
            // #pragma omp cancellation point for
        }
    }
    // Return all entries
    for (auto &[ar, br] : batch) {
        if (!m_cache.return_entry(std::move(br))) {
            update_failed.store(1, std::memory_order_relaxed);
        }
    }
    // Done with batch
    batch.clear();
    return update_failed.load(std::memory_order_relaxed);
}

bool hash_tree::update_page_hashes(address_ranges ars) {
    bool update_failed = false;
    page_entries batch;
    batch.reserve(m_cache.capacity());
    // Go sequentially over dirty pages of all address ranges, collecting borrowed cache entries for them.
    // The cache eventually runs out of entries to lend.
    // At this point, we have accumulated a batch of cache entries for dirty pages.
    // We update all these cache entries in parallel.
    // After that, we sequentially return the updated entries to the cache.
    for (auto &&ar : ars) {
        // Break out if there were previous failures
        if (update_failed) {
            break;
        }
        const auto start = ar.get_start();
        auto view = ar.get_dirty_page_tree().dirty_offsets_view(HASH_TREE_LOG2_PAGE_SIZE) |
            std::views::filter([length = ar.get_length()](auto offset) { return offset < length; });
        for (auto offset : view) {
            const auto paddr_page = start + offset;
            auto opt_br = m_cache.borrow_entry(paddr_page);
            // If we have no entry, the cache ran out of entries to lend
            if (!opt_br) {
                // So we update all entries and return them to the cache
                update_failed |= return_updated_page_entries(batch); // Using bitwise or to avoid short-circuit
                // In theory, we have now returned all borrowed cache entries
                opt_br = m_cache.borrow_entry(paddr_page);
                // So we must have succeeded borrowing, unless there was a prior failure
                if (!opt_br) {
                    update_failed = true;
                    break;
                }
            }
            // Add borrowed entry to batch
            batch.emplace_back(ar, std::move(*opt_br));
        }
    }
    // Update and return last batch
    update_failed |= return_updated_page_entries(batch); // Using bitwise or to avoid short-circuit
    if (update_failed) {
        // Kill cache because it is most likely corrupted
        m_cache.clear();
        return false;
    }
    return true;
}

void hash_tree::update_and_clear_dense_node_entries(dense_node_entries &batch, int log2_size) {
    if (batch.empty()) {
        return;
    }
    // #pragma omp parallel
    {
        hasher_type h;
        // #pragma omp for
        for (auto &[dht, offset] : batch) {
            auto child_size = 1 << (log2_size - 1);
            auto parent = dht.node_hash_view(offset, log2_size);
            auto left = dht.node_hash_view(offset, log2_size - 1);
            auto right = dht.node_hash_view(offset + child_size, log2_size - 1);
            get_concat_hash(h, left, right, parent);
        }
    }
    batch.clear();
}

bool hash_tree::update_dense_trees(address_ranges ars) {
    const auto thread_count = 8;
    const auto batch_size = thread_count << 10;
    dense_node_entries batch;
    batch.reserve(batch_size);
    // Get maximum log2_size of all address ranges
    const auto max_level_count =
        std::ranges::max(ars | std::views::transform([](const auto &ar) { return ar.get_level_count(); }));
    // Go from page size up until we have updated all dirty nodes of all all dense trees
    for (int level = 1; level < max_level_count; ++level) {
        auto log2_size = HASH_TREE_LOG2_PAGE_SIZE + level;
        for (auto &&ar : ars) {
            //??D If there are too many address ranges (not the case now), we could optimize this by
            //??D looping over only those with enough levels
            if (level >= ar.get_level_count()) {
                continue;
            }
            auto &dht = ar.get_dense_hash_tree();
            for (auto offset : ar.get_dirty_page_tree().dirty_offsets_view(log2_size)) {
                if (batch.size() == batch_size) {
                    update_and_clear_dense_node_entries(batch, log2_size);
                }
                batch.emplace_back(dht, offset);
            }
        }
        update_and_clear_dense_node_entries(batch, log2_size);
    }
    return true;
}

void hash_tree::get_root_hash(machine_hash_view hash) const noexcept {
    std::ranges::copy(m_nodes[1].hash, hash.begin());
}

const_machine_hash_view hash_tree::get_node_hash_view(uint64_t node_index, int log2_size) const noexcept {
    // Pristine node
    if (node_index == 0) {
        return const_machine_hash_view{m_pristine_hashes[log2_size]};
    }
    return m_nodes[node_index].hash;
}

bool hash_tree::update_sparse_tree(address_ranges ars) {
    // Count number of dirty address-range leaf-nodes
    // If there are none, we are done
    // Otherwise, allocate a fifo that holds at most one entry per dirty address-range leaf-node
    // For each dirty address-range leaf-node,
    //     Copy the hash from root of the address-range dense hash tree
    //     Enqueue its parent for update
    // Until the queue is empty
    //     Updating the hash of the node at the front from the hash of its children nodes
    //     If node is not the root, enqueue its parent for update
    auto is_dirty_ar = [](const address_range &ar) {
        const auto log2_size = AR_LOG2_PAGE_SIZE + ar.get_level_count() - 1;
        return ar.get_dirty_page_tree().is_dirty(0, log2_size);
    };
    auto dirty_count = std::ranges::count_if(ars, is_dirty_ar);
    if (dirty_count == 0) {
        return true;
    }
    circular_buffer<uint64_t> dirty(dirty_count);
    for (uint64_t ar_index = 0; const auto &ar : ars) {
        if (is_dirty_ar(ar)) {
            std::cerr << ar.get_description() << " was dirty\n";
            auto ar_node_index = ar_index + 2;
            auto &ar_node = m_nodes[ar_node_index];
            auto ar_root_hash_view = ar.get_dense_hash_tree().root_hash_view();
            if (std::ranges::equal(ar_root_hash_view, ar_node.hash)) {
                std::cerr << "    but hash didn't change!\n";
            }
            std::ranges::copy(ar_root_hash_view, ar_node.hash.begin());
            dirty.try_push_back(ar_node.parent);
        }
        ++ar_index;
    }
    hasher_type h;
    while (!dirty.empty()) {
        auto index = dirty.front();
        dirty.pop_front();
        auto &inner_node = m_nodes[index];
        auto left_hash_view = get_node_hash_view(inner_node.left, inner_node.log2_size - 1);
        auto right_hash_view = get_node_hash_view(inner_node.right, inner_node.log2_size - 1);
        get_concat_hash(h, left_hash_view, right_hash_view, inner_node.hash);
        if (inner_node.parent != 0) {
            dirty.try_push_back(inner_node.parent);
        }
    }
    return true;
}

bool hash_tree::update(address_ranges ars) {
    auto update_succeeded = update_page_hashes(ars) && update_dense_trees(ars) && update_sparse_tree(ars);
    if (update_succeeded) {
        for (auto &&ar : ars) {
            ar.get_dirty_page_tree().clean();
        }
    }
    return update_succeeded;
}

hash_tree::pristine_hashes hash_tree::get_pristine_hashes() const {
    hasher_type h;
    pristine_hashes hashes{};
    std::array<unsigned char, HASH_TREE_WORD_SIZE> zero{};
    machine_hash hash = get_hash(h, zero);
    for (auto log2_size : std::views::iota(HASH_TREE_LOG2_WORD_SIZE, static_cast<int>(hashes.size()))) {
        hashes[log2_size] = hash;
        get_concat_hash(h, hash, hash, hash);
    }
    return hashes;
};

hash_tree::hash_tree(const hash_tree_config &config, const_address_ranges ars) :
    m_nodes{create_nodes(ars)},
    m_cache{config.phtc_size},
    m_pristine_hashes{get_pristine_hashes()},
    m_pristine_page_hash_tree{page_hash_tree_cache::entry::get_pristine_page_hash_tree(hasher_type{})} {}

void hash_tree::check_address_ranges(const_address_ranges ars) {
    for (int ar_i = 0; auto &&ar : ars) {
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
        for (auto &&prev_ar : std::views::take(ars, ar_i)) {
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
        ++ar_i;
    }
}

template <std::random_access_iterator Iter, std::sentinel_for<Iter> Sent>
    requires(std::same_as<std::remove_cvref_t<std::iter_reference_t<Iter>>, address_range> &&
        std::is_reference_v<std::iter_reference_t<Iter>>)
uint64_t hash_tree::append_nodes(uint64_t begin_page_index, uint64_t log2_page_count, Iter &ar_curr /* modifiable! */,
    Iter ar_begin, Sent ar_sent, nodes_type &nodes, uint64_t parent) {
    const auto log2_size = log2_page_count + HASH_TREE_LOG2_PAGE_SIZE;
    // Page range is past the last occupied address ranges
    if (ar_curr == ar_sent) {
        // Entire subtree is pristine, simply return index to pristine node
        return 0;
    }
    auto &&ar = *ar_curr;
    const auto page_count = UINT64_C(1) << log2_page_count;
    const auto end_page_index = begin_page_index + page_count;
    const auto ar_begin_page_index = ar.get_start() >> HASH_TREE_LOG2_PAGE_SIZE;
    // Page range ends before next occupied address range starts
    if (ar_begin_page_index >= end_page_index) {
        // Entire subtree is pristine, simply return index to pristine node
        return 0;
    }
    // Page range matches next occopied address range exactly
    const auto ar_page_count = std::bit_ceil(ar.get_length()) >> HASH_TREE_LOG2_PAGE_SIZE;
    if (ar_begin_page_index == begin_page_index && ar_page_count == page_count) {
        auto ar_index = static_cast<uint64_t>(ar_curr - ar_begin);
        auto &ar_node = nodes[ar_index + 2]; // Address-range leaf-nodes are already there
        ar_node = node_type{
            .left = UINT64_MAX,
            .right = ar_index,
            .parent = parent,
            .log2_size = log2_size,
        };
        // Consume range
        ++ar_curr;
    }
    // We already subdivided to page level and found nothing
    if (log2_page_count == 0) {
        // Node is pristine, no need to allocate a node
        return 0;
    }
    uint64_t inner_index = 1;
    if (parent != 0) { // If not root, add inner node, otherwise use root node already there
        inner_index = nodes.size();
        nodes.push_back(node_type{});
    }
    // Otherwise, allocate inner node and recurse first left, then right
    nodes[inner_index].left = append_nodes(begin_page_index, log2_page_count - 1, ar_curr, ar_begin, ar_sent, nodes,
        inner_index); // must index into vector because function appends to it
    nodes[inner_index].right = append_nodes(begin_page_index + (page_count >> 1), log2_page_count - 1, ar_curr,
        ar_begin, ar_sent, nodes, inner_index); // must index into vector because function appends to it
    nodes[inner_index].parent = parent;
    nodes[inner_index].log2_size = log2_size;
    return inner_index;
}

hash_tree::nodes_type hash_tree::create_nodes(const_address_ranges ars) {
    check_address_ranges(ars);
    nodes_type nodes;
    // Node at 0 is reserved to avoid confusion with index 0 that means "pristine"
    // Node at 1 is the root, so we always know where it is
    // Address-range leaf-nodes come next, so we always know where they are as well
    // The rest of the nodes are added as needed, in an order we do not care about
    nodes.resize(1 + 1 + ars.size());
    const auto begin_page_index = 0;
    const auto log2_page_count = HASH_TREE_LOG2_ROOT_SIZE - HASH_TREE_LOG2_PAGE_SIZE;
    auto ar_iter = ars.begin();
    auto root_index = append_nodes(begin_page_index, log2_page_count, ar_iter, ars.begin(), ars.end(), nodes, 0);
    if (root_index != 1) {
        throw std::logic_error{"expected root index to be 1 (got "s.append(std::to_string(root_index)).append(")")};
    }
    return nodes;
}

void hash_tree::dump(address_ranges ars, std::ostream &out) {
    out << "digraph HashTree {\n";
    out << "  rankdir=TB;\n";
    out << "  node [shape=circle];\n";
    for (int index = 1; const auto &node : m_nodes | std::views::drop(1)) {
        if (node.left == UINT64_MAX) {
            const auto &ar = ars[node.right];
            out << "  A" << index << " [label=\"" << ar.get_description() << "\"];\n";
        }
        ++index;
    }
    out << "  subgraph InnerNodesOneChild {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=black, "
           "fixedsize=true];\n";
    for (int index = 1; const auto &node : m_nodes | std::views::drop(1)) {
        if (node.left != UINT64_MAX) {
            if (node.left == 0 || node.right == 0) {
                out << "    A" << index << ";\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph InnerNodesTwoChildren {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=red, fixedsize=true];\n";
    for (int index = 1; const auto &node : m_nodes | std::views::drop(1)) {
        if (node.left != UINT64_MAX) {
            if (node.left != 0 && node.right != 0) {
                out << "    A" << index << ";\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph NullNodes {\n";
    out << "    node [shape=circle, width=0.2, height=0.2, label=\"\", style=filled, fillcolor=white, color=black, "
           "fixedsize=true];\n";
    for (int null_index = 0; const auto &node : m_nodes | std::views::drop(1)) {
        if (node.left != UINT64_MAX) {
            if (node.left == 0) {
                out << "    N" << ++null_index << ";\n";
            }
            if (node.right == 0) {
                out << "    N" << ++null_index << ";\n";
            }
        }
    }
    out << "  }\n";
    for (int index = 1, null_index = 0; const auto &node : m_nodes | std::views::drop(1)) {
        if (node.left != UINT64_MAX) {
            if (node.left != 0) {
                out << "  A" << index << " -> A" << node.left << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
            if (node.right != 0) {
                out << "  A" << index << " -> A" << node.right << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
        }
        ++index;
    }
    for (int index = 2; const auto &node : m_nodes | std::views::drop(2)) {
        out << "  A" << index << " -> A" << node.parent << " [constraint=false, color=gray, style=dashed];\n";
        ++index;
    }
    out << "}\n";
}

} // namespace cartesi
