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
#include <queue>
#include <ranges>
#include <string>
#include <utility>

#include "algorithm.h"
#include "os-features.h"

#ifdef HAVE_OPENMP
#include <omp.h>
#endif

#include "i-hasher.h"
#include "machine-address-ranges.h"
#include "machine-hash.h"
#include "page-hash-tree-cache-stats.h"
#include "signposts.h"
#include "simd-hasher.h"

namespace cartesi {

using namespace std::string_literals;

static inline machine_hash to_hash(const_machine_hash_view view) {
    machine_hash hash;
    std::ranges::copy(view, hash.begin());
    return hash;
}

const_machine_hash_view hash_tree::get_sparse_node_hash_view(index_type node_index, int log2_size) const noexcept {
    // Pristine node
    if (is_pristine(node_index)) {
        return const_machine_hash_view{m_pristine_hashes[log2_size]};
    }
    return m_sparse_nodes[node_index].hash;
}

void hash_tree::get_pristine_proof(int curr_log2_size, proof_type &proof) const {
    const auto log2_target_size = proof.get_log2_target_size();
    for (int log2_size = curr_log2_size - 1; log2_size >= log2_target_size; --log2_size) {
        proof.set_sibling_hash(m_pristine_hashes[log2_size], log2_size);
    }
    proof.set_target_hash(m_pristine_hashes[log2_target_size]);
}

static inline uint64_t get_sibling_address(uint64_t address, int log2_size) {
    const uint64_t bit = UINT64_C(1) << log2_size;
    const uint64_t mask = ~(bit - 1);
    return (address ^ bit) & mask;
}

static inline uint64_t get_aligned_address(uint64_t address, int log2_size) {
    const uint64_t bit = UINT64_C(1) << log2_size;
    const uint64_t mask = ~(bit - 1);
    return address & mask;
}

void hash_tree::get_page_proof(address_range &ar, uint64_t address, proof_type &proof) {
    const auto paddr_page = address & ~(HASH_TREE_PAGE_SIZE - 1);
    bool hit = false;
    auto opt_br = m_page_cache.borrow_entry(paddr_page, hit);
    assert(opt_br && "page hash-tree cache has no entries to lend");
    if (!hit) {
        [[maybe_unused]] bool changed = false;
        update_dirty_page(ar, opt_br->get(), changed);
    }
    const auto log2_target_size = proof.get_log2_target_size();
    assert(log2_target_size >= HASH_TREE_LOG2_WORD_SIZE && "log2_size is too small");
    const auto &entry = opt_br->get();
    const auto node_offset = address & (HASH_TREE_PAGE_SIZE - 1);
    for (int log2_size = HASH_TREE_LOG2_PAGE_SIZE - 1; log2_size >= log2_target_size; --log2_size) {
        proof.set_sibling_hash(entry.node_hash_view(get_sibling_address(node_offset, log2_size), log2_size), log2_size);
    }
    proof.set_target_hash(entry.node_hash_view(node_offset, log2_target_size));
    m_page_cache.return_entry(*opt_br);
}

void hash_tree::get_dense_proof(address_range &ar, int ar_log2_size, uint64_t address, proof_type &proof) {
    const auto &dht = ar.get_dense_hash_tree();
    const auto log2_target_size = proof.get_log2_target_size();
    const auto dht_end = std::max<int>(HASH_TREE_LOG2_PAGE_SIZE, log2_target_size);
    const auto node_offset = address - ar.get_start();
    for (int log2_size = ar_log2_size - 1; log2_size >= dht_end; --log2_size) {
        const auto sibling_offset = get_sibling_address(node_offset, log2_size);
        proof.set_sibling_hash(dht.node_hash_view(sibling_offset, log2_size), log2_size);
    }
    if (log2_target_size >= HASH_TREE_LOG2_PAGE_SIZE) {
        proof.set_target_hash(dht.node_hash_view(node_offset, log2_target_size));
    } else {
        get_page_proof(ar, address, proof);
    }
}

hash_tree::proof_type hash_tree::get_proof(address_ranges ars, uint64_t address, int log2_size) {
    if (log2_size < HASH_TREE_LOG2_WORD_SIZE || log2_size > HASH_TREE_LOG2_ROOT_SIZE) {
        throw std::domain_error{"invalid log2_size"};
    }
    if (log2_size == HASH_TREE_LOG2_ROOT_SIZE) {
        if (address != 0) {
            throw std::domain_error{"address not aligned to log2_size"};
        }
    } else if (((address >> log2_size) << log2_size) != address) {
        throw std::domain_error{"address not aligned to log2_size"};
    }
    proof_type proof{HASH_TREE_LOG2_ROOT_SIZE, log2_size};
    proof.set_target_address(address);
    proof.set_root_hash(get_root_hash());
    index_type node_index = 1;
    int curr_log2_size = HASH_TREE_LOG2_ROOT_SIZE;
    for (;;) {
        // hit pristine node
        if (is_pristine(node_index)) {
            get_pristine_proof(curr_log2_size, proof);
            break;
        }
        const auto &node = m_sparse_nodes[node_index];
        assert(static_cast<int>(node.log2_size) == curr_log2_size && "incorrect node log2_size");
        // hit sparse tree node
        if (curr_log2_size == log2_size) {
            proof.set_target_hash(node.hash);
            break;
        }
        // transition to dense tree
        if (is_ar_node(node)) {
            auto &ar = ars[node.right];
            const int ar_log2_size = HASH_TREE_LOG2_PAGE_SIZE + ar.get_level_count() - 1;
            assert(curr_log2_size == ar_log2_size && "incorrect ar node log2_size");
            get_dense_proof(ar, ar_log2_size, address, proof);
            break;
        }
        // go down left or right on sparse tree depending on address
        --curr_log2_size;
        if ((address & (UINT64_C(1) << curr_log2_size)) == 0) {
            proof.set_sibling_hash(get_sparse_node_hash_view(node.right, curr_log2_size), curr_log2_size);
            node_index = node.left;
        } else {
            proof.set_sibling_hash(get_sparse_node_hash_view(node.left, curr_log2_size), curr_log2_size);
            node_index = node.right;
        }
    }
    return proof;
}

hash_tree_stats hash_tree::get_stats(bool clear) noexcept {
    auto s = hash_tree_stats{
        .phtc = m_page_cache.get_stats(clear),
        .sparse_node_hashes = m_sparse_node_hashes,
        .dense_node_hashes = m_dense_node_hashes,
    };
    if (clear) {
        m_sparse_node_hashes = 0;
        for (auto &a : m_dense_node_hashes) {
            a = 0;
        }
    }
    return s;
}

bool hash_tree::update_dirty_page(address_range &ar, page_hash_tree_cache::entry &entry, bool &changed) {
    const auto paddr_page = entry.get_paddr_page();
    const auto *base = ar.get_host_memory();
    if (!ar.is_memory() || base == nullptr || !ar.contains_absolute(paddr_page, HASH_TREE_PAGE_SIZE)) {
        return false;
    }
    const auto offset = paddr_page - ar.get_start();
    const auto page_view = std::span<const unsigned char, HASH_TREE_PAGE_SIZE>{base + offset, HASH_TREE_PAGE_SIZE};
    variant_hasher h{m_hash_function};
    page_hash_tree_cache::simd_page_hasher<variant_hasher> queue(h);
    auto &stats = m_page_cache.get_stats_ref();
    auto ret = m_page_cache.enqueue_hash_entry(queue, page_view, entry, stats);
    stats.inner_page_hashes += queue.flush();
    auto node_hash_view = ar.get_dense_hash_tree().node_hash_view(offset, HASH_TREE_LOG2_PAGE_SIZE);
    changed = !std::ranges::equal(entry.root_hash_view(), node_hash_view);
    if (changed) {
        std::ranges::copy(entry.root_hash_view(), node_hash_view.begin());
        ++stats.page_changes;
    }
    return ret;
}

bool hash_tree::enqueue_hash_dirty_page(page_hash_tree_cache::simd_page_hasher<variant_hasher> &queue,
    address_range &ar, page_hash_tree_cache::entry &entry, page_hash_tree_cache_stats &stats) {
    const auto paddr_page = entry.get_paddr_page();
    const auto *base = ar.get_host_memory();
    if (!ar.is_memory() || base == nullptr || !ar.contains_absolute(paddr_page, HASH_TREE_PAGE_SIZE)) {
        return false;
    }
    const auto offset = paddr_page - ar.get_start();
    const auto page_view = std::span<const unsigned char, HASH_TREE_PAGE_SIZE>{base + offset, HASH_TREE_PAGE_SIZE};
    return m_page_cache.enqueue_hash_entry(queue, page_view, entry, stats);
}

bool hash_tree::return_updated_dirty_pages(address_ranges ars, dirty_pages &batch,
    changed_address_ranges &changed_ars) {
    if (batch.empty()) {
        return false;
    }
    //??D The batch size past which we switch to parallel updates needs to be tuned empirically
    const int batch_size = static_cast<int>(batch.size());
    // Set block size to maximize SIMD lane utilization by hashing multiple pages together
    const int block_size = std::min(static_cast<int>(variant_hasher{m_hash_function}.get_optimal_lane_count()),
        page_hash_tree_cache::simd_page_hasher<variant_hasher>::QUEUE_MAX_PAGE_COUNT);
    // It's only worth to use multi-threading if we have enough entries to process
    [[maybe_unused]] const int threads =
        (m_concurrency > 1 && batch_size > m_concurrency && batch_size > block_size) ? m_concurrency : 1;
    uint64_t update_failures{0};
    uint64_t word_hits{0};
    uint64_t word_misses{0};
    uint64_t page_changes{0};
    uint64_t inner_page_hashes{0};
    uint64_t pristine_pages{0};
    uint64_t non_pristine_pages{0};
#pragma omp parallel for schedule(dynamic) if (threads > 1) num_threads(threads) reduction(+ : update_failures,        \
        word_hits, word_misses, page_changes, inner_page_hashes, pristine_pages, non_pristine_pages)
    for (int i = 0; i < batch_size; i += block_size) {
        // Queue entries to be hashed
        variant_hasher h{m_hash_function};
        page_hash_tree_cache::simd_page_hasher<variant_hasher> queue(h);
        page_hash_tree_cache_stats stats;
        for (int j = i; j < std::min(batch_size, i + block_size); ++j) {
            auto &[ar_index, br, changed] = batch[j];
            auto &ar = ars[ar_index];
            if (!enqueue_hash_dirty_page(queue, ar, br, stats)) {
                ++update_failures;
            }
        }
        // Flush SIMD hasher queue
        stats.inner_page_hashes += queue.flush();
        // Update changed entries
        for (int j = i; j < std::min(batch_size, i + block_size); ++j) {
            auto &[ar_index, br, changed] = batch[j];
            auto &ar = ars[ar_index];
            const auto offset = br.get_paddr_page() - ar.get_start();
            auto root_hash_view = br.root_hash_view();
            auto node_hash_view = ar.get_dense_hash_tree().node_hash_view(offset, HASH_TREE_LOG2_PAGE_SIZE);
            changed = !std::ranges::equal(root_hash_view, node_hash_view);
            if (changed) {
                std::ranges::copy(root_hash_view, node_hash_view.begin());
                ++stats.page_changes;
            }
        }
        // Increment stats
        word_hits += stats.word_hits;
        word_misses += stats.word_misses;
        page_changes += stats.page_changes;
        inner_page_hashes += stats.inner_page_hashes;
        pristine_pages += stats.pristine_pages;
        non_pristine_pages += stats.non_pristine_pages;
    }

    auto &page_stats = m_page_cache.get_stats_ref();
    page_stats.word_hits += word_hits;
    page_stats.word_misses += word_misses;
    page_stats.page_changes += page_changes;
    page_stats.inner_page_hashes += inner_page_hashes;
    page_stats.pristine_pages += pristine_pages;
    page_stats.non_pristine_pages += non_pristine_pages;

    // Return all entries and collect address ranges that were actually changed by update
    for (auto &[ar_index, br, changed] : batch) {
        auto &ar = ars[ar_index];
        auto offset = br.get_paddr_page() - ar.get_start();
        if (m_page_cache.return_entry(br)) {
            // If page hash was changed during update
            if (changed) {
                // If we haven't already done so, add changed address range to list
                algorithm::try_push_back(changed_ars, ar_index);
                // If page was marked dirty but was not in fact dirty
            } else {
                // We can safely mark the page clean because its contents already matched its hash
                // So we won't need to "bubble-up" any hash changes based on it
                ar.get_dirty_page_tree().mark_clean_page_and_up(offset);
            }
        } else {
            ++update_failures;
        }
    }
    // Done with batch
    batch.clear();
    return update_failures > 0;
}

hash_tree::~hash_tree() {
#ifdef DUMP_HASH_TREE_STATS
    std::cerr << "sparse node hashes: " << std::dec << m_sparse_node_hashes << '\n';
    std::cerr << "dense node hashes: \n";
    uint64_t sum = 0;
    for (int i = 0; auto a : m_dense_node_hashes) {
        sum += a;
        if (a != 0) {
            std::cerr << "    " << std::dec << i << ": " << a << '\n';
        }
        ++i;
    }
    std::cerr << "    total: " << sum << '\n';
#endif
}

bool hash_tree::update_dirty_pages(address_ranges ars, changed_address_ranges &changed_ars) {
    SCOPED_SIGNPOST(m_log, m_spid_update_page_hashes, "hash-tree: update page hashes", "");
    bool update_failed = false;
    dirty_pages batch;
    batch.reserve(m_page_cache.capacity());
    // Go sequentially over dirty pages of all address ranges, collecting borrowed cache entries for them.
    // The cache eventually runs out of entries to lend.
    // At this point, we have accumulated a batch of cache entries for dirty pages.
    // We update all these cache entries in parallel.
    // After that, we sequentially return the updated entries to the cache.
    // ??D In C++23, use views::enumerate instead
    for (int ar_index = 0; auto &ar : ars) {
        // Break out if there were previous failures
        if (update_failed) {
            break;
        }
        const auto start = ar.get_start();
        const auto length = ar.get_length();
        auto &dht = ar.get_dense_hash_tree();
        auto &dpt = ar.get_dirty_page_tree();
        for (auto offset : dpt.dirty_offsets_view(HASH_TREE_LOG2_PAGE_SIZE)) {
            if (offset >= length) {
                auto hash_view = dht.node_hash_view(offset, HASH_TREE_LOG2_PAGE_SIZE);
                std::ranges::copy(m_pristine_hashes[HASH_TREE_LOG2_PAGE_SIZE], hash_view.begin());
                continue;
            }
            const auto paddr_page = start + offset;
            auto opt_br = m_page_cache.borrow_entry(paddr_page);
            // If we have no entry, the cache ran out of entries to lend
            if (!opt_br) {
                // So we update all entries and return them to the cache
                update_failed |= return_updated_dirty_pages(ars, batch, changed_ars);
                // In theory, we have now returned all borrowed cache entries
                opt_br = m_page_cache.borrow_entry(paddr_page);
                // So we must have succeeded borrowing, unless there was a prior failure
                if (!opt_br) {
                    update_failed = true;
                    break;
                }
            }
            // Add borrowed entry to batch
            batch.emplace_back(ar_index, *opt_br, false);
        }
        ++ar_index;
    }
    // Update and return last batch
    update_failed |= return_updated_dirty_pages(ars, batch, changed_ars);
    if (update_failed) {
        // Kill cache because it is most likely corrupted
        m_page_cache.clear();
        return false;
    }
    return true;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void hash_tree::update_and_clear_dense_node_entries(dense_node_entries &batch, int log2_size) {
    if (batch.empty()) {
        return;
    }
    //??D The batch size past which we switch to parallel updates needs to be tuned empirically
    const int batch_size = static_cast<int>(batch.size());
    const int block_size = static_cast<int>(variant_hasher{m_hash_function}.get_optimal_lane_count());
    // It's only worth to use multi-threading if we have enough entries to process
    [[maybe_unused]] const int threads =
        (m_concurrency > 1 && batch_size > m_concurrency * block_size) ? m_concurrency : 1;
#pragma omp parallel for schedule(static) if (threads > 1) num_threads(threads)
    for (int block_start = 0; block_start < batch_size; block_start += block_size) {
        variant_hasher h{m_hash_function};
        simd_concat_hasher<variant_hasher, const_machine_hash_view> queue(h);
        for (int i = block_start; i < std::min(batch_size, block_start + block_size); ++i) {
            auto &[dht, offset] = batch[i];
            auto child_size = UINT64_C(1) << (log2_size - 1);
            auto parent = dht.node_hash_view(offset, log2_size);
            auto left = dht.node_hash_view(offset, log2_size - 1);
            auto right = dht.node_hash_view(offset + child_size, log2_size - 1);
            queue.enqueue(left, right, parent);
        }
        queue.flush();
    }
    m_dense_node_hashes[log2_size] += batch_size;
    batch.clear();
}

bool hash_tree::update_dense_trees(address_ranges ars, const changed_address_ranges &changed_ars) {
    SCOPED_SIGNPOST(m_log, m_spid_update_dense_trees, "hash-tree: update dense trees", "");
    if (changed_ars.empty()) {
        return true;
    }
    // We can batch more if we have more concurrency, however we need to limit to not run out of memory.
    const size_t batch_size = std::min(m_concurrency << 10, 16384);
    dense_node_entries batch;
    batch.reserve(batch_size);
    // Get maximum log2_size of all address ranges
    const auto max_level_count = std::ranges::max(
        changed_ars | std::views::transform([ars](auto ar_index) { return ars[ar_index].get_level_count(); }));
    // Go from page size up until we have updated all dirty nodes of all all dense trees
    for (int level = 1; level < max_level_count; ++level) {
        auto log2_size = HASH_TREE_LOG2_PAGE_SIZE + level;
        for (auto ar_index : changed_ars) {
            auto &ar = ars[ar_index];
            //??D If there are too many address ranges (not the case now), we could optimize this by
            //??D looping over only those with enough levels
            if (level > ar.get_level_count()) {
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

bool hash_tree::update_sparse_tree(address_ranges ars, const changed_address_ranges &changed_ars) {
    SCOPED_SIGNPOST(m_log, m_spid_update_sparse_tree, "hash-tree: update sparse tree", "");
    // If there no changed address ranges, we are done
    // Otherwise, allocate a fifo that holds at most one entry per changed address-range leaf-node
    // For each changed address-range leaf-node,
    //     Copy the hash from the root of the address-range dense hash tree to the leaf-node
    //     Enqueue its sparse node's parent for update
    // Until the queue is empty
    //     Update the hash of the node at the front from the hash of its children nodes
    //     If node is not the root, enqueue its parent for update
    auto changed_count = std::ranges::size(changed_ars);
    if (changed_count == 0) {
        return true;
    }
    using E = std::pair<int, int>;
    std::vector<E> changed_backing;
    changed_backing.reserve(changed_count);
    std::priority_queue<E, std::vector<E>, std::greater<>> changed(std::greater<>{}, std::move(changed_backing));
    for (auto ar_index : changed_ars) {
        auto ar_node_index = get_ar_sparse_node_index(ar_index);
        auto &ar_node = m_sparse_nodes[ar_node_index];
        auto ar_root_hash_view = ars[ar_index].get_dense_hash_tree().root_hash_view();
        std::ranges::copy(ar_root_hash_view, ar_node.hash.begin());
        auto &ar_parent_node = m_sparse_nodes[ar_node.parent];
        if (ar_parent_node.marked == 0) {
            ar_parent_node.marked = 1;
            changed.emplace(ar_parent_node.log2_size, ar_node.parent);
        }
    }
    variant_hasher h{m_hash_function};
    simd_concat_hasher<variant_hasher, const_machine_hash_view> queue(h);
    int last_log2_size = -1;
    while (!changed.empty()) {
        auto [log2_size, inner_index] = changed.top();
        changed.pop();
        auto &inner_node = m_sparse_nodes[inner_index];
        // Every node with smaller log2_size than inner_node has already been processed.
        // By implication, its children have already been processed.
        // So we can clear the mark with no fear inner_node will be added back to the queue.
        inner_node.marked = 0;
        auto left_hash_view = get_sparse_node_hash_view(inner_node.left, log2_size - 1);
        auto right_hash_view = get_sparse_node_hash_view(inner_node.right, log2_size - 1);
        // When crossing tree height boundary, we need to flush the queue
        if (last_log2_size != log2_size) {
            last_log2_size = log2_size;
            queue.flush();
        }
        queue.enqueue(left_hash_view, right_hash_view, inner_node.hash);
        ++m_sparse_node_hashes;
        if (!is_pristine(inner_node.parent)) {
            auto &parent_node = m_sparse_nodes[inner_node.parent];
            if (parent_node.marked == 0) {
                parent_node.marked = 1;
                changed.emplace(log2_size + 1, inner_node.parent);
            }
        }
    }
    queue.flush();
    return true;
}

machine_hash hash_tree::get_root_hash() const noexcept {
    return m_sparse_nodes[1].hash;
}

machine_hash hash_tree::get_dense_node_hash(address_range &ar, uint64_t address, int log2_size) {
    assert(ar.contains_absolute(address, HASH_TREE_WORD_SIZE) && "address not in expected address range");
    if (log2_size < HASH_TREE_LOG2_PAGE_SIZE) {
        assert(log2_size >= HASH_TREE_LOG2_WORD_SIZE && "invalid log2_size");
        const auto paddr_page = address & ~(HASH_TREE_PAGE_SIZE - 1);
        bool hit = false;
        auto opt_br = m_page_cache.borrow_entry(paddr_page, hit);
        assert(opt_br && "page hash-tree cache has no entries to lend");
        if (!hit) {
            [[maybe_unused]] bool changed = false;
            update_dirty_page(ar, *opt_br, changed);
        }
        auto node_offset = address - paddr_page;
        auto hash = to_hash(opt_br->get().node_hash_view(node_offset, log2_size));
        m_page_cache.return_entry(*opt_br);
        return hash;
    }
    const auto offset = address - ar.get_start();
    return to_hash(ar.get_dense_hash_tree().node_hash_view(offset, log2_size));
}

machine_hash hash_tree::get_node_hash(address_ranges ars, uint64_t address, int log2_size) {
    if (log2_size < HASH_TREE_LOG2_WORD_SIZE || log2_size > HASH_TREE_LOG2_ROOT_SIZE) {
        throw std::invalid_argument{"invalid log2_size"};
    }
    if (log2_size == HASH_TREE_LOG2_ROOT_SIZE) {
        if (address != 0) {
            throw std::invalid_argument{"address not aligned to log2_size"};
        }
    } else if (((address >> log2_size) << log2_size) != address) {
        throw std::invalid_argument{"address not aligned to log2_size"};
    }
    index_type node_index = 1;
    int curr_log2_size = HASH_TREE_LOG2_ROOT_SIZE;
    for (;;) {
        // hit pristine node
        if (is_pristine(node_index)) {
            return m_pristine_hashes[log2_size];
        }
        const auto &node = m_sparse_nodes[node_index];
        assert(static_cast<int>(node.log2_size) == curr_log2_size && "incorrect node log2_size");
        // hit sparse tree node
        if (curr_log2_size == log2_size) {
            return node.hash;
        }
        // transition to dense tree
        if (is_ar_node(node)) {
            auto &ar = ars[node.right];
            [[maybe_unused]] const int ar_log2_size = HASH_TREE_LOG2_PAGE_SIZE + ar.get_level_count() - 1;
            assert(curr_log2_size == ar_log2_size && "incorrect ar node log2_size");
            return get_dense_node_hash(ar, address, log2_size);
        }
        // go down left or right on sparse tree depending on address
        --curr_log2_size;
        if ((address & (UINT64_C(1) << curr_log2_size)) == 0) {
            node_index = node.left;
        } else {
            node_index = node.right;
        }
    }
}

bool hash_tree::verify(address_ranges ars) const {
    variant_hasher h{m_hash_function};
    bool ret = true;
    for (auto ar_node_index = get_ar_sparse_node_index(0); const auto &ar : ars) {
        const std::span<const unsigned char> mem{ar.get_host_memory(), ar.get_length()};
        const auto &dht = ar.get_dense_hash_tree();
        const auto &dpt = ar.get_dirty_page_tree();
        auto ar_actually_dirty = false;
        for (uint64_t offset = 0; offset < ar.get_length(); offset += HASH_TREE_PAGE_SIZE) {
            auto paddr_page = ar.get_start() + offset;
            auto page = mem.subspan(offset, HASH_TREE_PAGE_SIZE);
            auto page_hash = get_merkle_tree_hash(h, page, HASH_TREE_WORD_SIZE);
            auto actually_dirty = !std::ranges::equal(page_hash, dht.node_hash_view(offset, HASH_TREE_LOG2_PAGE_SIZE));
            ar_actually_dirty = ar_actually_dirty || actually_dirty;
            auto marked_dirty = dpt.is_node_dirty(offset, HASH_TREE_LOG2_PAGE_SIZE);
            // LCOV_EXCL_START
            if (actually_dirty != marked_dirty) {
                if (!marked_dirty) {
                    ret = false;
                    std::cerr << "page 0x" << std::hex << std::uppercase << paddr_page << " (in "
                              << ar.get_description() << ") is " << (marked_dirty ? "" : "not ")
                              << "marked dirty but is " << (actually_dirty ? "" : "not ") << "dirty\n";
                    // check page in cache it is there
                    auto opt_br = m_page_cache.borrow_entry_if_hit(paddr_page);
                    if (opt_br) {
                        auto &cache_entry = opt_br->get();

                        if (!std::ranges::equal(page_hash, cache_entry.root_hash_view())) {
                            std::cerr << "    cached page root hash mismatch\n";
                        }
                        const page_hash_tree_cache::page_view entry_page{cache_entry.get_page()};
                        for (auto word_offset = 0UL; word_offset < HASH_TREE_PAGE_SIZE;
                            word_offset += HASH_TREE_WORD_SIZE) {
                            const auto page_word = page.subspan(word_offset, HASH_TREE_WORD_SIZE);
                            const auto entry_word = entry_page.subspan(word_offset, HASH_TREE_WORD_SIZE);
                            if (!std::ranges::equal(page_word, entry_word)) {
                                std::cerr << "    word 0x" << std::hex << std::uppercase << (paddr_page + word_offset)
                                          << " differs\n";
                            }
                        }
                        m_page_cache.return_entry(cache_entry);
                    }
                    std::cerr << "! FAILED!\n";
                }
            }
        }
        const int ar_log2_size = HASH_TREE_LOG2_PAGE_SIZE + ar.get_level_count() - 1;
        auto ar_marked_dirty = dpt.is_node_dirty(0, ar_log2_size);
        if (ar_actually_dirty != ar_marked_dirty) {
            if (!ar_marked_dirty) {
                ret = false;
                std::cerr << ar.get_description() << " is " << (ar_marked_dirty ? "" : "not ") << "marked dirty but is "
                          << (ar_actually_dirty ? "" : "not ") << "dirty";
                std::cerr << "! FAILED!\n";
            }
        }
        const auto &ar_node = m_sparse_nodes[ar_node_index];
        if (!std::ranges::equal(ar_node.hash, dht.node_hash_view(0, ar_log2_size))) {
            std::cerr << ar.get_description() << " dense hash tree root does not match sparse node hash\n";
        }
        // LCOV_EXCL_STOP
        ++ar_node_index;
    }
    return ret;
}

bool hash_tree::update(address_ranges ars) {
    SCOPED_SIGNPOST(m_log, m_spid_update, "hash-tree: update", "");
    changed_address_ranges changed_ars;
    changed_ars.reserve(ars.size());
    auto update_succeeded = update_dirty_pages(ars, changed_ars) && update_dense_trees(ars, changed_ars) &&
        update_sparse_tree(ars, changed_ars);
    if (update_succeeded) {
        for (auto ar_index : changed_ars) {
            ars[ar_index].get_dirty_page_tree().clean();
        }
    }
    return update_succeeded;
}

bool hash_tree::update_words(address_ranges ars, dirty_words_type dirty_words) {
    constexpr auto page_mask = ~(HASH_TREE_PAGE_SIZE - 1);
    // Dirty_words contains an unordered set of the address of all words that became dirty since last update
    // We copy these to a sorted vector "words"
    // Every word in the same page must be updated by the same thread
    // So we compute a vector "page_starts" with the indices into "words" of the first word in each page
    // It is over this "page_starts" vector that we iterate over using threads
    if (dirty_words.empty()) {
        return true;
    }
    std::vector<uint64_t> words;
    words.reserve(dirty_words.size());
    std::ranges::copy(dirty_words, std::back_inserter(words));
    std::ranges::sort(words);
    std::vector<uint64_t> page_starts;
    uint64_t last_paddr_page = -1;
    //??D change to std::views::enumerate on C++23
    for (uint64_t start = 0; auto word : words) {
        auto paddr_page = word & page_mask;
        if (paddr_page != last_paddr_page) {
            page_starts.push_back(start);
            last_paddr_page = paddr_page;
        }
        ++start;
    }
    page_starts.push_back(words.size()); // last entry
    //??D I'll assume here that we do not have more threads than the cache size,
    // so we don't need to process in batches, and will fail if this assumption if false
    uint64_t update_failures{0}; // NOLINT(misc-const-correctness)
    int ar_index = 0;
    int max_level_count = 0;
    dense_node_entries curr_dense_node;
    dense_node_entries next_dense_node;
    changed_address_ranges changed_ars;
    for (unsigned i = 0; i < page_starts.size() - 1; ++i) {
        auto begin = page_starts[i];
        auto end = page_starts[i + 1];
        auto paddr_page = words[begin] & page_mask;
        bool hit = false;
        auto opt_br = m_page_cache.borrow_entry(paddr_page, hit);
        if (!opt_br) {
            ++update_failures;
            continue;
        }
        auto &cache_entry = opt_br->get();
        for (; ar_index < static_cast<int>(ars.size()); ++ar_index) {
            if (ars[ar_index].contains_absolute(paddr_page, HASH_TREE_PAGE_SIZE)) {
                break;
            }
        }
        if (ar_index >= static_cast<int>(ars.size())) {
            ++update_failures;
            m_page_cache.return_entry(cache_entry);
            continue;
        }
        auto &ar = ars[ar_index];
        algorithm::try_push_back(changed_ars, ar_index);
        max_level_count = std::max(max_level_count, ar.get_level_count());
        const auto *base = ar.get_host_memory();
        if (!ar.is_memory() || base == nullptr) {
            ++update_failures;
            m_page_cache.return_entry(cache_entry);
            continue;
        }
        const auto page_offset = paddr_page - ar.get_start();
        // if we had a cache hit, update only the words that changed in the cache
        if (hit) {
            variant_hasher h{m_hash_function};
            page_hash_tree_cache::simd_page_hasher<variant_hasher> queue(h);
            const auto page =
                std::span<const unsigned char, HASH_TREE_PAGE_SIZE>{base + page_offset, HASH_TREE_PAGE_SIZE};
            auto &page_tree = cache_entry.get_page_hash_tree();
            const page_hash_tree_cache::page_view entry_page{cache_entry.get_page()};
            for (auto word_address : std::span(words).subspan(begin, end - begin)) {
                const auto word_offset = word_address - paddr_page;
                const auto page_word =
                    std::span<const unsigned char, HASH_TREE_WORD_SIZE>{page.subspan(word_offset, HASH_TREE_WORD_SIZE)};
                const auto entry_word =
                    std::span<unsigned char, HASH_TREE_WORD_SIZE>{entry_page.subspan(word_offset, HASH_TREE_WORD_SIZE)};
                const auto index = static_cast<int>((HASH_TREE_PAGE_SIZE + word_offset) / HASH_TREE_WORD_SIZE);
                queue.enqueue_leaf(page_word, page_tree, index);
                std::ranges::copy(page_word, entry_word.begin());
            }
            queue.flush();
            // otherwise, the update from scratch
        } else {
            bool changed = false;
            if (!update_dirty_page(ar, cache_entry, changed)) {
                ++update_failures;
                m_page_cache.return_entry(cache_entry);
                continue;
            }
        }
        auto &dht = ar.get_dense_hash_tree();
        auto node_hash_view = dht.node_hash_view(page_offset, HASH_TREE_LOG2_PAGE_SIZE);
        std::ranges::copy(cache_entry.root_hash_view(), node_hash_view.begin());
        m_page_cache.return_entry(cache_entry);
        algorithm::try_push_back(curr_dense_node,
            dense_node_entry{.dht = dht, .offset = get_aligned_address(page_offset, HASH_TREE_LOG2_PAGE_SIZE + 1)});
    }
    for (int level = 1; level < max_level_count; ++level) {
        auto log2_size = HASH_TREE_LOG2_PAGE_SIZE + level;
        next_dense_node.clear();
        variant_hasher h{m_hash_function};
        simd_concat_hasher<variant_hasher, const_machine_hash_view> queue(h);
        for (auto &[dht, offset] : curr_dense_node) {
            auto child_size = UINT64_C(1) << (log2_size - 1);
            auto parent = dht.node_hash_view(offset, log2_size);
            auto left = dht.node_hash_view(offset, log2_size - 1);
            auto right = dht.node_hash_view(offset + child_size, log2_size - 1);
            queue.enqueue(left, right, parent);
            algorithm::try_push_back(next_dense_node,
                dense_node_entry{.dht = dht, .offset = get_aligned_address(offset, log2_size + 1)});
        }
        queue.flush();
        std::swap(curr_dense_node, next_dense_node);
    }
    return !static_cast<bool>(update_failures > 0) && update_sparse_tree(ars, changed_ars);
}

bool hash_tree::update_page(address_ranges ars, uint64_t paddr_page) {
    paddr_page >>= HASH_TREE_LOG2_PAGE_SIZE;
    paddr_page <<= HASH_TREE_LOG2_PAGE_SIZE;
    variant_hasher h{m_hash_function};
    // Find address range where page might lie
    auto it = std::ranges::find_if(ars,
        [paddr_page](auto &ar) { return ar.contains_absolute(paddr_page, HASH_TREE_PAGE_SIZE); });
    if (it == ars.end()) {
        throw std::runtime_error{"page to update is not in a memory address range"};
    }
    const auto ar_index = it - ars.begin();
    auto &ar = ars[ar_index];
    // Get page entry from page hash-tree cache
    auto opt_br = m_page_cache.borrow_entry(paddr_page);
    assert(opt_br && "page hash-tree cache has no entries to lend");
    auto &entry = opt_br->get();
    bool changed = false;
    // Update page with data from address range
    update_dirty_page(ar, entry, changed);
    // If nothing changed, we are done
    if (!changed) {
        m_page_cache.return_entry(entry);
        return true;
    }
    // Copy new page hash to address range's dense hash tree
    const auto page_offset = paddr_page - ar.get_start();
    auto &dht = ar.get_dense_hash_tree();
    auto page_hash_view = dht.node_hash_view(page_offset, HASH_TREE_LOG2_PAGE_SIZE);
    std::ranges::copy(entry.root_hash_view(), page_hash_view.begin());
    // Bubble up the dense hash tree
    const int ar_log2_size = HASH_TREE_LOG2_PAGE_SIZE + ar.get_level_count() - 1;
    for (int log2_size = HASH_TREE_LOG2_PAGE_SIZE + 1; log2_size <= ar_log2_size; ++log2_size) {
        auto child_size = UINT64_C(1) << (log2_size - 1);
        auto node_offset = get_aligned_address(page_offset, log2_size);
        auto parent = dht.node_hash_view(node_offset, log2_size);
        auto left = dht.node_hash_view(node_offset, log2_size - 1);
        auto right = dht.node_hash_view(node_offset + child_size, log2_size - 1);
        get_concat_hash(h, left, right, parent);
    }
    // Copy address range hash to corresponding sparse node
    auto node_index = get_ar_sparse_node_index(ar_index);
    std::ranges::copy(dht.node_hash_view(0, ar_log2_size), m_sparse_nodes[node_index].hash.begin());
    // Bubble up sparse hash tree
    node_index = m_sparse_nodes[node_index].parent;
    int log2_size = ar_log2_size + 1;
    while (node_index != 0) {
        auto &node = m_sparse_nodes[node_index];
        assert(log2_size == static_cast<int>(node.log2_size) && "invalid sparse node log2_size");
        auto left_hash_view = get_sparse_node_hash_view(node.left, log2_size - 1);
        auto right_hash_view = get_sparse_node_hash_view(node.right, log2_size - 1);
        get_concat_hash(h, left_hash_view, right_hash_view, node.hash);
        node_index = node.parent;
        ++log2_size;
    }
    assert(log2_size == HASH_TREE_LOG2_ROOT_SIZE + 1 && "invalid sparse tree log2_size");
    m_page_cache.return_entry(entry);
    return true;
}

hash_tree::pristine_hashes hash_tree::get_pristine_hashes(hash_function_type hash_function) {
    variant_hasher h{hash_function};
    pristine_hashes hashes{};
    std::array<unsigned char, HASH_TREE_WORD_SIZE> zero{};
    machine_hash hash = get_hash(h, zero);
    for (auto log2_size : std::views::iota(HASH_TREE_LOG2_WORD_SIZE, static_cast<int>(hashes.size()))) {
        hashes[log2_size] = hash;
        get_concat_hash(h, hash, hash, hash);
    }
    return hashes;
};

static int get_concurrency([[maybe_unused]] int value) {
#ifdef HAVE_OPENMP
    const int concurrency = value != 0 ? value : omp_get_max_threads();
    return std::min(concurrency, omp_get_max_threads());
#else
    return 1;
#endif
}

hash_tree::hash_tree(const hash_tree_config &config, uint64_t concurrency, const_address_ranges ars,
    hash_function_type hash_function) :
#ifdef HAS_SIGNPOSTS
    m_log{os_log_create("io.cartesi.machine-emulator", "hash-tree")},
    m_spid_update{os_signpost_id_generate(m_log)},
    m_spid_update_page_hashes{os_signpost_id_generate(m_log)},
    m_spid_update_dense_trees{os_signpost_id_generate(m_log)},
    m_spid_update_sparse_tree{os_signpost_id_generate(m_log)},
    m_page_cache{m_log, variant_hasher{hash_function}, config.phtc_size},
#else
    m_page_cache{variant_hasher{hash_function}, config.phtc_size},
#endif
    m_sparse_nodes{create_nodes(ars)},
    m_pristine_hashes{get_pristine_hashes(hash_function)},
    m_concurrency{get_concurrency(static_cast<int>(concurrency))},
    m_hash_function{hash_function} {
}

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
hash_tree::index_type hash_tree::append_nodes(uint64_t begin_page_index, uint64_t log2_page_count,
    Iter &ar_curr /* modifiable! */, Iter ar_begin, Sent ar_sent, nodes_type &nodes, index_type parent) {
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
        auto ar_index = static_cast<index_type>(ar_curr - ar_begin);
        const auto ar_node_index = get_ar_sparse_node_index(ar_index);
        auto &ar_node = nodes[ar_node_index]; // Address-range leaf-nodes are already there
        ar_node = node_type{
            .left = AR_NODE_TAG,
            .right = ar_index,
            .parent = parent,
            .log2_size = static_cast<uint32_t>(log2_size),
            .marked = 0,
        };
        // Consume range
        ++ar_curr;
        return ar_node_index;
    }
    // We already subdivided to page level and found nothing
    if (log2_page_count == 0) {
        // Node is pristine, no need to allocate a node
        return 0;
    }
    index_type inner_index = 1;
    if (parent != 0) { // If not root, add inner node, otherwise use root node already there
        inner_index = static_cast<index_type>(nodes.size());
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
    // Address-range leaf-nodes come next, so we always know where they are from their index in ars
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

// LCOV_EXCL_START
void hash_tree::dump(const_address_ranges ars, std::ostream &out) {
    out << "digraph HashTree {\n";
    out << "  rankdir=TB;\n";
    out << "  node [shape=circle];\n";
    for (int index = 1; const auto &node : m_sparse_nodes | std::views::drop(1)) {
        if (is_ar_node(node)) {
            const auto &ar = ars[node.right];
            out << "  A" << index << " [label=\"" << index << "," << ar.get_description() << "\"];\n";
        }
        ++index;
    }
    out << "  subgraph InnerNodesOneChild {\n";
    out << "    node [shape=circle, width=0.5, height=0.5, label=\"\", style=filled, fillcolor=gray, "
           "fixedsize=true];\n";
    for (int index = 1; const auto &node : m_sparse_nodes | std::views::drop(1)) {
        if (!is_ar_node(node)) {
            if (is_pristine(node.left) || is_pristine(node.right)) {
                out << "    A" << index << "[label=\"" << index << "\"];\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph InnerNodesTwoChildren {\n";
    out << "    node [shape=circle, width=0.5, height=0.5, label=\"\", style=filled, fillcolor=red, fixedsize=true];\n";
    for (int index = 1; const auto &node : m_sparse_nodes | std::views::drop(1)) {
        if (!is_ar_node(node)) {
            if (!is_pristine(node.left) && !is_pristine(node.right)) {
                out << "    A" << index << ";\n";
            }
        }
        ++index;
    }
    out << "  }\n";
    out << "  subgraph NullNodes {\n";
    out << "    node [shape=circle, width=0.5, height=0.5, label=\"\", style=filled, fillcolor=white, color=black, "
           "fixedsize=true];\n";
    for (int null_index = 0; const auto &node : m_sparse_nodes | std::views::drop(1)) {
        if (!is_ar_node(node)) {
            if (is_pristine(node.left)) {
                out << "    N" << ++null_index << ";\n";
            }
            if (is_pristine(node.right)) {
                out << "    N" << ++null_index << ";\n";
            }
        }
    }
    out << "  }\n";
    for (int index = 1, null_index = 0; const auto &node : m_sparse_nodes | std::views::drop(1)) {
        if (!is_ar_node(node)) {
            if (!is_pristine(node.left)) {
                out << "  A" << index << " -> A" << node.left << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
            if (!is_pristine(node.right)) {
                out << "  A" << index << " -> A" << node.right << ";\n";
            } else {
                out << "  A" << index << " -> N" << ++null_index << ";\n";
            }
        }
        ++index;
    }
    for (auto index = get_ar_sparse_node_index(0); const auto &node : m_sparse_nodes | std::views::drop(2)) {
        out << "  A" << index << " -> A" << node.parent << " [constraint=false, color=gray, style=dashed];\n";
        ++index;
    }
    out << "}\n";
}
// LCOV_EXCL_STOP

} // namespace cartesi
