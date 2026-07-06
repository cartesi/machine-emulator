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

#ifndef STEP_LOG_HPP
#define STEP_LOG_HPP

/// \file
/// \brief Parsed binary step log: the witnessed tree, the queries every replayer runs over it, and
/// the root-hash recompute.
///
/// Heap-free so it builds in the risc0 guest; the host and zkVM hash backends are selected by
/// ZKARCHITECTURE.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <span>

#include "address-range-constants.hpp"
#include "hash-tree-constants.hpp"
#include "i-hasher.hpp"
#include "machine-hash.hpp"
#include "step-log-layout.hpp"
#include "throw.hpp"
#include "uint128.hpp"
#include "variant-hasher.hpp"

namespace cartesi {

using hash_type = unsigned char (*)[MACHINE_HASH_SIZE];
using const_hash_type = const unsigned char (*)[MACHINE_HASH_SIZE];

#ifdef ZKARCHITECTURE

extern "C" void zk_merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size,
    hash_type hash);

extern "C" void zk_concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result);

inline void merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size, hash_type hash) {
    zk_merkle_tree_hash(hash_function, data, size, hash);
}

inline void concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result) {
    zk_concat_hash(hash_function, left, right, result);
}

#else

inline void merkle_tree_hash(hash_function_type hash_function, const unsigned char *data, size_t size, hash_type hash) {
    variant_hasher h{hash_function};
    get_merkle_tree_hash(h, std::span<const unsigned char>{data, size}, HASH_TREE_WORD_SIZE,
        machine_hash_view{*hash, MACHINE_HASH_SIZE});
}

inline void concat_hash(hash_function_type hash_function, const_hash_type left, const_hash_type right,
    hash_type result) {
    variant_hasher h{hash_function};
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    get_concat_hash(h, *reinterpret_cast<const machine_hash *>(left), *reinterpret_cast<const machine_hash *>(right),
        *reinterpret_cast<machine_hash *>(result));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
}

#endif

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

/// \brief Parsed binary step log: the witnessed tree plus the header values it was decoded from.
/// \details Non-owning -- pages/nodes/siblings are spans into the caller's log image. \p pages is
/// mutable so the root recompute can rehash each page into its scratch slot. The queries and the
/// recompute are caller-invariant: every replayer finds a page, finds a node, and reconstructs the
/// root identically.
struct step_log {
    machine_hash root_hash_before{};   ///< Root hash before the step (from log header)
    uint64_t requested_cycle_count{0}; ///< Caller-requested cycle count (from log header; see step_log_header)
    machine_hash root_hash_after{};    ///< Root hash after the step (from log header)
    hash_function_type hash_function{hash_function_type::keccak256}; ///< Hash function used for the step log
    std::span<page_entry> pages;            ///< Witnessed pages, rehashed into their scratch slots
    std::span<const node_entry> nodes;      ///< Subtree-write nodes
    std::span<const machine_hash> siblings; ///< Sibling hashes for untouched subtrees
    uint64_t consumed_node_count{0};        ///< Nodes a semantic write consumed during replay; see compute_root_hash

    /// \brief Decode and validate a binary step log.
    /// \param log_image Pointer to the step log file bytes. The returned step_log keeps spans into it,
    /// so it must outlive the step_log.
    /// \param log_size Size of the log bytes.
    /// \return A validated step_log whose witnessed tree reconstructs root_hash_before.
    /// \throw runtime_error if the log is malformed or the initial root hash does not match.
    /// \details Mirrors StepLog.decode in the Solidity replayer: header parse, per-count size bounds,
    /// page ordering, per-node alignment/range, the combined pages+nodes disjointness walk, and the
    /// initial-root recompute.
    static step_log decode(unsigned char *log_image, uint64_t log_size) {
        step_log log;
        // Parse header with a stack-local copy to avoid alignment UB on the log buffer
        if (log_size < sizeof(step_log_header)) {
            THROW(std::runtime_error, "step log shorter than header");
        }
        step_log_header header{};
        std::memcpy(&header, log_image, sizeof(header));
        if (header.signature != STEP_LOG_SIGNATURE) {
            THROW(std::runtime_error, "invalid step log signature");
        }
        switch (header.hash_function) {
            case static_cast<uint64_t>(hash_function_type::keccak256):
                log.hash_function = hash_function_type::keccak256;
                break;
            case static_cast<uint64_t>(hash_function_type::sha256):
                log.hash_function = hash_function_type::sha256;
                break;
            default:
                THROW(std::runtime_error, "invalid log format: unsupported hash function type");
        }
        // Bound each count against remaining log bytes. Division avoids overflow
        // (remaining stays within log_size; each *_count * sizeof is then safe).
        uint64_t remaining = log_size - sizeof(step_log_header);
        if (header.page_count > remaining / sizeof(page_entry)) {
            THROW(std::runtime_error, "page count exceeds step log size");
        }
        const uint64_t pages_bytes = header.page_count * sizeof(page_entry);
        remaining -= pages_bytes;
        if (header.node_count > remaining / sizeof(node_entry)) {
            THROW(std::runtime_error, "node count exceeds step log size");
        }
        const uint64_t nodes_bytes = header.node_count * sizeof(node_entry);
        remaining -= nodes_bytes;
        if (remaining % sizeof(machine_hash) != 0 || header.sibling_count != remaining / sizeof(machine_hash)) {
            THROW(std::runtime_error, "sibling count does not match step log size");
        }
        log.root_hash_before = header.root_hash_before;
        log.requested_cycle_count = header.requested_cycle_count;
        log.root_hash_after = header.root_hash_after;
        if (header.page_count == 0) {
            THROW(std::runtime_error, "page count is zero");
        }
        log.pages = std::span<page_entry>{reinterpret_cast<page_entry *>(log_image + sizeof(step_log_header)),
            static_cast<std::size_t>(header.page_count)};
        log.nodes = std::span<const node_entry>{
            reinterpret_cast<const node_entry *>(log_image + sizeof(step_log_header) + pages_bytes),
            static_cast<std::size_t>(header.node_count)};
        log.siblings = std::span<const machine_hash>{
            reinterpret_cast<const machine_hash *>(log_image + sizeof(step_log_header) + pages_bytes + nodes_bytes),
            static_cast<std::size_t>(header.sibling_count)};

        validate_pages_ordered(log.pages);
        validate_nodes_aligned(log.nodes);
        validate_entries_ordered_and_disjoint(log.pages, log.nodes);
        // Pre-state integrity: the recomputed root must match the header's claim.
        if (log.compute_root_hash(false) != log.root_hash_before) {
            THROW(std::runtime_error, "initial root hash mismatch");
        }
        return log;
    }

    /// \brief Try to find a witnessed page by its physical address.
    /// \param paddr_page Page-aligned physical address.
    /// \return Pointer to the page entry if witnessed, nullptr otherwise.
    page_entry *try_find_page(uint64_t paddr_page) const {
        const auto page_index = paddr_page >> AR_LOG2_PAGE_SIZE;
        auto it = std::ranges::lower_bound(pages, page_index, std::ranges::less{},
            [](const auto &page) { return page.index; });
        if (it != pages.end() && it->index == page_index) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Find a witnessed page by its physical address, or throw if absent.
    page_entry *find_page(uint64_t paddr_page) const {
        auto *page_log = try_find_page(paddr_page);
        if (page_log == nullptr) {
            THROW(std::runtime_error, "required page not found");
        }
        return page_log;
    }

    /// \brief Try to find a subtree-write node by its start address.
    /// \param address Subtree start address.
    /// \return Pointer to the node entry if present, nullptr otherwise.
    const node_entry *try_find_node(uint64_t address) const {
        auto it =
            std::ranges::lower_bound(nodes, address, std::ranges::less{}, [](const auto &n) { return n.address; });
        if (it != nodes.end() && it->address == address) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Recompute the machine root hash from the witnessed tree.
    /// \param use_after When false, use each node's hash_before (reconstructs root_hash_before). When
    /// true, use each node's hash_after (reconstructs root_hash_after).
    /// \details Hashes each page lazily into its scratch slot, then walks the tree with three cursors
    /// (pages, nodes, siblings) to produce the root hash. A zero scratch slot means "needs hashing":
    /// pages arrive zero on the wire (validate_pages_ordered enforces it), and every replay accessor
    /// re-zeros a page's slot when it writes the page. So the before-replay call hashes all pages and
    /// the after-replay call rehashes only the pages the operation actually wrote -- clean pages keep
    /// the hash the before pass validated against root_hash_before, which is byte-identical post-step.
    /// Nodes pick between their two precomputed hashes based on \p use_after.
    machine_hash compute_root_hash(bool use_after) const {
        static const machine_hash all_zeros{};
        for (auto &page : pages) {
            if (page.hash == all_zeros) {
                merkle_tree_hash(hash_function, page.data, AR_PAGE_SIZE, reinterpret_cast<hash_type>(&page.hash));
            }
        }
        size_t next_page = 0;
        size_t next_node = 0;
        size_t next_sibling = 0;
        auto root_hash = compute_subtree(0, HASH_TREE_LOG2_ROOT_SIZE - AR_LOG2_PAGE_SIZE, next_page, next_node,
            next_sibling, use_after);
        if (next_page != pages.size()) {
            THROW(std::runtime_error, "too many pages in log");
        }
        if (next_node != nodes.size()) {
            THROW(std::runtime_error, "too many nodes in log");
        }
        if (next_sibling != siblings.size()) {
            THROW(std::runtime_error, "too many sibling hashes in log");
        }
        if (use_after) {
            check_all_nodes_consumed();
        }
        return root_hash;
    }

    /// \brief Assert every witnessed node was consumed by a semantic write during replay.
    /// \details Post-state soundness: a node's hash_after is folded into root_hash_after verbatim, so
    /// every node must be produced by a semantic write (cmio supra-page or uarch reset); an unconsumed
    /// node would inject an arbitrary post-state subtree. compute_root_hash(true) calls this. A reverted
    /// operation substitutes a recorded root instead of recomputing it, so it must call this explicitly
    /// to keep the same guarantee.
    void check_all_nodes_consumed() const {
        if (consumed_node_count != nodes.size()) {
            THROW(std::runtime_error, "unconsumed node in step log");
        }
    }

private:
    /// \brief Validate that witnessed pages are strictly ascending by index, with a zero scratch slot.
    /// \param pages Witnessed pages, in wire order.
    /// \throw runtime_error if a page index is not strictly increasing or a scratch hash is non-zero.
    static void validate_pages_ordered(std::span<const page_entry> pages) {
        static const machine_hash all_zeros{};
        for (size_t i = 0; i < pages.size(); i++) {
            if (i > 0 && pages[i - 1].index >= pages[i].index) {
                THROW(std::runtime_error, "invalid log format: page index is not in increasing order");
            }
            // find_page binary-searches by page.data address, so data pointers must increase monotonically.
            // Unreachable while all pages share one contiguous buffer (data order then follows the index order
            // above), but it fail-closes should pages ever be allocated independently.
            // LCOV_EXCL_START
            if (i > 0 && +pages[i - 1].data >= +pages[i].data) {
                THROW(std::runtime_error, "invalid log format: page data is not in increasing order");
            }
            // LCOV_EXCL_STOP
            if (pages[i].hash != all_zeros) {
                THROW(std::runtime_error, "invalid log format: page scratch hash area is not zero");
            }
        }
    }

    /// \brief Validate each node's size range and address alignment.
    /// \param nodes Subtree-write nodes, in wire order.
    /// \throw runtime_error if a node's log2 size is out of range or its address is not aligned to its size.
    /// \details Runs before the disjointness walk, which relies on log2_size <= HASH_TREE_LOG2_ROOT_SIZE
    /// to keep its 1 << log2_size shift well defined.
    static void validate_nodes_aligned(std::span<const node_entry> nodes) {
        for (const auto &n : nodes) {
            if (n.log2_size <= HASH_TREE_LOG2_PAGE_SIZE || n.log2_size > HASH_TREE_LOG2_ROOT_SIZE) {
                THROW(std::runtime_error, "invalid log format: node log2 size out of range");
            }
            // A node at HASH_TREE_LOG2_ROOT_SIZE must have address 0; UINT64_C(1) <<
            // HASH_TREE_LOG2_ROOT_SIZE would be undefined. Mirrors
            // StepLog.validateEntriesOrderedAndDisjoint's alignment special case.
            if (n.log2_size == HASH_TREE_LOG2_ROOT_SIZE) {
                if (n.address != 0) {
                    THROW(std::runtime_error, "invalid log format: node address not aligned to its size");
                }
            } else {
                const auto node_size = UINT64_C(1) << n.log2_size;
                if ((n.address & (node_size - 1)) != 0) {
                    THROW(std::runtime_error, "invalid log format: node address not aligned to its size");
                }
            }
        }
    }

    /// \brief Validate that the combined pages+nodes stream is strictly ascending and disjoint.
    /// \param pages Witnessed pages, ascending by index.
    /// \param nodes Subtree-write nodes, with validated sizes (see validate_nodes_aligned).
    /// \throw runtime_error if any entry starts before the previous entry's end.
    /// \details Same algorithm as StepLog.validateEntriesOrderedAndDisjoint in the Solidity replayer.
    /// 128-bit arithmetic so an entry ending at 2^64 cannot overflow.
    static void validate_entries_ordered_and_disjoint(std::span<const page_entry> pages,
        std::span<const node_entry> nodes) {
        size_t pi = 0; // page index cursor
        size_t ni = 0; // node index cursor
        // end of the previous entry (page or node), for overlap checking
        uint128_t prev_end = 0;
        while (pi < pages.size() || ni < nodes.size()) {
            uint128_t entry_start{}; // page or node used in this iteration
            uint128_t entry_end{};   // page or node used in this iteration
            bool take_page = false;  // take next entry from pages or nodes
            if (pi >= pages.size()) {
                take_page = false;
            } else if (ni >= nodes.size()) {
                take_page = true;
            } else {
                const uint128_t page_start = static_cast<uint128_t>(pages[pi].index) << AR_LOG2_PAGE_SIZE;
                take_page = page_start < nodes[ni].address;
            }
            if (take_page) {
                entry_start = static_cast<uint128_t>(pages[pi].index) << AR_LOG2_PAGE_SIZE;
                entry_end = entry_start + (static_cast<uint128_t>(1) << AR_LOG2_PAGE_SIZE);
                ++pi;
            } else {
                entry_start = nodes[ni].address;
                entry_end = entry_start + (static_cast<uint128_t>(1) << nodes[ni].log2_size);
                ++ni;
            }
            if (entry_start < prev_end) {
                THROW(std::runtime_error, "invalid log format: page or node overlaps a previous entry");
            }
            prev_end = entry_end;
        }
    }

    /// \brief Recursively reconstruct the root hash of the subtree rooted at page_index.
    /// \param page_index Index of the first page in the subtree.
    /// \param log2_page_count Log2 of the number of pages in the subtree.
    /// \param next_page Cursor into the pages array; advances past each page consumed.
    /// \param next_node Cursor into the nodes array; advances past each node consumed.
    /// \param next_sibling Cursor into the sibling hashes; advances past each sibling consumed.
    /// \param use_after Selects which of a node's two stored hashes to use (see compute_root_hash).
    /// \return Root hash of the subtree at (page_index, log2_page_count).
    machine_hash compute_subtree(uint64_t page_index, int log2_page_count, size_t &next_page, size_t &next_node,
        size_t &next_sibling, bool use_after) const {
        const auto subtree_start_addr = page_index << AR_LOG2_PAGE_SIZE;
        const auto subtree_log2_size = log2_page_count + AR_LOG2_PAGE_SIZE;
        const auto page_count = UINT64_C(1) << log2_page_count;
        const auto subtree_end_page_index = page_index + page_count;
        // next unconsumed page / node is inside this subtree?
        const bool page_in = next_page < pages.size() && pages[next_page].index < subtree_end_page_index;
        // shift node address into page-index units to compare with subtree_end_page_index
        const bool node_in =
            next_node < nodes.size() && (nodes[next_node].address >> AR_LOG2_PAGE_SIZE) < subtree_end_page_index;
        if (!page_in && !node_in) {
            if (next_sibling >= siblings.size()) {
                THROW(std::runtime_error, "too few sibling hashes in log");
            }
            return siblings[next_sibling++];
        }
        if (node_in && nodes[next_node].address == subtree_start_addr &&
            nodes[next_node].log2_size == static_cast<uint64_t>(subtree_log2_size)) {
            const auto &n = nodes[next_node++];
            return use_after ? n.hash_after : n.hash_before;
        }
        if (log2_page_count > 0) {
            auto left = compute_subtree(page_index, log2_page_count - 1, next_page, next_node, next_sibling, use_after);
            const auto halfway_page_index = page_index + (page_count >> 1);
            auto right =
                compute_subtree(halfway_page_index, log2_page_count - 1, next_page, next_node, next_sibling, use_after);
            machine_hash hash{};
            concat_hash(hash_function, reinterpret_cast<hash_type>(&left), reinterpret_cast<hash_type>(&right),
                reinterpret_cast<hash_type>(&hash));
            return hash;
        }
        // Leaf: must be a page (nodes have log2_size > page, so can't fit in a single-page subtree)
        return pages[next_page++].hash;
    }
};

// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

} // namespace cartesi

#endif
