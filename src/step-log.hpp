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
/// \brief On-disk layout and parsed form of a binary step log.
///
/// A step log is a fixed-size header followed by three variable-length arrays:
///
///     step_log_header header;
///     page_entry      pages[header.page_count];
///     node_entry      nodes[header.node_count];
///     machine_hash    siblings[header.sibling_count];
///
/// All multi-byte integer fields use host (little-endian) byte order; there is no endian marker.
/// Heap-free so it builds in the risc0 guest; the host and zkVM hash backends are selected by
/// ZKARCHITECTURE.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ranges>
#include <span>

#include "address-range-constants.hpp"
#include "compiler-defines.hpp"
#include "hash-tree-constants.hpp"
#include "i-hasher.hpp"
#include "machine-hash.hpp"
#include "throw.hpp"
#include "uint128.hpp"
#include "variant-hasher.hpp"

namespace cartesi {

/// \brief Signature at the start of a binary step log file: magic + version + reserved.
/// Version byte is 3: all array counts live in the header.
constexpr std::array<char, 8> STEP_LOG_SIGNATURE = {'C', 'T', 'S', 'I', 3, 0, 0, 0};

/// \brief Fixed-size prefix of a step log file.
/// \details The log is only the witness: it carries no root hash claims and no cycle count.
/// The root hash before is recomputed from the witnessed tree at decode time; the cycle count
/// and the root hash after are the caller's, driving the replay and checking its result.
struct PACKED step_log_header {
    std::array<char, 8> signature; ///< STEP_LOG_SIGNATURE (magic + version + reserved)
    uint64_t hash_function;        ///< Value of hash_function_type used to hash the log
    uint64_t page_count;           ///< Number of entries in the pages array
    uint64_t node_count;           ///< Number of entries in the nodes array
    uint64_t sibling_count;        ///< Number of entries in the siblings array
};
static_assert(sizeof(step_log_header) == 40, "expected wire size of step_log_header is 40 bytes");

/// \brief One touched page of memory recorded in a step log.
/// \details The recorder writes \p hash zero-filled; the replayer fills it with
/// merkle_tree_hash(data) at verify time and uses it to reconstruct the root.
struct PACKED page_entry {
    uint64_t index;                          ///< Page index (byte address >> log2_page_size)
    unsigned char data[HASH_TREE_PAGE_SIZE]; ///< Page contents as of first touch
    machine_hash hash;                       ///< Scratch slot; must be zero on disk
};
static_assert(sizeof(page_entry) == 4136, "expected wire size of page_entry is 4136 bytes");
// The page wire format is written by the recorder using HASH_TREE_* and reconstructed by
// the replayer using AR_*; the two must denote the same page geometry, or recorder and
// replayer would disagree on page-index mapping and page data length.
static_assert(HASH_TREE_LOG2_PAGE_SIZE == AR_LOG2_PAGE_SIZE,
    "step-log page wire format requires the hash-tree and address-range page log2 sizes to match");
static_assert(HASH_TREE_PAGE_SIZE == AR_PAGE_SIZE,
    "step-log page_entry.data size must equal the AR_PAGE_SIZE used by the replayer");

/// \brief One subtree-write (bulk write spanning > 1 page) recorded in a step log.
/// \details A node is a subtree whose contents are not witnessed, only its hash. The wire value
/// is the subtree hash before the step; a replayed bulk write overwrites the slot with the hash
/// computed from the write's own arguments, so the slot always holds the subtree's current hash.
struct PACKED node_entry {
    uint64_t address;   ///< Subtree start address; must be aligned to 2^log2_size
    uint64_t log2_size; ///< log2 of the subtree size; must be > page-log2 and <= root-log2
    machine_hash hash;  ///< Subtree hash, kept current during replay
};
static_assert(sizeof(node_entry) == 48, "expected wire size of node_entry is 48 bytes");

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
/// mutable so the root recompute can rehash each page into its scratch slot.
struct step_log {
    machine_hash root_hash_before{}; ///< Root hash before the step, recomputed from the witnessed tree at decode
    hash_function_type hash_function{hash_function_type::keccak256}; ///< Hash function used for the step log
    std::span<page_entry> pages;            ///< Witnessed pages, rehashed into their scratch slots
    std::span<node_entry> nodes;            ///< Subtree-write nodes, kept current during replay
    std::span<const machine_hash> siblings; ///< Sibling hashes for untouched subtrees

    /// \brief Decode and validate a binary step log.
    /// \param log_image Pointer to the step log file bytes. The returned step_log keeps spans into it,
    /// so it must outlive the step_log.
    /// \param log_size Size of the log bytes.
    /// \param required_hash_function When set, reject a log declaring any other hash function.
    /// Verifiers whose protocol fixes the hash function (the on-chain replayer is Keccak-256 only)
    /// pass it so a mismatched log fails here instead of at the initial-root recompute.
    /// \return A validated step_log with root_hash_before recomputed from the witnessed tree.
    /// \throw runtime_error if the log is malformed.
    /// \details Mirrors StepLog.decode in the Solidity replayer: header parse, per-count size bounds,
    /// page ordering, per-node alignment/range, the combined pages+nodes disjointness walk, and the
    /// initial-root recompute.
    static step_log decode(unsigned char *log_image, uint64_t log_size,
        std::optional<hash_function_type> required_hash_function = std::nullopt) {
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
        if (required_hash_function && log.hash_function != *required_hash_function) {
            THROW(std::runtime_error, "step log hash function not supported by this verifier");
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
        if (header.page_count == 0) {
            THROW(std::runtime_error, "page count is zero");
        }
        log.pages = std::span<page_entry>{reinterpret_cast<page_entry *>(log_image + sizeof(step_log_header)),
            static_cast<std::size_t>(header.page_count)};
        log.nodes =
            std::span<node_entry>{reinterpret_cast<node_entry *>(log_image + sizeof(step_log_header) + pages_bytes),
                static_cast<std::size_t>(header.node_count)};
        log.siblings = std::span<const machine_hash>{
            reinterpret_cast<const machine_hash *>(log_image + sizeof(step_log_header) + pages_bytes + nodes_bytes),
            static_cast<std::size_t>(header.sibling_count)};

        validate_pages_ordered(log.pages);
        validate_nodes_aligned(log.nodes);
        validate_entries_ordered_and_disjoint(log.pages, log.nodes);
        log.root_hash_before = log.compute_root_hash();
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
    node_entry *try_find_node(uint64_t address) const {
        auto it =
            std::ranges::lower_bound(nodes, address, std::ranges::less{}, [](const auto &n) { return n.address; });
        if (it != nodes.end() && it->address == address) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Recompute the machine root hash from the witnessed tree's current state.
    /// \details A zero scratch slot means "needs hashing": pages arrive zero on the wire and replay
    /// accessors re-zero a page's slot on write, so the decode-time pass hashes every page and the
    /// finish-time pass rehashes only the pages the operation wrote. Node slots are used as they
    /// stand; replayed bulk writes keep them current.
    machine_hash compute_root_hash() const {
        static const machine_hash all_zeros{};
        for (auto &page : pages) {
            if (page.hash == all_zeros) {
                merkle_tree_hash(hash_function, page.data, AR_PAGE_SIZE, reinterpret_cast<hash_type>(&page.hash));
            }
        }
        size_t next_page = 0;
        size_t next_node = 0;
        size_t next_sibling = 0;
        auto root_hash =
            compute_subtree(0, HASH_TREE_LOG2_ROOT_SIZE - AR_LOG2_PAGE_SIZE, next_page, next_node, next_sibling);
        if (next_page != pages.size()) {
            THROW(std::runtime_error, "too many pages in log");
        }
        if (next_node != nodes.size()) {
            THROW(std::runtime_error, "too many nodes in log");
        }
        if (next_sibling != siblings.size()) {
            THROW(std::runtime_error, "too many sibling hashes in log");
        }
        return root_hash;
    }

    /// \brief Assert a caller-claimed pre-operation root hash matches the witnessed tree.
    /// \param claimed Root hash the caller expects the operation to start from.
    void check_root_hash_before(const_machine_hash_view claimed) const {
        if (!std::ranges::equal(claimed, root_hash_before)) {
            THROW(std::runtime_error, "root hash before does not match step log");
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
            // find_page binary-searches by page.data address. In the current implementation all pages
            // share one contiguous buffer, so data order follows the index order above; the check only
            // matters if pages are ever allocated independently.
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
        size_t next_page = 0;
        size_t next_node = 0;
        uint128_t prev_end = 0;
        while (next_page < pages.size() || next_node < nodes.size()) {
            uint128_t entry_start{};
            uint128_t entry_end{};
            bool take_page = false;
            if (next_page >= pages.size()) {
                take_page = false;
            } else if (next_node >= nodes.size()) {
                take_page = true;
            } else {
                const uint128_t page_start = static_cast<uint128_t>(pages[next_page].index) << AR_LOG2_PAGE_SIZE;
                take_page = page_start < nodes[next_node].address;
            }
            if (take_page) {
                entry_start = static_cast<uint128_t>(pages[next_page].index) << AR_LOG2_PAGE_SIZE;
                entry_end = entry_start + (static_cast<uint128_t>(1) << AR_LOG2_PAGE_SIZE);
                ++next_page;
            } else {
                entry_start = nodes[next_node].address;
                entry_end = entry_start + (static_cast<uint128_t>(1) << nodes[next_node].log2_size);
                ++next_node;
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
    /// \return Root hash of the subtree at (page_index, log2_page_count).
    machine_hash compute_subtree(uint64_t page_index, int log2_page_count, size_t &next_page, size_t &next_node,
        size_t &next_sibling) const {
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
            return nodes[next_node++].hash;
        }
        if (log2_page_count > 0) {
            auto left = compute_subtree(page_index, log2_page_count - 1, next_page, next_node, next_sibling);
            const auto halfway_page_index = page_index + (page_count >> 1);
            auto right = compute_subtree(halfway_page_index, log2_page_count - 1, next_page, next_node, next_sibling);
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
