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
/// \brief Binary layout and parsed form of a step log.
///
/// A step log is a fixed-size header followed by three variable-length arrays:
///
///     step_log_header header;
///     { slice_entry_header; data[1 << log2_size]; machine_hash; } slices[header.page_count];
///     node_entry      nodes[header.node_count];
///     machine_hash    siblings[header.sibling_count];
///
/// All multi-byte integer fields use host (little-endian) byte order; there is no endian marker.
/// Slice descriptors use caller-provided storage; contents and hashes remain in the log image.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ranges>
#include <span>
#include <utility>

#include "address-range-constants.hpp"
#include "compiler-defines.hpp"
#include "hash-tree-constants.hpp"
#include "i-hasher.hpp"
#include "machine-hash.hpp"
#include "step-log-hash.hpp"
#include "throw.hpp"
#include "uint128.hpp"

namespace cartesi {

/// \brief Signature at the start of a binary step log buffer: magic + version + reserved.
/// Version byte is 4: variable-size page slices, with all counts in the header.
constexpr std::array<char, 8> STEP_LOG_SIGNATURE = {'C', 'T', 'S', 'I', 4, 0, 0, 0};

/// \brief Fixed-size prefix of a step log buffer.
/// \details The root hash before is recomputed from the witnessed tree at decode time; the cycle
/// count and the root hash after are the caller's, driving the replay and checking its result.
struct PACKED step_log_header {
    std::array<char, 8> signature; ///< STEP_LOG_SIGNATURE (magic + version + reserved)
    uint64_t hash_function;        ///< Value of hash_function_type used by the state tree
    uint64_t page_count;           ///< Number of variable-size slices
    uint64_t node_count;           ///< Number of entries in the nodes array
    uint64_t sibling_count;        ///< Number of entries in the siblings array
};
static_assert(sizeof(step_log_header) == 40, "expected wire size of step_log_header is 40 bytes");

/// \brief Fixed prefix of a variable-size slice entry on the wire.
struct PACKED slice_entry_header {
    uint64_t address;   ///< Byte address, aligned to the slice size
    uint64_t log2_size; ///< 5..12; followed by data and a 32-byte scratch hash
};
static_assert(sizeof(slice_entry_header) == 16, "expected wire size of slice_entry_header is 16 bytes");

/// \brief Descriptor for one witnessed slice, keyed by its enclosing page.
/// \details Data and scratch hash point into the caller-owned log image.
struct slice_entry {
    uint64_t address;
    uint64_t log2_size;
    unsigned char *data;
    machine_hash *hash;

    uint64_t size() const {
        return UINT64_C(1) << log2_size;
    }
    uint64_t page_index() const {
        return address >> AR_LOG2_PAGE_SIZE;
    }

    unsigned char *find_data(uint64_t paddr, uint64_t length) const {
        const uint64_t offset = paddr - address;
        // Subtraction also rejects addresses below the slice, without an overflowing end address.
        if (length > size() || offset > size() - length) {
            THROW(std::runtime_error, "access outside witnessed slice");
        }
        return data + offset;
    }
};

static_assert(HASH_TREE_LOG2_PAGE_SIZE == AR_LOG2_PAGE_SIZE,
    "step-log page lookup requires matching hash-tree and address-range page sizes");

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

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

/// \brief Parsed binary step log: the witnessed tree plus the header values it was decoded from.
/// \details Borrows the caller's slice descriptors and log image; decoding performs no heap allocation.
struct step_log {
    machine_hash root_hash_before{}; ///< Root hash before the step, recomputed from the witnessed tree at decode
    hash_function_type hash_function{hash_function_type::keccak256}; ///< Hash function used for the step log
    std::span<slice_entry> pages;           ///< Witnessed slices, rehashed into their scratch slots
    std::span<node_entry> nodes;            ///< Subtree-write nodes, kept current during replay
    std::span<const machine_hash> siblings; ///< Sibling hashes for untouched subtrees

    /// \brief Read the slice count, bounded by log length, before allocating descriptor storage.
    static size_t get_slice_count(const unsigned char *log_image, uint64_t log_size) {
        return static_cast<size_t>(read_header(log_image, log_size).page_count);
    }

    /// \brief Decode and validate a binary step log without allocating memory.
    /// \param log_image Pointer to the step log buffer. The returned step_log keeps spans into it,
    /// so it must outlive the step_log.
    /// \param log_size Size of the log bytes.
    /// \param slice_storage Caller-owned descriptors; must outlive the returned step_log.
    /// \param required_hash_function When set, reject a log declaring any other hash function.
    /// Verifiers whose protocol fixes the hash function (the on-chain replayer is Keccak-256 only)
    /// pass it so a mismatched log fails here instead of at the initial-root recompute.
    /// \return A validated step_log with root_hash_before recomputed from the witnessed tree.
    /// \throw runtime_error if the log is malformed.
    /// \details Mirrors StepLog.decode in the Solidity replayer: header parse, per-count size bounds,
    /// page ordering, per-node alignment/range, the combined pages+nodes disjointness walk, and the
    /// initial-root recompute.
    /// Solidity's per-count caps have no C++ wire-format counterpart; callers bound descriptor storage.
    static step_log decode(unsigned char *log_image, uint64_t log_size, std::span<slice_entry> slice_storage,
        std::optional<hash_function_type> required_hash_function = std::nullopt) {
        step_log log;
        const auto header = read_header(log_image, log_size);
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
        uint64_t remaining = log_size - sizeof(step_log_header);
        if (header.page_count > slice_storage.size()) {
            THROW(std::runtime_error, "slice count exceeds descriptor storage capacity");
        }
        auto *cursor = log_image + sizeof(step_log_header);
        log.pages = slice_storage.first(static_cast<size_t>(header.page_count));
        for (uint64_t i = 0; i < header.page_count; ++i) {
            if (remaining < sizeof(slice_entry_header)) {
                THROW(std::runtime_error, "truncated slice header");
            }
            slice_entry_header entry{};
            std::memcpy(&entry, cursor, sizeof(entry));
            cursor += sizeof(entry);
            remaining -= sizeof(entry);
            if (entry.log2_size < HASH_TREE_LOG2_WORD_SIZE || entry.log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
                THROW(std::runtime_error, "invalid log format: slice log2 size out of range");
            }
            const uint64_t size = UINT64_C(1) << entry.log2_size;
            if ((entry.address & (size - 1)) != 0) {
                THROW(std::runtime_error, "invalid log format: slice address not aligned to its size");
            }
            if (remaining < size + sizeof(machine_hash)) {
                THROW(std::runtime_error, "truncated slice data or hash");
            }
            log.pages[i] = {entry.address, entry.log2_size, cursor, reinterpret_cast<machine_hash *>(cursor + size)};
            cursor += size + sizeof(machine_hash);
            remaining -= size + sizeof(machine_hash);
        }
        if (header.node_count > remaining / sizeof(node_entry)) {
            THROW(std::runtime_error, "node count exceeds step log size");
        }
        const uint64_t nodes_bytes = header.node_count * sizeof(node_entry);
        log.nodes = {reinterpret_cast<node_entry *>(cursor), static_cast<size_t>(header.node_count)};
        cursor += nodes_bytes;
        remaining -= nodes_bytes;
        if (remaining % sizeof(machine_hash) != 0 || header.sibling_count != remaining / sizeof(machine_hash)) {
            THROW(std::runtime_error, "step log byte length does not match counts");
        }
        log.siblings = {reinterpret_cast<const machine_hash *>(cursor), static_cast<size_t>(header.sibling_count)};
        validate_pages_ordered(log.pages);
        validate_nodes_aligned(log.nodes);
        validate_entries_ordered_and_disjoint(log.pages, log.nodes);
        log.root_hash_before = log.compute_root_hash();
        return log;
    }

    /// \brief Try to find a witnessed page by physical address.
    /// \param paddr_page Any physical address inside the page.
    /// \return Pointer to the page entry if witnessed, nullptr otherwise.
    const slice_entry *try_find_page(uint64_t paddr_page) const {
        const auto page_index = paddr_page >> AR_LOG2_PAGE_SIZE;
        auto it = std::ranges::lower_bound(pages, page_index, std::ranges::less{},
            [](const auto &page) { return page.page_index(); });
        if (it != pages.end() && it->page_index() == page_index) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Find a witnessed page by any physical address inside it, or throw if absent.
    const slice_entry *find_page(uint64_t paddr_page) const {
        auto *page_log = try_find_page(paddr_page);
        if (page_log == nullptr) {
            THROW(std::runtime_error, "required page not found");
        }
        return page_log;
    }

    /// \brief Checked pointer to \p length bytes at physical address \p paddr within a witnessed slice.
    unsigned char *find_data(uint64_t paddr, uint64_t length = sizeof(uint64_t)) const {
        return find_page(paddr)->find_data(paddr, length);
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

    /// \brief Find the subtree-write node at \p address spanning 2^log2_size bytes, or throw if absent.
    node_entry *find_node(uint64_t address, int log2_size) const {
        auto *node = try_find_node(address);
        if (node == nullptr || !std::cmp_equal(node->log2_size, log2_size)) {
            THROW(std::runtime_error, "required node not found");
        }
        return node;
    }

    /// \brief Recompute the machine root hash from the witnessed tree's current state.
    /// \details A zero scratch slot means "needs hashing": pages arrive zero on the wire and replay
    /// accessors re-zero a page's slot on write, so the decode-time pass hashes every page and the
    /// finish-time pass rehashes only the pages the operation wrote. Node slots are used as they
    /// stand; replayed bulk writes keep them current.
    machine_hash compute_root_hash() const {
        static const machine_hash all_zeros{};
        for (auto &page : pages) {
            if (*page.hash == all_zeros) {
                merkle_tree_hash(hash_function, page.data, page.size(), reinterpret_cast<hash_type>(page.hash));
            }
        }
        size_t next_page = 0;
        size_t next_node = 0;
        size_t next_sibling = 0;
        auto root_hash = compute_subtree(0, HASH_TREE_LOG2_ROOT_SIZE, next_page, next_node, next_sibling);
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
    static step_log_header read_header(const unsigned char *log_image, uint64_t log_size) {
        // Parse header with a stack-local copy to avoid alignment UB on the log buffer
        if (log_size < sizeof(step_log_header)) {
            THROW(std::runtime_error, "step log shorter than header");
        }
        step_log_header header{};
        std::memcpy(&header, log_image, sizeof(header));
        if (header.signature != STEP_LOG_SIGNATURE) {
            THROW(std::runtime_error, "invalid step log signature");
        }
        constexpr uint64_t min_slice_bytes =
            sizeof(slice_entry_header) + (UINT64_C(1) << HASH_TREE_LOG2_WORD_SIZE) + sizeof(machine_hash);
        if (header.page_count == 0) {
            THROW(std::runtime_error, "slice count is zero");
        }
        if (header.page_count > (log_size - sizeof(step_log_header)) / min_slice_bytes ||
            header.page_count > SIZE_MAX) {
            THROW(std::runtime_error, "slice count exceeds step log size");
        }
        return header;
    }

    /// \brief Validate address order, disjointness, page uniqueness and zero scratch hashes.
    static void validate_pages_ordered(std::span<const slice_entry> pages) {
        const machine_hash zero{};
        for (size_t i = 0; i < pages.size(); ++i) {
            if (i > 0) {
                const auto &prev = pages[i - 1];
                if (prev.address >= pages[i].address) {
                    THROW(std::runtime_error, "invalid log format: slice addresses not in increasing order");
                }
                if (static_cast<uint128_t>(prev.address) + prev.size() > pages[i].address) {
                    THROW(std::runtime_error, "invalid log format: slice overlaps previous slice");
                }
                if (prev.page_index() == pages[i].page_index()) {
                    THROW(std::runtime_error, "invalid log format: multiple slices in the same page");
                }
            }
            if (*pages[i].hash != zero) {
                THROW(std::runtime_error, "invalid log format: slice scratch hash area is not zero");
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
    /// \param pages Witnessed slices, ascending by address.
    /// \param nodes Subtree-write nodes, with validated sizes (see validate_nodes_aligned).
    /// \throw runtime_error if any entry starts before the previous entry's end.
    /// \details Same algorithm as StepLog.validateEntriesOrderedAndDisjoint in the Solidity replayer.
    /// 128-bit arithmetic so an entry ending at 2^64 cannot overflow.
    static void validate_entries_ordered_and_disjoint(std::span<const slice_entry> pages,
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
                const uint128_t page_start = static_cast<uint128_t>(pages[next_page].address);
                take_page = page_start < nodes[next_node].address;
            }
            if (take_page) {
                entry_start = static_cast<uint128_t>(pages[next_page].address);
                entry_end = entry_start + pages[next_page].size();
                ++next_page;
            } else {
                entry_start = nodes[next_node].address;
                entry_end = entry_start + (static_cast<uint128_t>(1) << nodes[next_node].log2_size);
                ++next_node;
            }
            if (entry_start < prev_end) {
                THROW(std::runtime_error, "invalid log format: slice or node overlaps a previous entry");
            }
            prev_end = entry_end;
        }
    }

    /// \brief Reconstruct a subtree with cursors into slices, bulk-write nodes and siblings.
    machine_hash compute_subtree(uint64_t address, int log2_size, size_t &next_page, size_t &next_node,
        size_t &next_sibling) const {
        const uint128_t end = static_cast<uint128_t>(address) + (static_cast<uint128_t>(1) << log2_size);
        const bool page_in = next_page < pages.size() && static_cast<uint128_t>(pages[next_page].address) < end;
        const bool node_in = next_node < nodes.size() && static_cast<uint128_t>(nodes[next_node].address) < end;
        if (!page_in && !node_in) {
            if (next_sibling >= siblings.size()) {
                THROW(std::runtime_error, "too few sibling hashes in log");
            }
            return siblings[next_sibling++];
        }
        if (node_in && nodes[next_node].address == address && std::cmp_equal(nodes[next_node].log2_size, log2_size)) {
            return nodes[next_node++].hash;
        }
        if (page_in && pages[next_page].address == address && std::cmp_equal(pages[next_page].log2_size, log2_size)) {
            return *pages[next_page++].hash;
        }
        if (log2_size <= HASH_TREE_LOG2_WORD_SIZE) {
            THROW(std::runtime_error, "invalid log format: slice or node crosses subtree boundary");
        }
        const auto left = compute_subtree(address, log2_size - 1, next_page, next_node, next_sibling);
        const auto right = compute_subtree(address + (UINT64_C(1) << (log2_size - 1)), log2_size - 1, next_page,
            next_node, next_sibling);
        machine_hash hash{};
        concat_hash(hash_function, reinterpret_cast<const_hash_type>(&left), reinterpret_cast<const_hash_type>(&right),
            reinterpret_cast<hash_type>(&hash));
        return hash;
    }
};

// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

} // namespace cartesi

#endif
