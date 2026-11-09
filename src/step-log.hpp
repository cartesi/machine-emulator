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
///     step_log_header header;                    // 40 bytes
///     slice_entry     slices[header.slice_count]; // 56 bytes each
///     unsigned char   data[sum of slice sizes];   // contents, in table order
///     node_entry      nodes[header.node_count];   // 48 bytes each
///     machine_hash    siblings[header.sibling_count];
///
/// A slice is an aligned power-of-two piece of one page whose bytes the log carries.
/// The wire allows sizes 2^5..2^12; the recorder's minimum slice size is 2^9.
/// The uarch registers are witnessed as a unit: a slice in their page covers all 35 of them,
/// so a verifier can load and store them in one pass instead of looking each one up.
/// All multi-byte integer fields use little-endian byte order; there is no endian marker.
/// Decode allocates nothing and borrows the image, so the same code can run in uarch and zkVM guests.

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
/// Version 5.
constexpr std::array<char, 8> STEP_LOG_SIGNATURE = {'C', 'T', 'S', 'I', 5, 0, 0, 0};

/// \brief Fixed-size prefix of a step log buffer.
struct PACKED step_log_header {
    std::array<char, 8> signature; ///< STEP_LOG_SIGNATURE (magic + version + reserved)
    uint64_t hash_function;        ///< Value of hash_function_type used by the state tree
    uint64_t slice_count;          ///< Number of variable-size slices
    uint64_t node_count;           ///< Number of entries in the nodes array
    uint64_t sibling_count;        ///< Number of entries in the siblings array
};
static_assert(sizeof(step_log_header) == 40, "expected wire size of step_log_header is 40 bytes");

/// \brief Witnessed slice with a scratch slot: zero on the wire, current hash during replay.
struct PACKED slice_entry {
    uint64_t address;     ///< Byte address, aligned to the slice size
    uint64_t log2_size;   ///< Log2 of the slice size, 5..12
    uint64_t data_offset; ///< Offset of the slice's bytes in the data region
    machine_hash hash;    ///< Current slice hash; zero means it needs hashing

    uint64_t size() const {
        return UINT64_C(1) << log2_size;
    }
    uint64_t page_index() const {
        return address >> AR_LOG2_PAGE_SIZE;
    }
};
static_assert(sizeof(slice_entry) == 56, "expected wire size of slice_entry is 56 bytes");

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

/// \brief Slice sizes a verifier accepts: any size from one word up to a page, or whole pages only.
/// \details The wire format is the same either way. Uarch, reset and cmio replay accept any size
/// and bounds-check each access against its slice; machine replay accepts whole pages only and
/// skips that check.
enum class step_log_shape { any_size, whole_pages };

/// \brief Parsed binary step log: the witnessed tree plus the header values it was decoded from.
/// \details Borrows the caller's log image; decoding performs no heap allocation.
struct step_log {
    machine_hash root_hash_before{}; ///< Root hash before the step, recomputed from the witnessed tree at decode
    hash_function_type hash_function{hash_function_type::keccak256}; ///< Hash function used for the step log
    std::span<slice_entry> slices;          ///< Witnessed slices; scratch slot is the current hash, zero when stale
    unsigned char *data{};                  ///< Start of the contiguous slice data region
    std::span<node_entry> nodes;            ///< Subtree-write nodes, kept current during replay
    std::span<const machine_hash> siblings; ///< Sibling hashes for untouched subtrees

    /// \brief Decode and validate a binary step log without allocating memory.
    /// \param log_image Pointer to the step log buffer. The returned step_log keeps spans into it,
    /// so it must outlive the step_log.
    /// \param log_size Size of the log bytes.
    /// \param required_hash_function When set, reject a log declaring any other hash function.
    /// Verifiers whose protocol fixes the hash function (the on-chain replayer is Keccak-256 only)
    /// pass it so a mismatched log fails here instead of at the initial-root recompute.
    /// \param shape Accepted witness shape; machine replay requires whole pages.
    /// \return A validated step_log with root_hash_before recomputed from the witnessed tree.
    /// \throw runtime_error if the log is malformed.
    /// \details Mirrors StepLog.decode in the Solidity replayer.
    static step_log decode(unsigned char *log_image, uint64_t log_size,
        std::optional<hash_function_type> required_hash_function = std::nullopt,
        step_log_shape shape = step_log_shape::any_size) {
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
        auto *cursor = log_image + sizeof(step_log_header);
        const uint64_t slice_table_bytes = header.slice_count * sizeof(slice_entry);
        log.slices = {reinterpret_cast<slice_entry *>(cursor), static_cast<size_t>(header.slice_count)};
        cursor += slice_table_bytes;
        remaining -= slice_table_bytes;
        uint128_t data_size = 0;
        for (const auto &entry : log.slices) {
            if (entry.log2_size < HASH_TREE_LOG2_WORD_SIZE || entry.log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
                THROW(std::runtime_error, "invalid log format: slice log2 size out of range");
            }
            if (shape == step_log_shape::whole_pages && entry.log2_size != HASH_TREE_LOG2_PAGE_SIZE) {
                THROW(std::runtime_error, "machine replay requires whole-page witnesses");
            }
            const uint64_t size = entry.size();
            if ((entry.address & (size - 1)) != 0) {
                THROW(std::runtime_error, "invalid log format: slice address not aligned to its size");
            }
            if (data_size != entry.data_offset) {
                THROW(std::runtime_error, "slice data offset mismatch");
            }
            data_size += size;
        }
        if (data_size > remaining) {
            THROW(std::runtime_error, "truncated slice data");
        }
        log.data = cursor;
        cursor += static_cast<uint64_t>(data_size);
        remaining -= static_cast<uint64_t>(data_size);
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
        validate_slices_ordered(log.slices);
        validate_nodes_aligned(log.nodes);
        validate_entries_ordered_and_disjoint(log.slices, log.nodes);
        log.root_hash_before = log.compute_root_hash();
        return log;
    }

    /// \brief The slice witnessed in the page containing \p paddr, or nullptr.
    /// \param paddr Any physical address inside the page.
    /// \return Pointer to the slice entry if witnessed, nullptr otherwise.
    slice_entry *try_find_slice(uint64_t paddr) const {
        const auto page_index = paddr >> AR_LOG2_PAGE_SIZE;
        auto it = std::ranges::lower_bound(slices, page_index, std::ranges::less{},
            [](const auto &slice) { return slice.page_index(); });
        if (it != slices.end() && it->page_index() == page_index) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Same, throwing "required slice not found" when absent.
    slice_entry *find_slice(uint64_t paddr) const {
        auto *slice = try_find_slice(paddr);
        if (slice == nullptr) {
            THROW(std::runtime_error, "required slice not found");
        }
        return slice;
    }

    /// \brief Pointer to a validated slice's bytes in the borrowed data region.
    unsigned char *get_data(const slice_entry &entry) const {
        return data + entry.data_offset;
    }

    /// \brief Checked pointer to \p length bytes at physical address \p paddr in \p entry.
    unsigned char *find_data(const slice_entry &entry, uint64_t paddr, uint64_t length) const {
        const uint64_t offset = paddr - entry.address;
        // Subtraction also rejects addresses below the slice, without an overflowing end address.
        if (length > entry.size() || offset > entry.size() - length) {
            THROW(std::runtime_error, "access outside witnessed slice");
        }
        return get_data(entry) + offset;
    }

    /// \brief Checked pointer to \p length bytes at physical address \p paddr within a witnessed slice.
    unsigned char *find_data(uint64_t paddr, uint64_t length) const {
        return find_data(*find_slice(paddr), paddr, length);
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
    /// \details Node slots are used as they stand; replayed bulk writes keep them current.
    machine_hash compute_root_hash() const {
        static const machine_hash all_zeros{};
        for (auto &slice : slices) {
            // zero means stale: decode hashes every slice, a replayed write re-zeroes its slot,
            // finish rehashes only those
            if (slice.hash == all_zeros) {
                merkle_tree_hash(hash_function, get_data(slice), slice.size(),
                    reinterpret_cast<hash_type>(&slice.hash));
            }
        }
        size_t next_slice = 0;
        size_t next_node = 0;
        size_t next_sibling = 0;
        auto root_hash = compute_subtree_hash(0, HASH_TREE_LOG2_ROOT_SIZE, next_slice, next_node, next_sibling);
        if (next_slice != slices.size()) {
            THROW(std::runtime_error, "too many slices in log");
        }
        if (next_node != nodes.size()) {
            THROW(std::runtime_error, "too many nodes in log");
        }
        if (next_sibling != siblings.size()) {
            THROW(std::runtime_error, "too many sibling hashes in log");
        }
        return root_hash;
    }

    /// \brief Throw unless the caller-claimed root hash before matches the witnessed tree.
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
        if (header.slice_count == 0) {
            THROW(std::runtime_error, "slice count is zero");
        }
        if (header.slice_count > (log_size - sizeof(step_log_header)) / sizeof(slice_entry) ||
            header.slice_count > SIZE_MAX) {
            THROW(std::runtime_error, "slice count exceeds step log size");
        }
        return header;
    }

    /// \brief Validate address order, disjointness, page uniqueness and zero scratch hashes.
    static void validate_slices_ordered(std::span<const slice_entry> slices) {
        const machine_hash zero{};
        for (size_t i = 0; i < slices.size(); ++i) {
            if (i > 0) {
                const auto &prev = slices[i - 1];
                if (prev.address >= slices[i].address) {
                    THROW(std::runtime_error, "invalid log format: slice addresses not in increasing order");
                }
                if (static_cast<uint128_t>(prev.address) + prev.size() > slices[i].address) {
                    THROW(std::runtime_error, "invalid log format: slice overlaps previous slice");
                }
                if (prev.page_index() == slices[i].page_index()) {
                    THROW(std::runtime_error, "invalid log format: multiple slices in the same page");
                }
            }
            if (slices[i].hash != zero) {
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

    /// \brief Validate that the combined slices+nodes stream is strictly ascending and disjoint.
    /// \param slices Witnessed slices, ascending by address.
    /// \param nodes Subtree-write nodes, with validated sizes (see validate_nodes_aligned).
    /// \throw runtime_error if any entry starts before the previous entry's end.
    /// \details Same algorithm as StepLog.validateEntriesOrderedAndDisjoint in the Solidity replayer.
    /// 128-bit arithmetic so an entry ending at 2^64 cannot overflow.
    static void validate_entries_ordered_and_disjoint(std::span<const slice_entry> slices,
        std::span<const node_entry> nodes) {
        size_t next_slice = 0;
        size_t next_node = 0;
        uint128_t prev_end = 0;
        while (next_slice < slices.size() || next_node < nodes.size()) {
            uint128_t entry_start{};
            uint128_t entry_end{};
            bool take_slice = false;
            if (next_slice >= slices.size()) {
                take_slice = false;
            } else if (next_node >= nodes.size()) {
                take_slice = true;
            } else {
                const auto slice_start = static_cast<uint128_t>(slices[next_slice].address);
                take_slice = slice_start < nodes[next_node].address;
            }
            if (take_slice) {
                entry_start = static_cast<uint128_t>(slices[next_slice].address);
                entry_end = entry_start + slices[next_slice].size();
                ++next_slice;
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

    /// \brief Hash of the subtree at (address, log2_size), consuming the slice, node and sibling cursors in address
    /// order.
    machine_hash compute_subtree_hash(uint64_t address, uint64_t log2_size, size_t &next_slice, size_t &next_node,
        size_t &next_sibling) const {
        const uint128_t end = static_cast<uint128_t>(address) + (static_cast<uint128_t>(1) << log2_size);
        const bool slice_in = next_slice < slices.size() && static_cast<uint128_t>(slices[next_slice].address) < end;
        const bool node_in = next_node < nodes.size() && static_cast<uint128_t>(nodes[next_node].address) < end;
        if (!slice_in && !node_in) {
            if (next_sibling >= siblings.size()) {
                THROW(std::runtime_error, "too few sibling hashes in log");
            }
            return siblings[next_sibling++];
        }
        if (node_in && nodes[next_node].address == address && nodes[next_node].log2_size == log2_size) {
            return nodes[next_node++].hash;
        }
        if (slice_in && slices[next_slice].address == address && slices[next_slice].log2_size == log2_size) {
            return slices[next_slice++].hash;
        }
        if (log2_size <= HASH_TREE_LOG2_WORD_SIZE) {
            THROW(std::runtime_error, "invalid log format: slice or node not aligned to a subtree");
        }
        const auto left = compute_subtree_hash(address, log2_size - 1, next_slice, next_node, next_sibling);
        const auto right = compute_subtree_hash(address + (UINT64_C(1) << (log2_size - 1)), log2_size - 1, next_slice,
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
