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

#ifndef STEP_LOG_LAYOUT_HPP
#define STEP_LOG_LAYOUT_HPP

/// \file
/// \brief On-disk layout of a binary step log file.
///
/// A step log is a fixed-size header followed by three variable-length arrays:
///
///     step_log_header header;
///     page_entry      pages[header.page_count];
///     node_entry      nodes[header.node_count];
///     machine_hash    siblings[header.sibling_count];
///
/// All multi-byte integer fields use host (little-endian) byte order; there is no endian marker.

#include <array>
#include <cstdint>

#include "address-range-constants.hpp"
#include "compiler-defines.hpp"
#include "hash-tree-constants.hpp"
#include "machine-hash.hpp"

namespace cartesi {

/// \brief Signature at the start of a binary step log file: magic + version + reserved.
/// Version byte is 3: all array counts live in the header.
constexpr std::array<char, 8> STEP_LOG_SIGNATURE = {'C', 'T', 'S', 'I', 3, 0, 0, 0};

/// \brief Fixed-size prefix of a step log file.
struct PACKED step_log_header {
    std::array<char, 8> signature;  ///< STEP_LOG_SIGNATURE (magic + version + reserved)
    machine_hash root_hash_before;  ///< Machine root hash before the step
    uint64_t requested_cycle_count; ///< Cycle count requested by the caller; 0 for operations without one
    machine_hash root_hash_after;   ///< Machine root hash after the step
    uint64_t hash_function;         ///< Value of hash_function_type used to hash the log
    uint64_t page_count;            ///< Number of entries in the pages array
    uint64_t node_count;            ///< Number of entries in the nodes array
    uint64_t sibling_count;         ///< Number of entries in the siblings array
};
static_assert(sizeof(step_log_header) == 112, "expected wire size of step_log_header is 112 bytes");

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
/// \details hash_before / hash_after are the subtree hashes around the bulk write; the
/// replayer picks one depending on whether it is reconstructing root_hash_before or
/// root_hash_after.
struct PACKED node_entry {
    uint64_t address;         ///< Subtree start address; must be aligned to 2^log2_size
    uint64_t log2_size;       ///< log2 of the subtree size; must be > page-log2 and <= root-log2
    machine_hash hash_before; ///< Subtree hash captured before the bulk write
    machine_hash hash_after;  ///< Subtree hash after the bulk write
};
static_assert(sizeof(node_entry) == 80, "expected wire size of node_entry is 80 bytes");

} // namespace cartesi

#endif
