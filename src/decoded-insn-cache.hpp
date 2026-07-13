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

#ifndef DECODED_INSN_CACHE_HPP
#define DECODED_INSN_CACHE_HPP

/// \file
/// \brief Decoded instruction page cache (host-only interpreter acceleration).
/// \details
/// The fast interpreter memoizes the fetch+decode of guest code pages: for each 2-byte
/// slot of a cached page there is an entry holding the computed-goto handler address and
/// the raw instruction bytes, so the interpreter hot loop dispatches with a single load
/// instead of insn load + decode + jump-table load.
///
/// SEMANTIC EQUIVALENCE INVARIANT: an entry is either the DECODE sentinel (which performs
/// a full generic fetch+decode) or holds exactly what fetch+decode would produce for the
/// current bytes at that host location. Every path that can mutate guest memory during
/// interpretation kills affected entries before the next dispatch from them:
///  - guest word stores: state_access::do_write_memory_word calls
///    decoded_insn_cache_store_barrier() with the store's host address;
///  - bulk/DMA writes (virtio): state_access::do_write_memory (and
///    do_write_memory_with_padding) call decoded_insn_cache_invalidate_range();
///  - anything happening between interpret() calls (host API writes, uarch, snapshot
///    restore, another machine on the same thread): interpret_loop bumps the pool
///    generation on entry, which lazily invalidates all cached pages.
/// The cache itself never writes machine state (committed or penumbra), so all state
/// transitions remain bit-identical to the non-cached interpreter, for all guests,
/// including ones that write code without fence.i.
///
/// The pool is owned by the machine object (a host-only, default-initialized member that
/// is never serialized): machines are not thread-safe by API contract, so per-machine
/// ownership is race-free, and process forks inherit a valid copy.

#include <array>
#include <cstdint>
#include <memory>

#include "riscv-constants.hpp"

namespace cartesi {

/// \brief One decoded instruction slot.
struct decoded_insn_entry final {
    const void *handler; ///< Computed-goto label inside interpret_loop<state_access>
    int32_t payload;     ///< Pre-decoded payload for specialized handlers (immediate or
                         ///< packed fields, meaning defined per handler), else 0
    uint32_t insn;       ///< Raw instruction bytes (as fetch_insn would produce)
};

static_assert(sizeof(decoded_insn_entry) == 16, "unexpected decoded_insn_entry size");

/// \brief Number of decoded page slots in the pool (direct-mapped by host page number).
constexpr uint64_t DECODED_INSN_CACHE_SIZE = 1024;

/// \brief Number of entries per decoded page (one per possible 2-byte aligned pc).
constexpr uint64_t DECODED_INSN_PAGE_ENTRIES = (PAGE_OFFSET_MASK + 1) / 2;

/// \brief A decoded guest code page.
struct decoded_insn_page final {
    std::array<decoded_insn_entry, DECODED_INSN_PAGE_ENTRIES> entries;
};

/// \brief Tag describing what a pool slot currently caches.
struct decoded_insn_page_tag final {
    uint64_t faddr_page{UINT64_C(-1)}; ///< Host address of the cached page (never -1 when valid)
    uint64_t generation{0};            ///< Pool generation this slot was installed in
};

static_assert(sizeof(decoded_insn_page_tag) == 16, "unexpected decoded_insn_page_tag size");

/// \brief Decoded instruction cache pool.
struct decoded_insn_cache final {
    /// \brief Store-barrier watch array: watch[slot] holds the host page address of the
    /// slot's cached page while it is decoded and clean, or 0 otherwise ("dirty": entries
    /// were reset by a store and none re-decoded since). Zero never matches a real host
    /// page (page 0 is never mapped), so zero-initialization means "no match".
    /// Kept as a dedicated compact array so the per-store barrier probe is one load.
    std::array<uint64_t, DECODED_INSN_CACHE_SIZE> watch{};
    std::array<decoded_insn_page_tag, DECODED_INSN_CACHE_SIZE> tags{};
    std::unique_ptr<decoded_insn_page[]> pages; ///< Lazily allocated (32MiB)
    const void *sentinel{nullptr};              ///< DECODE sentinel handler label (set per interpret_loop entry)
    uint64_t generation{0};                     ///< Bumped on every interpret_loop entry
};

/// \brief Pool slot index for a host address.
static inline uint64_t decoded_insn_cache_slot_index(uint64_t faddr) {
    return (faddr >> LOG2_PAGE_SIZE) & (DECODED_INSN_CACHE_SIZE - 1);
}

/// \brief Resets all entries of a pool slot to the DECODE sentinel.
/// \details The page memory itself is never freed or moved, so the interpreter loop may
/// keep dispatching through a stale-cached base pointer: it will simply hit sentinels.
static inline void decoded_insn_cache_reset_page(decoded_insn_cache &cache, uint64_t slot_index) {
    cache.pages[slot_index].entries.fill(decoded_insn_entry{cache.sentinel, 0, 0});
}

/// \brief Store barrier: invalidates the decoded page overlapping a guest store, if any.
/// \param cache The machine's decoded instruction cache.
/// \param faddr Host address being written.
/// \details Kept small and branch-predictable: one watch load and compare on the store
/// hot path; the [[unlikely]] body runs only when a store hits a currently-decoded and
/// clean code page. Clearing watch makes repeated stores to the same page O(1).
static inline void decoded_insn_cache_store_barrier(decoded_insn_cache &cache, uint64_t faddr) {
    const uint64_t slot_index = decoded_insn_cache_slot_index(faddr);
    if (cache.watch[slot_index] == (faddr & ~PAGE_OFFSET_MASK)) [[unlikely]] {
        decoded_insn_cache_reset_page(cache, slot_index);
        cache.watch[slot_index] = 0;
    }
}

/// \brief Range barrier: invalidates all decoded pages overlapping a host address range.
/// \details Used by bulk writes (device DMA). Rare; scans all pool watches.
static inline void decoded_insn_cache_invalidate_range(decoded_insn_cache &cache, uint64_t faddr, uint64_t length) {
    if (!cache.pages) {
        return;
    }
    const uint64_t first_page = faddr & ~PAGE_OFFSET_MASK;
    const uint64_t last_page = (faddr + length - 1) & ~PAGE_OFFSET_MASK;
    for (uint64_t slot_index = 0; slot_index < DECODED_INSN_CACHE_SIZE; ++slot_index) {
        const uint64_t watched_page = cache.watch[slot_index];
        if (watched_page != 0 && watched_page >= first_page && watched_page <= last_page) {
            decoded_insn_cache_reset_page(cache, slot_index);
            cache.watch[slot_index] = 0;
        }
    }
}

} // namespace cartesi

#endif
