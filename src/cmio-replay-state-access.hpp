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

#ifndef CMIO_REPLAY_STATE_ACCESS_HPP
#define CMIO_REPLAY_STATE_ACCESS_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

#include "address-range-constants.hpp"
#include "hash-tree-constants.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-hash.hpp"
#include "no-step-log-dumper.hpp"
#include "scoped-note.hpp"
#include "shadow-registers.hpp"
#include "step-log-hash.hpp"
#include "step-log.hpp"
#include "strict-aliasing.hpp"
#include "throw.hpp"

namespace cartesi {

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

/// Merkle hash of the subtree [start, start + 2^log2_size) of `data` (data_length
/// bytes, zero-padded beyond). A subtree entirely past the data collapses to the
/// precomputed pristine-zero hash for its level; a subtree entirely within falls
/// through to merkle_tree_hash; only the boundary subtree at each level recurses.
/// Mirrors HashTree.merkleSubtreeHashPadded in the Solidity replayer. Heap-free so it
/// builds in a zkVM guest.
inline machine_hash merkle_subtree_hash_padded(hash_function_type hash_function, const unsigned char *data,
    uint64_t data_length, uint64_t start, int log2_size, const machine_hash *pristine) {
    constexpr int word_log2 = HASH_TREE_LOG2_WORD_SIZE;
    constexpr uint64_t word_size = UINT64_C(1) << word_log2;
    if (start >= data_length) {
        return pristine[log2_size];
    }
    machine_hash result{};
    if (log2_size == word_log2) {
        // Leaf. One straddling the data boundary is zero-padded on the right,
        // matching the rx-buffer post-state after the copy_n + fill_n write.
        if (start + word_size <= data_length) {
            merkle_tree_hash(hash_function, data + start, word_size, reinterpret_cast<hash_type>(&result));
        } else {
            std::array<unsigned char, word_size> buf{};
            std::memcpy(buf.data(), data + start, static_cast<size_t>(data_length - start));
            merkle_tree_hash(hash_function, buf.data(), word_size, reinterpret_cast<hash_type>(&result));
        }
        return result;
    }
    const uint64_t size = UINT64_C(1) << log2_size;
    if (start + size <= data_length) {
        merkle_tree_hash(hash_function, data + start, size, reinterpret_cast<hash_type>(&result));
        return result;
    }
    const uint64_t half = size >> 1;
    const machine_hash left =
        merkle_subtree_hash_padded(hash_function, data, data_length, start, log2_size - 1, pristine);
    const machine_hash right =
        merkle_subtree_hash_padded(hash_function, data, data_length, start + half, log2_size - 1, pristine);
    concat_hash(hash_function, reinterpret_cast<const_hash_type>(&left), reinterpret_cast<const_hash_type>(&right),
        reinterpret_cast<hash_type>(&result));
    return result;
}

/// Merkle hash of `data` (data_length bytes) zero-padded to 2^write_length_log2_size.
inline void merkle_tree_hash_padded(hash_function_type hash_function, const unsigned char *data, uint64_t data_length,
    int write_length_log2_size, hash_type hash) {
    if (write_length_log2_size <= HASH_TREE_LOG2_WORD_SIZE || write_length_log2_size >= HASH_TREE_LOG2_ROOT_SIZE) {
        THROW(std::invalid_argument, "write_length_log2_size out of range");
    }
    const uint64_t write_length = UINT64_C(1) << write_length_log2_size;
    if (data_length > write_length) {
        THROW(std::invalid_argument, "data_length exceeds padded write length");
    }
    if (data == nullptr && data_length != 0) {
        THROW(std::invalid_argument, "data is null but data_length is non-zero");
    }
    constexpr int word_log2 = HASH_TREE_LOG2_WORD_SIZE;
    constexpr uint64_t word_size = UINT64_C(1) << word_log2;
    // Pristine-zero hash per level, built from merkle_tree_hash + concat_hash alone
    // (heap-free for the ZK guest).
    std::array<machine_hash, HASH_TREE_LOG2_ROOT_SIZE + 1> pristine{};
    std::array<unsigned char, word_size> zero_word{};
    merkle_tree_hash(hash_function, zero_word.data(), zero_word.size(),
        reinterpret_cast<hash_type>(&pristine[word_log2]));
    for (int k = word_log2 + 1; k <= write_length_log2_size; ++k) {
        concat_hash(hash_function, reinterpret_cast<const_hash_type>(&pristine[k - 1]),
            reinterpret_cast<const_hash_type>(&pristine[k - 1]), reinterpret_cast<hash_type>(&pristine[k]));
    }
    const machine_hash root =
        merkle_subtree_hash_padded(hash_function, data, data_length, 0, write_length_log2_size, pristine.data());
    *reinterpret_cast<machine_hash *>(hash) = root;
}

// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,misc-no-recursion)

template <typename Dumper>
class cmio_replay_state_access;

template <typename Dumper>
struct i_state_access_fast_addr<cmio_replay_state_access<Dumper>> {
    using type = uint64_t;
};

/// CMIO transitions accept slices and check each access; they never run the machine interpreter.
template <typename Dumper = no_step_log_dumper>
// NOLINTNEXTLINE(misc-multiple-inheritance)
class cmio_replay_state_access :
    public i_state_access<cmio_replay_state_access<Dumper>>,
    public i_accept_scoped_notes<cmio_replay_state_access<Dumper>>,
    public i_prefer_shadow_state<cmio_replay_state_access<Dumper>> {
public:
    struct context {
        step_log log;
        [[no_unique_address]] Dumper dumper{};
    };

private:
    context &m_context; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    cmio_replay_state_access(context &context, unsigned char *log_image, uint64_t log_size,
        std::span<slice_entry> slice_storage) :
        m_context(context) {
        m_context.log = step_log::decode(log_image, log_size, slice_storage, hash_function_type::keccak256);
    }

    machine_hash finish() {
        return m_context.log.compute_root_hash();
    }

private:
    friend i_state_access<cmio_replay_state_access>;
    friend i_prefer_shadow_state<cmio_replay_state_access>;
    friend i_accept_scoped_notes<cmio_replay_state_access>;

    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        const auto paddr = static_cast<uint64_t>(what);
        const auto val = aliased_aligned_read<uint64_t>(m_context.log.find_data(paddr));
        m_context.dumper.read(nullptr, paddr, val);
        return val;
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        const auto paddr = static_cast<uint64_t>(what);
        auto *data = m_context.log.find_data(paddr);
        *m_context.log.find_page(paddr)->hash = machine_hash{};
        m_context.dumper.write(nullptr, paddr, aliased_aligned_read<uint64_t>(data), val);
        aliased_aligned_write<uint64_t>(data, val);
    }

    /// \brief Verify a padded memory write recorded in the log.
    /// \param paddr Destination physical address; must be aligned to (1 << write_length_log2_size).
    /// \param data Pointer to source bytes.
    /// \param data_length Number of valid bytes at \p data.
    /// \param write_length_log2_size Log2 of the full write length (data + padding).
    /// \details Supra-page writes hash (data || zero padding) into the logged node's slot.
    /// Sub-page writes mutate the logged page in place so its new hash feeds the
    /// finish()-time root reconstruction.
    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) const {
        if (data == nullptr) {
            THROW(std::invalid_argument, "data is null");
        }
        const uint64_t write_length = UINT64_C(1) << write_length_log2_size;
        if (write_length < data_length) {
            THROW(std::invalid_argument, "write length is less than data length");
        }
        if (write_length_log2_size > HASH_TREE_LOG2_PAGE_SIZE) {
            // Supra-page: hash data + zero-pad via pristine-streaming into the logged node's slot.
            auto *node = m_context.log.find_node(paddr, write_length_log2_size);
            const machine_hash old_hash = node->hash;
            merkle_tree_hash_padded(m_context.log.hash_function, data, data_length, write_length_log2_size,
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<hash_type>(&node->hash));
            m_context.dumper.write_hash(nullptr, paddr, write_length_log2_size, old_hash, node->hash,
                std::span<const unsigned char>{data, data_length});
            return;
        }
        // Sub-page: mutate the logged page in place so its new hash flows into root reconstruction.
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        auto *page_log = m_context.log.find_page(paddr_page);
        *page_log->hash = machine_hash{};
        auto *slice_data = page_log->find_data(paddr, write_length);
        m_context.dumper.write_bytes(nullptr, paddr, write_length_log2_size,
            std::span<const unsigned char>{slice_data, write_length},
            std::span<const unsigned char>{data, data_length});
        std::copy_n(data, data_length, slice_data);
        if (write_length > data_length) {
            std::fill_n(slice_data + data_length, write_length - data_length, 0);
        }
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "cmio_replay_state_access";
    }

    // Preserve dump brackets; the default sink leaves no scoped-note overhead.
    auto do_make_scoped_note(const char *text) const {
        if constexpr (std::is_same_v<Dumper, no_step_log_dumper>) {
            return i_accept_scoped_notes<cmio_replay_state_access>::do_make_scoped_note(text);
        } else {
            return scoped_note{*this, text};
        }
    }

    void do_push_begin_bracket(const char *text) const {
        m_context.dumper.begin_bracket(text);
    }

    void do_push_end_bracket(const char *text) const {
        m_context.dumper.end_bracket(text);
    }
};

} // namespace cartesi
#endif
