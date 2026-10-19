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

#ifndef REPLAY_STEP_STATE_ACCESS_HPP
#define REPLAY_STEP_STATE_ACCESS_HPP

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <optional>
#include <ranges>
#include <type_traits>
#include <utility>
#include <variant>

#include "address-range-constants.hpp"
#include "assert-printf.hpp"
#include "compiler-defines.hpp"
#include "hash-tree-constants.hpp"
#include "host-addr.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "mock-address-range.hpp"
#include "no-step-log-dumper.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"
#include "rejected-manual-yield.hpp"
#include "riscv-constants.hpp"
#include "scoped-note.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"
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
class replay_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <typename Dumper>
struct i_state_access_fast_addr<replay_step_state_access<Dumper>> {
    using type = uint64_t;
};

/// \brief Provides machine state from a step log buffer
/// \tparam Dumper Dump sink: no_step_log_dumper by default, step_log_dumper for dump_send_cmio_response.
/// Only the accesses send_cmio_response performs reach the sink; the interpreter's word accesses do not.
template <typename Dumper = no_step_log_dumper>
// NOLINTNEXTLINE(misc-multiple-inheritance)
class replay_step_state_access :
    public i_state_access<replay_step_state_access<Dumper>>,
    public i_accept_scoped_notes<replay_step_state_access<Dumper>>,
    public i_prefer_shadow_state<replay_step_state_access<Dumper>> {
public:
    // Physical offsets keep slice bounds enforceable even when the interpreter hits the TLB.
    struct replay_tlb_slot {
        uint64_t vaddr_page{TLB_UNVERIFIED_PAGE};
        uint64_t vp_offset{};
    };
    using replay_tlb_state = std::array<std::array<replay_tlb_slot, TLB_SET_SIZE>, TLB_NUM_SETS_>;
    // Keep resolved values in the shared context: interpreter helpers copy the accessor.
    struct replay_slice_cache {
        uint64_t address{};
        uint64_t size{};
        unsigned char *data{};
        machine_hash *hash{};

        void assign(const slice_entry &slice) {
            address = slice.address;
            size = slice.size();
            data = slice.data;
            hash = slice.hash;
        }
    };
    struct context {
        step_log log;                           ///< Parsed step log (witnessed tree)
        mock_address_ranges ars{};              ///< Array of address ranges
        replay_tlb_state tlb{};                 ///< Hot TLB cache for validated entries
        replay_slice_cache memory_slice{};      ///< Last resolved memory slice
        replay_slice_cache shadow_regs_slice{}; ///< Resolved shadow-register slice
        [[no_unique_address]] Dumper dumper{};  ///< Receives the dump; the no-op sink takes no space
    };

private:
    context &m_context; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    // \brief Construct a replay_step_state_access object from a log image
    // \param context The context object to be filled with the replay step log data
    // \param log_image Image of the step log file
    // \param log_size The size of the log data
    // \param slice_storage Caller-owned descriptors; must outlive this replay
    // \param required_hash_function When set, reject a log declaring any other hash function
    // (see step_log::decode); machine step logs are otherwise hash-function agnostic
    // \throw runtime_error if the log data is invalid
    replay_step_state_access(context &context, unsigned char *log_image, uint64_t log_size,
        std::span<slice_entry> slice_storage, std::optional<hash_function_type> required_hash_function = std::nullopt) :
        m_context(context) {
        m_context.log = step_log::decode(log_image, log_size, slice_storage, required_hash_function);
        // Decode guarantees a nonempty table of slices at least 32 bytes long.
        // Seeding both caches avoids an empty-cache branch on every word access.
        m_context.memory_slice.assign(m_context.log.pages.front());
        m_context.shadow_regs_slice = m_context.memory_slice;
        // initialize hot TLB entries as unverified
        for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
            for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
                m_context.tlb[set_index][slot_index].vaddr_page = TLB_UNVERIFIED_PAGE;
                m_context.tlb[set_index][slot_index].vp_offset = 0;
            }
        }
    }

    // \brief Finish the replay and return the obtained root hash after
    // \param revert_on_rejected_yield Whether a machine left paused on a manual rejected yield makes the
    // recorded revert root hash the canonical post-operation hash.
    // \details A step or uarch reset that leaves the machine paused on a rejected input reverts: its
    // canonical post-operation hash is the recorded revert root hash. A send_cmio_response is not a step;
    // when it no-ops on an already-rejected machine the transition is the identity, so it never reverts
    // and its post-operation hash is the recomputed machine root hash.
    machine_hash finish(bool revert_on_rejected_yield = true) {
        if (revert_on_rejected_yield && is_rejected_manual_yield(*this)) {
            return this->read_revert_root_hash();
        }
        return m_context.log.compute_root_hash();
    }

private:
    NO_INLINE unsigned char *resolve_slice_miss(replay_slice_cache &cache, uint64_t paddr, uint64_t length) const {
        const auto &slice = *m_context.log.find_page(paddr);
        auto *data = slice.find_data(paddr, length);
        cache.assign(slice);
        return data;
    }

    /// Physical addresses survive TLB hits; subtraction checks the full access on every hit.
    template <typename T>
    unsigned char *find_cached_data(replay_slice_cache &cache, uint64_t paddr) const {
        static_assert(sizeof(T) <= HASH_TREE_WORD_SIZE);
        const uint64_t offset = paddr - cache.address;
        // Every cached slice is validated and at least 32 bytes: size - sizeof(T) cannot underflow.
        if (offset > cache.size - sizeof(T)) [[unlikely]] {
            return resolve_slice_miss(cache, paddr, sizeof(T));
        }
        return cache.data + offset;
    }

    static_assert(sizeof(shadow_registers_state) <= AR_PAGE_SIZE, "shadow registers must fit in a single page");

    host_addr get_shadow_reg_host_addr(shadow_registers_what what) const {
        const auto paddr = static_cast<uint64_t>(what);
        return cast_ptr_to_host_addr(find_cached_data<uint64_t>(m_context.shadow_regs_slice, paddr));
    }

    uint64_t read_pmas_istart(uint64_t index) const {
        const auto haddr = cast_ptr_to_host_addr(m_context.log.find_data(pmas_get_abs_addr(index, pmas_what::istart)));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t read_pmas_ilength(uint64_t index) const {
        const auto haddr = cast_ptr_to_host_addr(m_context.log.find_data(pmas_get_abs_addr(index, pmas_what::ilength)));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<replay_step_state_access>;

    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        const auto val = aliased_aligned_read<uint64_t>(get_shadow_reg_host_addr(what));
        m_context.dumper.read(nullptr, static_cast<uint64_t>(what), val);
        return val;
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        const auto haddr = get_shadow_reg_host_addr(what);
        *m_context.shadow_regs_slice.hash = machine_hash{}; // written slice: rehash on the after-root pass
        m_context.dumper.write(nullptr, static_cast<uint64_t>(what), aliased_aligned_read<uint64_t>(haddr), val);
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    machine_hash do_read_revert_root_hash() const {
        machine_hash hash{};
        std::copy_n(m_context.log.find_data(AR_SHADOW_REVERT_ROOT_HASH_START, hash.size()), hash.size(), hash.begin());
        return hash;
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<replay_step_state_access>;

    /// Retain the physical address until the checked memory access, including on TLB hits.
    uint64_t do_get_faddr(uint64_t paddr, uint64_t /* pma_index */ = 0) const {
        return paddr;
    }

    // LCOV_EXCL_START
    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }
    // LCOV_EXCL_STOP

    // LCOV_EXCL_START
    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }
    // LCOV_EXCL_STOP

    std::pair<uint64_t, uint64_t> do_read_pma_bounds(uint64_t index) const {
        assert(index < PMA_MAX);
        // Preserve snapshots already selected by lookup or TLB validation.
        auto &mock = m_context.ars[index];
        if (!std::holds_alternative<std::monostate>(mock)) {
            const auto &ar = get_mock_address_range(mock, [](const char *err) { THROW(std::runtime_error, err); });
            return {ar.get_start(), ar.get_length()};
        }
        return {read_pmas_istart(index) & PMA_ISTART_START_MASK, read_pmas_ilength(index)};
    }

    address_range &do_read_pma(uint64_t index) const {
        if (index >= PMA_MAX) [[unlikely]] {
            static address_range sentinel{"sentinel"};
            return sentinel;
        }
        // record_step_state_access will have recorded the access to istart and
        // ilength in its implementation of read_pmas_entry.
        const uint64_t istart = read_pmas_istart(index);
        const uint64_t ilength = read_pmas_ilength(index);
        const auto i = static_cast<size_t>(index);
        const auto abrt = [](const char *err) { THROW(std::runtime_error, err); };
        if (std::holds_alternative<std::monostate>(m_context.ars[i])) {
            m_context.ars[i] = make_mock_address_range(istart, ilength, abrt);
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return get_mock_address_range(m_context.ars[index], abrt);
    }

    template <typename T, typename A>
    void do_read_memory_word(uint64_t paddr, uint64_t /* pma_index */, T *pval) const {
        *pval = aliased_aligned_read<T, A>(find_cached_data<T>(m_context.memory_slice, paddr));
    }

    template <typename T, typename A>
    void do_write_memory_word(uint64_t paddr, uint64_t /* pma_index */, T val) const {
        auto *data = find_cached_data<T>(m_context.memory_slice, paddr);
        *m_context.memory_slice.hash = machine_hash{};
        aliased_aligned_write<T, A>(data, val);
    }

    template <typename TYPE>
    auto read_tlb_field(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) const {
        const auto paddr = shadow_tlb_get_abs_addr(set_index, slot_index, what);
        const auto haddr = cast_ptr_to_host_addr(m_context.log.find_data(paddr, sizeof(TYPE)));
        return aliased_aligned_read<TYPE>(haddr);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return m_context.tlb[SET][slot_index].vaddr_page;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vf_offset(uint64_t slot_index) const {
        return m_context.tlb[SET][slot_index].vp_offset;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <typename TYPE>
    auto write_tlb_field(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what, TYPE val) const {
        const auto paddr = shadow_tlb_get_abs_addr(set_index, slot_index, what);
        const auto haddr = cast_ptr_to_host_addr(m_context.log.find_data(paddr, sizeof(TYPE)));
        *m_context.log.find_page(paddr)->hash = machine_hash{};
        aliased_aligned_write<TYPE>(haddr, val);
    }

    template <TLB_set_index SET>
    uint64_t do_init_hot_tlb_slot(uint64_t slot_index) const {
        auto &hot_slot = m_context.tlb[SET][slot_index];
        // Only act on unverified entries
        if (hot_slot.vaddr_page != TLB_UNVERIFIED_PAGE) {
            return hot_slot.vaddr_page;
        }
        // Read shadow entry from the log
        const auto vaddr_page = read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::vaddr_page);
        const auto vp_offset = read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::vp_offset);
        const auto pma_index = read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::pma_index);
        const auto zero_padding = read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::zero_padding_);
        const auto &ar = do_read_pma(pma_index);
        if (shadow_tlb_verify_slot(SET, vaddr_page, vp_offset, zero_padding, ar) == TLB_INVALID_PAGE) {
            hot_slot.vaddr_page = TLB_INVALID_PAGE;
            return TLB_INVALID_PAGE;
        }
        // Require a witnessed slice for the target page (throws if absent); each access still checks its bounds.
        (void) m_context.log.find_page(vaddr_page + vp_offset);
        hot_slot.vaddr_page = vaddr_page;
        hot_slot.vp_offset = vp_offset;
        return vaddr_page;
    }

    template <TLB_set_index SET>
    constexpr bool do_verify_cold_tlb_slot(uint64_t /*slot_index*/) const {
        return true;
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index) const {
        assert(vaddr_page != TLB_UNVERIFIED_PAGE);
        write_tlb_field(SET, slot_index, shadow_tlb_what::vaddr_page, vaddr_page);
        write_tlb_field(SET, slot_index, shadow_tlb_what::vp_offset, vp_offset);
        write_tlb_field(SET, slot_index, shadow_tlb_what::pma_index, pma_index);
        write_tlb_field(SET, slot_index, shadow_tlb_what::zero_padding_, UINT64_C(0));
        m_context.tlb[SET][slot_index].vaddr_page = TLB_UNVERIFIED_PAGE;
        m_context.tlb[SET][slot_index].vp_offset = 0;
    }

    // LCOV_EXCL_START
    bool do_putchar(uint8_t /*c*/) const { // NOLINT(readability-convert-member-functions-to-static)
        return false;
    }
    // LCOV_EXCL_STOP

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
    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "replay_step_state_access";
    }

    // -----
    // i_accept_scoped_notes interface implementation
    // -----
    friend i_accept_scoped_notes<replay_step_state_access>;

    // A real scoped_note only when there is a dumper to receive the brackets. With the no-op sink the
    // interpreter's notes must cost the zkVM guest nothing, which the base default guarantees (it still
    // honors DUMP_SCOPED_NOTE builds)
    auto do_make_scoped_note(const char *text) const {
        if constexpr (std::is_same_v<Dumper, no_step_log_dumper>) {
            return i_accept_scoped_notes<replay_step_state_access>::do_make_scoped_note(text);
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
