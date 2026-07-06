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
#include <ranges>
#include <variant>

#include "address-range-constants.hpp"
#include "assert-printf.hpp"
#include "compiler-defines.hpp"
#include "hash-tree-constants.hpp"
#include "host-addr.hpp"
#include "hot-tlb.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "mock-address-range.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"
#include "rejected-manual-yield.hpp"
#include "riscv-constants.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"
#include "step-log-layout.hpp"
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
/// builds in the risc0 guest.
static machine_hash merkle_subtree_hash_padded(hash_function_type hash_function, const unsigned char *data,
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
static void merkle_tree_hash_padded(hash_function_type hash_function, const unsigned char *data, uint64_t data_length,
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

class replay_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<replay_step_state_access> {
    using type = host_addr;
};

// \brief Provides machine state from a step log file
class replay_step_state_access :
    public i_state_access<replay_step_state_access>,
    public i_accept_scoped_notes<replay_step_state_access>,
    public i_prefer_shadow_state<replay_step_state_access> {
public:
    struct context {
        step_log log;              ///< Parsed step log (witnessed tree)
        mock_address_ranges ars{}; ///< Array of address ranges
        hot_tlb_state tlb{};       ///< Hot TLB cache for validated entries
    };

private:
    context &m_context;                              // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    mutable page_entry *m_shadow_regs_page{nullptr}; ///< cache shadow registers page

public:
    // \brief Construct a replay_step_state_access object from a log image
    // \param context The context object to be filled with the replay step log data
    // \param log_image Image of the step log file
    // \param log_size The size of the log data
    // \throw runtime_error if the initial root hash does not match or the log data is invalid
    replay_step_state_access(context &context, unsigned char *log_image, uint64_t log_size) : m_context(context) {
        m_context.log = step_log::decode(log_image, log_size);
        // initialize hot TLB entries as unverified
        for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
            for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
                m_context.tlb[set_index][slot_index].vaddr_page = TLB_UNVERIFIED_PAGE;
                m_context.tlb[set_index][slot_index].vh_offset = host_addr{0};
            }
        }
    }

    // \brief Finish the replay and return the obtained root hash after
    // \param revert_on_rejected_yield Whether a machine left paused on a manual rejected yield makes the
    // recorded revert root hash the canonical post-operation hash.
    // \throw runtime_error if the final root hash does not match the step log header
    // \details A step or uarch reset that leaves the machine paused on a rejected input reverts: its
    // canonical post-operation hash is the recorded revert root hash. A send_cmio_response is not a step;
    // when it no-ops on an already-rejected machine the transition is the identity, so it never reverts
    // and its post-operation hash is the recomputed machine root hash.
    machine_hash finish(bool revert_on_rejected_yield = true) {
        machine_hash obtained_root_hash{};
        if (revert_on_rejected_yield && is_rejected_manual_yield(*this)) {
            // Revert substitutes the recorded root instead of recomputing it; still assert no node was
            // left unconsumed (compute_root_hash makes this assertion on the non-reverted path).
            m_context.log.check_all_nodes_consumed();
            obtained_root_hash = read_revert_root_hash();
        } else {
            obtained_root_hash = m_context.log.compute_root_hash(true);
        }
        if (obtained_root_hash != m_context.log.root_hash_after) {
            THROW(std::runtime_error, "final root hash mismatch");
        }
        return obtained_root_hash;
    }

private:
    /// \brief Try to find a page in the logged data by the host address of its data
    /// \param haddr Host address of page data
    /// \return A pointer to the page_entry structure if found, nullptr otherwise
    page_entry *try_find_page(host_addr haddr_page) const {
        auto it = std::ranges::lower_bound(m_context.log.pages, haddr_page, std::ranges::less{},
            [](const auto &page) { return cast_ptr_to_host_addr(page.data); });
        if (it != m_context.log.pages.end() && cast_ptr_to_host_addr(it->data) == haddr_page) {
            return &(*it);
        }
        return nullptr;
    }

    page_entry *find_page(host_addr haddr_page) const {
        auto *page_log = try_find_page(haddr_page);
        // The only caller is do_write_tlb, which receives vh_offset from the interpreter's page walk.
        // The interpreter computes vh_offset from do_get_faddr, which already called find_page(uint64_t)
        // successfully for the same page. Since vaddr_page + vh_offset points to that page's data,
        // the host_addr lookup will always find it.
        // LCOV_EXCL_START
        if (page_log == nullptr) {
            THROW(std::runtime_error, "required page not found");
        }
        // LCOV_EXCL_STOP
        return page_log;
    }

    /// \brief Zero the cached scratch hash of the page containing \p haddr so compute_root_hash
    /// rehashes it on the after-root pass.
    /// \details A write through a raw host address only knows the address, not the page entry. Page
    /// data pointers strictly ascend, so the containing page is the last one whose data is <= haddr.
    /// \p haddr always falls inside a witnessed page (the interpreter resolved it via do_get_faddr,
    /// which find_page'd it), so the lookup never steps before the first page.
    void invalidate_page_hash(host_addr haddr) const {
        auto it = std::ranges::upper_bound(m_context.log.pages, haddr, std::ranges::less{},
            [](const auto &page) { return cast_ptr_to_host_addr(page.data); });
        (--it)->hash = machine_hash{};
    }

    static_assert(sizeof(shadow_registers_state) <= AR_PAGE_SIZE, "shadow registers must fit in a single page");

    host_addr get_shadow_reg_host_addr(shadow_registers_what what) const {
        const auto paddr = static_cast<uint64_t>(what);
        const auto page = paddr & ~PAGE_OFFSET_MASK;
        const auto offset = paddr & PAGE_OFFSET_MASK;
        if (m_shadow_regs_page == nullptr) {
            m_shadow_regs_page = m_context.log.find_page(page);
        }
        return cast_ptr_to_host_addr(m_shadow_regs_page->data) + offset;
    }

    uint64_t read_shadow_reg(shadow_registers_what what) const {
        return aliased_aligned_read<uint64_t>(get_shadow_reg_host_addr(what));
    }

    void write_shadow_reg(shadow_registers_what what, uint64_t val) const {
        const auto haddr = get_shadow_reg_host_addr(what);
        m_shadow_regs_page->hash = machine_hash{}; // written page: rehash on the after-root pass
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t read_pmas_istart(uint64_t index) const {
        const auto haddr = do_get_faddr(pmas_get_abs_addr(index, pmas_what::istart));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t read_pmas_ilength(uint64_t index) const {
        const auto haddr = do_get_faddr(pmas_get_abs_addr(index, pmas_what::ilength));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<replay_step_state_access>;

    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        return read_shadow_reg(what);
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        write_shadow_reg(what, val);
    }

    machine_hash do_read_revert_root_hash() const {
        constexpr uint64_t paddr = AR_SHADOW_REVERT_ROOT_HASH_START;
        const auto *page_log = m_context.log.find_page(paddr & ~PAGE_OFFSET_MASK);
        machine_hash hash{};
        std::copy_n(page_log->data + (paddr & PAGE_OFFSET_MASK), hash.size(), hash.begin());
        return hash;
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<replay_step_state_access>;

    /// \brief Convert physical address to host address
    /// \param paddr The physical address
    /// \return Host address
    host_addr do_get_faddr(uint64_t paddr, uint64_t /* pma_index */ = 0) const {
        // This assumes the corresponding page has been touched
        // (replay_step_state_access makes sure of it for any address we try to convert)
        const auto paddr_page = paddr & ~PAGE_OFFSET_MASK;
        auto *page_log = m_context.log.find_page(paddr_page);
        const auto offset = paddr & PAGE_OFFSET_MASK;
        return cast_ptr_to_host_addr(page_log->data) + offset;
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
    void do_read_memory_word(host_addr haddr, uint64_t /* pma_index */, T *pval) const {
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t /* pma_index */, T val) const {
        invalidate_page_hash(haddr);
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <typename TYPE>
    auto read_tlb_field(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) const {
        const auto haddr = do_get_faddr(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        return aliased_aligned_read<TYPE>(haddr);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return m_context.tlb[SET][slot_index].vaddr_page;
    }

    template <TLB_set_index SET>
    host_addr do_read_tlb_vf_offset(uint64_t slot_index) const {
        return m_context.tlb[SET][slot_index].vh_offset;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return read_tlb_field<uint64_t>(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <typename TYPE>
    auto write_tlb_field(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what, TYPE val) const {
        const auto haddr = do_get_faddr(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        invalidate_page_hash(haddr);
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
        if (shadow_tlb_verify_slot(vaddr_page, vp_offset, zero_padding, ar) == TLB_INVALID_PAGE) {
            hot_slot.vaddr_page = TLB_INVALID_PAGE;
            return TLB_INVALID_PAGE;
        }
        // Find the target page in the log and compute vh_offset pointing into log data
        const auto paddr_page = vaddr_page + vp_offset;
        const auto haddr_page = cast_ptr_to_host_addr(m_context.log.find_page(paddr_page)->data);
        const auto vh_offset = haddr_page - vaddr_page;
        // Verification passed -- promote to hot entry
        hot_slot.vaddr_page = vaddr_page;
        hot_slot.vh_offset = vh_offset;
        return vaddr_page;
    }

    template <TLB_set_index SET>
    constexpr bool do_verify_cold_tlb_slot(uint64_t /*slot_index*/) const {
        return true;
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) const {
        assert(vaddr_page != TLB_UNVERIFIED_PAGE);
        write_tlb_field(SET, slot_index, shadow_tlb_what::vaddr_page, vaddr_page);
        if (vaddr_page != TLB_INVALID_PAGE) {
            // Convert vh_offset to vp_offset for the log (shadow stores vp_offset)
            const auto paddr_page = find_page(vaddr_page + vh_offset)->index << AR_LOG2_PAGE_SIZE;
            write_tlb_field(SET, slot_index, shadow_tlb_what::vp_offset, paddr_page - vaddr_page);
        } else {
            write_tlb_field(SET, slot_index, shadow_tlb_what::vp_offset, static_cast<uint64_t>(vh_offset));
        }
        write_tlb_field(SET, slot_index, shadow_tlb_what::pma_index, pma_index);
        write_tlb_field(SET, slot_index, shadow_tlb_what::zero_padding_, UINT64_C(0));
        // Mark hot entry as unverified so next access re-validates from the log
        m_context.tlb[SET][slot_index].vaddr_page = TLB_UNVERIFIED_PAGE;
        m_context.tlb[SET][slot_index].vh_offset = host_addr{0};
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
    /// \details Supra-page writes hash (data || zero padding) and compare to the logged
    /// node's hash_after. Sub-page writes mutate the logged page in place so its new hash
    /// feeds the finish()-time root reconstruction.
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
            // Supra-page: hash data + zero-pad via pristine-streaming and compare to the logged node.
            const auto *node = m_context.log.try_find_node(paddr);
            if (node == nullptr || node->log2_size != static_cast<uint64_t>(write_length_log2_size)) {
                THROW(std::runtime_error, "write_memory_with_padding node not found in log");
            }
            machine_hash data_hash{};
            merkle_tree_hash_padded(m_context.log.hash_function, data, data_length, write_length_log2_size,
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<hash_type>(&data_hash));
            if (node->hash_after != data_hash) {
                THROW(std::runtime_error, "write_memory_with_padding does not match logged hash");
            }
            m_context.log.consumed_node_count++;
            return;
        }
        // Sub-page: mutate the logged page in place so its new hash flows into root reconstruction.
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        auto *page_log = m_context.log.find_page(paddr_page);
        page_log->hash = machine_hash{};
        const uint64_t offset = paddr & PAGE_OFFSET_MASK;
        std::copy_n(data, data_length, page_log->data + offset);
        if (write_length > data_length) {
            std::fill_n(page_log->data + offset + data_length, write_length - data_length, 0);
        }
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "replay_step_state_access";
    }
};

} // namespace cartesi

#endif
