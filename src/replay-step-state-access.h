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

#ifndef REPLAY_STEP_STATE_ACCESS_H
#define REPLAY_STEP_STATE_ACCESS_H

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <optional>
#include <ranges>

#include "compiler-defines.h"
#include "host-addr.h"
#include "i-accept-scoped-notes.h"
#include "i-prefer-shadow-state.h"
#include "i-state-access.h"
#include "machine-reg.h"
#include "mock-address-range.h"
#include "pmas.h"
#include "replay-step-state-access-interop.h"
#include "riscv-constants.h"
#include "shadow-registers.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "strict-aliasing.h"
#include "uarch-constants.h"
#include "uarch-defines.h"

namespace cartesi {

// \file this code is designed to be compiled for a free-standing environment.
// Environment-specific functions have the prefix "interop_" and are declared in "replay-step-state-access-interop.h"

class replay_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<replay_step_state_access> {
    using type = host_addr;
};

// \brief checks if a buffer is large enough to hold a data block of N elements of size S starting at a given offset
// \param max The maximum offset allowed
// \param current The current offset
// \param elsize The size of each element
// \param elcount The number of elements
// \param next Receives the start offset of the next data block
// \return true if the buffer is large enough and data doesn't overflow, false otherwise
static inline bool validate_and_advance_offset(uint64_t max, uint64_t current, uint64_t elsize, uint64_t elcount,
    uint64_t *next) {
    uint64_t size{};
    if (__builtin_mul_overflow(elsize, elcount, &size)) {
        return false;
    }
    if (__builtin_add_overflow(current, size, next)) {
        return false;
    }
    return *next <= max;
}

// \brief Provides machine state from a step log file
class replay_step_state_access :
    public i_state_access<replay_step_state_access>,
    public i_accept_scoped_notes<replay_step_state_access>,
    public i_prefer_shadow_state<replay_step_state_access> {
public:
    using address_type = uint64_t;
    using data_type = unsigned char[AR_PAGE_SIZE];
    using hash_type = std::array<unsigned char, interop_machine_hash_byte_size>;
    static_assert(sizeof(hash_type) == interop_machine_hash_byte_size);

    struct PACKED page_type {
        address_type index;
        data_type data;
        hash_type hash;
    };

    struct context {
        uint64_t page_count{0};             ///< Number of pages in the step log
        page_type *pages{nullptr};          ///< Array of page data
        uint64_t sibling_count{0};          ///< Number of sibling hashes in the step log
        hash_type *sibling_hashes{nullptr}; ///< Array of sibling hashes
        mock_address_ranges ars{};          ///< Array of address ranges
    };

private:
    context &m_context; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    // \brief Construct a replay_step_state_access object from a log image and expected initial root hash
    // \param context The context object to be filled with the replay step log data
    // \param log_image Image of the step log file
    // \param log_size The size of the log data
    // \param root_hash_before The expected machine root hash before the replay
    // \throw runtime_error if the initial root hash does not match or the log data is invalid
    replay_step_state_access(context &context, unsigned char *log_image, uint64_t log_size,
        const hash_type &root_hash_before) :
        m_context(context) {
        // relevant offsets in the log data
        uint64_t first_page_offset{};
        uint64_t first_sibling_offset{};
        uint64_t sibling_count_offset{};
        uint64_t end_offset{}; // end of the log data

        // set page count
        if (!validate_and_advance_offset(log_size, 0, sizeof(m_context.page_count), 1, &first_page_offset)) {
            interop_throw_runtime_error("page count past end of step log");
        }
        m_context.page_count = aliased_aligned_read<uint64_t, uint8_t>(log_image);
        if (m_context.page_count == 0) {
            interop_throw_runtime_error("page count is zero");
        }
        // set page data
        if (!validate_and_advance_offset(log_size, first_page_offset, sizeof(page_type), m_context.page_count,
                &sibling_count_offset)) {
            interop_throw_runtime_error("page data past end of step log");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_context.pages = reinterpret_cast<page_type *>(log_image + first_page_offset);

        // set sibling count and hashes
        if (!validate_and_advance_offset(log_size, sibling_count_offset, sizeof(m_context.sibling_count), 1,
                &first_sibling_offset)) {
            interop_throw_runtime_error("sibling count past end of step log");
        }
        m_context.sibling_count = aliased_aligned_read<uint64_t, uint8_t>(log_image + sibling_count_offset);

        // set sibling hashes
        if (!validate_and_advance_offset(log_size, first_sibling_offset, sizeof(hash_type), m_context.sibling_count,
                &end_offset)) {
            interop_throw_runtime_error("sibling hashes past end of step log");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_context.sibling_hashes = reinterpret_cast<hash_type *>(log_image + first_sibling_offset);

        // ensure that we read exactly the expected log size
        if (end_offset != log_size) {
            interop_throw_runtime_error("extra data at end of step log");
        }

        // ensure that the page indexes are in increasing order
        // and that the scratch hash area is all zeros
        static const hash_type all_zeros{};
        for (uint64_t i = 0; i < m_context.page_count; i++) {
            if (i > 0 && m_context.pages[i - 1].index >= m_context.pages[i].index) {
                interop_throw_runtime_error("invalid log format: page index is not in increasing order");
            }
            // In the current implementation, this check is unnecessary
            // But we may in the future change the data field to point to independently allocated pages
            // This would break the code that uses binary search to find the page based on the address of its data
            if (i > 0 && +m_context.pages[i - 1].data >= +m_context.pages[i].data) {
                interop_throw_runtime_error("invalid log format: page data is not in increasing order");
            }
            if (m_context.pages[i].hash != all_zeros) {
                interop_throw_runtime_error("invalid log format: page scratch hash area is not zero");
            }
        }
        // compute  and check the machine root hash before the replay
        auto computed_root_hash_before = compute_root_hash();
        if (computed_root_hash_before != root_hash_before) {
            interop_throw_runtime_error("initial root hash mismatch");
        }
        // relocate all tlb vh offsets into the logged page data
        relocate_tlb_vp_offset_to_vh_offset<TLB_CODE>();
        relocate_tlb_vp_offset_to_vh_offset<TLB_READ>();
        relocate_tlb_vp_offset_to_vh_offset<TLB_WRITE>();
    }

    // \brief Finish the replay and check the final machine root hash
    // \param final_root_hash The expected final machine root hash
    // \throw runtime_error if the final root hash does not match
    void finish(const hash_type &root_hash_after) {
        // reset all tlb vh offsets to zero
        // this is to mimic peek behavior of tlb pma device
        relocate_tlb_vh_offset_to_vp_offset<TLB_CODE>();
        relocate_tlb_vh_offset_to_vp_offset<TLB_READ>();
        relocate_tlb_vh_offset_to_vp_offset<TLB_WRITE>();
        // compute and check machine root hash after the replay
        auto computed_final_root_hash = compute_root_hash();
        if (computed_final_root_hash != root_hash_after) {
            interop_throw_runtime_error("final root hash mismatch");
        }
    }

private:
    /// \brief Try to find a page in the logged data by its physical address
    /// \param paddr The physical address of the page
    /// \return A pointer to the page_type structure if found, nullptr otherwise
    page_type *try_find_page(uint64_t paddr_page) const {
        const auto page_index = paddr_page >> AR_LOG2_PAGE_SIZE;
        auto pages = std::ranges::views::counted(m_context.pages, static_cast<int64_t>(m_context.page_count));
        auto it = std::ranges::lower_bound(pages, page_index, std::ranges::less{},
            [](const auto &page) { return page.index; });
        if (it != pages.end() && it->index == page_index) {
            return &(*it);
        }
        return nullptr;
    }

    /// \brief Try to find a page in the logged data by the host address of its data
    /// \param haddr Host address of page data
    /// \return A pointer to the page_type structure if found, nullptr otherwise
    page_type *try_find_page(host_addr haddr_page) const {
        auto pages = std::ranges::views::counted(m_context.pages, static_cast<int64_t>(m_context.page_count));
        auto it = std::ranges::lower_bound(pages, haddr_page, std::ranges::less{},
            [](const auto &page) { return cast_ptr_to_host_addr(page.data); });
        if (it != pages.end() && cast_ptr_to_host_addr(it->data) == haddr_page) {
            return &(*it);
        }
        return nullptr;
    }

    // \brief Relocate all TLB vp_offset fields to vh_offset
    // \details This makes the translation point directly to logged page data
    template <TLB_set_index SET>
    void relocate_tlb_vp_offset_to_vh_offset() {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto vp_offset_field_addr = shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vp_offset);
            auto *vp_offset_log = try_find_page(vp_offset_field_addr & ~PAGE_OFFSET_MASK);
            const auto vaddr_page_field_addr = shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page);
            auto *vaddr_page_log = try_find_page(vaddr_page_field_addr & ~PAGE_OFFSET_MASK);
            // If vp_offset was accessed during record, both it and vaddr_page will appear in the log
            // (record_step_state_access makes sure of it)
            // Otherwise, we do not need to translate
            if (vp_offset_log == nullptr || vaddr_page_log == nullptr) {
                continue;
            }
            const auto vaddr_page_field_haddr =
                cast_ptr_to_host_addr(vaddr_page_log->data) + (vaddr_page_field_addr & PAGE_OFFSET_MASK);
            const auto vaddr_page = aliased_aligned_read<uint64_t>(vaddr_page_field_haddr);
            // If, moreover, the slot was valid, the corresponding page will also appear in the log
            // (record_step_state_access makes sure of it)
            // Otherwise, we do not need to translate
            if (vaddr_page != TLB_INVALID_PAGE) {
                const auto vp_offset_field_haddr =
                    cast_ptr_to_host_addr(vp_offset_log->data) + (vp_offset_field_addr & PAGE_OFFSET_MASK);
                const auto vp_offset = aliased_aligned_read<uint64_t>(vp_offset_field_haddr);
                const auto paddr_page = vaddr_page + vp_offset;
                auto *page_log = try_find_page(paddr_page);
                if (page_log == nullptr) {
                    continue;
                }
                const auto haddr_page = cast_ptr_to_host_addr(page_log->data);
                const auto vh_offset = haddr_page - vaddr_page;
                aliased_aligned_write<host_addr>(vp_offset_field_haddr, vh_offset);
            }
        }
    }

    // \brief Reverses changes to TLB so we have vp_offset fields again instead of vh_offset
    // \details This makes the translation point back to target physical addresses
    template <TLB_set_index SET>
    void relocate_tlb_vh_offset_to_vp_offset() {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto vp_offset_field_addr = shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vp_offset);
            auto *vp_offset_log = try_find_page(vp_offset_field_addr & ~PAGE_OFFSET_MASK);
            const auto vaddr_page_field_addr = shadow_tlb_get_abs_addr(SET, slot_index, shadow_tlb_what::vaddr_page);
            auto *vaddr_page_log = try_find_page(vaddr_page_field_addr & ~PAGE_OFFSET_MASK);
            // If vp_offset was accessed during record, both it and vaddr_page will appear in the log
            // (record_step_state_access makes sure of it)
            // Otherwise, we do not need to translate
            if (vp_offset_log == nullptr || vaddr_page_log == nullptr) {
                continue;
            }
            const auto vaddr_page_field_haddr =
                cast_ptr_to_host_addr(vaddr_page_log->data) + (vaddr_page_field_addr & PAGE_OFFSET_MASK);
            const auto vaddr_page = aliased_aligned_read<uint64_t>(vaddr_page_field_haddr);
            // If, moreover, the slot was valid, the corresponding page will also appear in the log
            // (record_step_state_access makes sure of it)
            // Otherwise, we do not need to translate
            // We also don't need to translate back if it is no longer valid
            if (vaddr_page != TLB_INVALID_PAGE) {
                const auto vp_offset_field_haddr =
                    cast_ptr_to_host_addr(vp_offset_log->data) + (vp_offset_field_addr & PAGE_OFFSET_MASK);
                const auto vh_offset = aliased_aligned_read<host_addr>(vp_offset_field_haddr);
                const auto haddr_page = vaddr_page + vh_offset;
                auto *page_log = try_find_page(haddr_page);
                if (page_log == nullptr) {
                    continue;
                }
                const auto paddr_page = page_log->index << AR_LOG2_PAGE_SIZE;
                const auto vp_offset = paddr_page - vaddr_page;
                aliased_aligned_write<uint64_t>(vp_offset_field_haddr, vp_offset);
            }
        }
    }

    page_type *find_page(uint64_t paddr_page) const {
        auto *page_log = try_find_page(paddr_page);
        if (page_log == nullptr) {
            interop_throw_runtime_error("required page not found");
        }
        return page_log;
    }

    page_type *find_page(host_addr haddr_page) const {
        auto *page_log = try_find_page(haddr_page);
        if (page_log == nullptr) {
            interop_throw_runtime_error("required page not found");
        }
        return page_log;
    }

    // \brief Compute the current machine root hash
    hash_type compute_root_hash() {
        //??D Here we should only do this for dirty pages, right?
        //??D Initially, all pages are dirty, because we don't know their hashes
        //??D But in the end, we should only update those pages that we touched
        //??D May improve performance when we are running this on ZK
        for (uint64_t i = 0; i < m_context.page_count; i++) {
            interop_merkle_tree_hash(m_context.pages[i].data, AR_PAGE_SIZE,
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<interop_hash_type>(&m_context.pages[i].hash));
        }
        size_t next_page = 0;
        size_t next_sibling = 0;
        auto root_hash = compute_root_hash_impl(0, interop_log2_root_size - AR_LOG2_PAGE_SIZE, next_page, next_sibling);
        if (next_page != m_context.page_count) {
            interop_throw_runtime_error("too many pages in log");
        }
        if (next_sibling != m_context.sibling_count) {
            interop_throw_runtime_error("too many sibling hashes in log");
        }
        return root_hash;
    }

    // \brief Compute the root hash of a memory range recursively
    // \param page_index Index of the first page in the range
    // \param log2_page_count Log2 of the size of number of pages in the range
    // \param next_page Index of the next page to be visited
    // \param next_sibling Index of the next sibling hash to be visited
    // \return Resulting root hash of the range
    hash_type compute_root_hash_impl(address_type page_index, int log2_page_count, size_t &next_page,
        size_t &next_sibling) {
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast))
        auto page_count = UINT64_C(1) << log2_page_count;
        if (next_page >= m_context.page_count || page_index + page_count <= m_context.pages[next_page].index) {
            if (next_sibling >= m_context.sibling_count) {
                interop_throw_runtime_error("too few sibling hashes in log");
            }
            return m_context.sibling_hashes[next_sibling++];
        }
        if (log2_page_count > 0) {
            auto left = compute_root_hash_impl(page_index, log2_page_count - 1, next_page, next_sibling);
            const auto halfway_page_index = page_index + (page_count >> 1);
            auto right = compute_root_hash_impl(halfway_page_index, log2_page_count - 1, next_page, next_sibling);
            hash_type hash{};
            interop_concat_hash(reinterpret_cast<interop_hash_type>(&left), reinterpret_cast<interop_hash_type>(&right),
                reinterpret_cast<interop_hash_type>(&hash));
            return hash;
        }
        if (m_context.pages[next_page].index == page_index) {
            return m_context.pages[next_page++].hash;
        }
        if (next_sibling >= m_context.sibling_count) {
            interop_throw_runtime_error("too few sibling hashes in log");
        }
        return m_context.sibling_hashes[next_sibling++];
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast))
    }

    //??D we should probably optimize access to the shadow so it doesn't perform a translation every time
    // We can do this by caching the vh_offset translation of the registers shadow page. This is easy if
    // static_assert(sizeof(shadow_state) <= AR_PAGE_SIZE, "shadow state must fit in single page");
    uint64_t check_read_reg(machine_reg reg) const {
        const auto haddr = do_get_faddr(machine_reg_address(reg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    //??D we should probably optimize access to the shadow so it doesn't perform a translation every time
    // We can do this by caching the vh_offset translation of the registers shadow page. This is easy if
    // static_assert(sizeof(shadow_state) <= AR_PAGE_SIZE, "shadow state must fit in single page");
    void check_write_reg(machine_reg reg, uint64_t val) const {
        const auto haddr = do_get_faddr(machine_reg_address(reg));
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
        return check_read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        check_write_reg(machine_reg_enum(what), val);
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
        auto *page_log = find_page(paddr_page);
        const auto offset = paddr & PAGE_OFFSET_MASK;
        return cast_ptr_to_host_addr(page_log->data) + offset;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    address_range &do_read_pma(uint64_t index) const {
        assert(index < PMA_MAX);
        // record_step_state_access will have recorded the access to istart and
        // ilength in its implementation of read_pmas_entry.
        const uint64_t istart = read_pmas_istart(index);
        const uint64_t ilength = read_pmas_ilength(index);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        const int i = static_cast<int>(index);
        const auto abrt = [](const char *err) { interop_throw_runtime_error(err); };
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
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <typename TYPE>
    auto check_read_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) const {
        const auto haddr = do_get_faddr(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        return aliased_aligned_read<TYPE>(haddr);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return check_read_tlb<uint64_t>(SET, slot_index, shadow_tlb_what::vaddr_page);
    }

    template <TLB_set_index SET>
    host_addr do_read_tlb_vf_offset(uint64_t slot_index) const {
        return check_read_tlb<host_addr>(SET, slot_index, shadow_tlb_what::vp_offset);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return check_read_tlb<uint64_t>(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <typename TYPE>
    auto check_write_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what, TYPE val) const {
        const auto haddr = do_get_faddr(shadow_tlb_get_abs_addr(set_index, slot_index, what));
        aliased_aligned_write<TYPE>(haddr, val);
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) const {
        check_write_tlb(SET, slot_index, shadow_tlb_what::vaddr_page, vaddr_page);
        check_write_tlb(SET, slot_index, shadow_tlb_what::vp_offset, vh_offset);
        check_write_tlb(SET, slot_index, shadow_tlb_what::pma_index, pma_index);
    }

    void do_putchar(uint8_t /*c*/) const { // NOLINT(readability-convert-member-functions-to-static)
        ;                                  // do nothing
    }

    void do_mark_dirty_page(host_addr /* haddr */, uint64_t /* pma_index */) const {
        // this is a noop since we have no host machine
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "replay_step_state_access";
    }
};

} // namespace cartesi

#endif
