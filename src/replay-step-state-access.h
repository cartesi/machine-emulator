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

#include <cstdlib>
#include <optional>

#include "compiler-defines.h"
#include "device-state-access.h"
#include "host-addr.h"
#include "i-state-access.h"
#include "mock-pma-entry.h"
#include "pma-constants.h"
#include "replay-step-state-access-interop.h"
#include "riscv-constants.h"
#include "shadow-pmas.h"
#include "shadow-state.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "strict-aliasing.h"
#include "uarch-constants.h"
#include "uarch-defines.h"

namespace cartesi {

// \file this code is designed to be compiled for a free-standing environment.
// Environment-specific functions have the prefix "interop_" and are declared in "replay-step-state-access-interop.h"

class replay_step_state_access;

// Type trait that should return the pma_entry type for a state access class
template <>
struct i_state_access_pma_entry<replay_step_state_access> {
    using type = mock_pma_entry;
};
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
class replay_step_state_access : public i_state_access<replay_step_state_access> {
public:
    using address_type = uint64_t;
    using data_type = unsigned char[PMA_PAGE_SIZE];
    using hash_type = std::array<unsigned char, interop_machine_hash_byte_size>;
    static_assert(sizeof(hash_type) == interop_machine_hash_byte_size);

    struct PACKED page_type {
        address_type index;
        data_type data;
        hash_type hash;
    };

    struct context {
        uint64_t page_count{0};                                    ///< Number of pages in the step log
        page_type *pages{nullptr};                                 ///< Array of page data
        uint64_t sibling_count{0};                                 ///< Number of sibling hashes in the step log
        hash_type *sibling_hashes{nullptr};                        ///< Array of sibling hashes
        std::array<std::optional<mock_pma_entry>, PMA_MAX> pmas{}; ///< Array of PMA entries
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
        memcpy(&m_context.page_count, log_image, sizeof(m_context.page_count));
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
        memcpy(&m_context.sibling_count, log_image + sibling_count_offset, sizeof(m_context.sibling_count));

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
    friend i_state_access<replay_step_state_access>;

    /// \brief Try to find a page in the logged data by its physical address
    /// \param paddr The physical address of the page
    /// \return A pointer to the page_type structure if found, nullptr otherwise
    page_type *try_find_page(uint64_t paddr_page) const {
        const auto page_index = paddr_page >> PMA_PAGE_SIZE_LOG2;
        uint64_t min{0};
        uint64_t max{m_context.page_count};
        while (min < max) {
            auto mid = (min + max) >> 1;
            if (m_context.pages[mid].index == page_index) {
                return &m_context.pages[mid];
            }
            if (m_context.pages[mid].index < page_index) {
                min = mid + 1;
            } else {
                max = mid;
            }
        }
        return nullptr;
    }

    /// \brief Try to find a page in the logged data by the host address of its data
    /// \param haddr Host address of page data
    /// \return A pointer to the page_type structure if found, nullptr otherwise
    page_type *try_find_page(host_addr haddr_page) const {
        uint64_t min{0};
        uint64_t max{m_context.page_count};
        while (min < max) {
            auto mid = (min + max) >> 1;
            auto mid_page_data = cast_ptr_to_host_addr(m_context.pages[mid].data);
            if (mid_page_data == haddr_page) {
                return &m_context.pages[mid];
            }
            if (mid_page_data < haddr_page) {
                min = mid + 1;
            } else {
                max = mid;
            }
        }
        return nullptr;
    }

    // \brief Relocate all TLB vp_offset fields to vh_offset
    // \details This makes the translation point directly to logged page data
    template <TLB_set_use USE>
    void relocate_tlb_vp_offset_to_vh_offset() {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto vp_offset_field_addr = shadow_tlb_get_vp_offset_abs_addr<USE>(slot_index);
            auto *vp_offset_log = try_find_page(vp_offset_field_addr & ~PAGE_OFFSET_MASK);
            const auto vaddr_page_field_addr = shadow_tlb_get_vaddr_page_abs_addr<USE>(slot_index);
            auto *vaddr_page_log = try_find_page(vaddr_page_field_addr & ~PAGE_OFFSET_MASK);
            // If vp_offset was accessed during record, both it and vaddr_apge will appear in the log
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
    template <TLB_set_use USE>
    void relocate_tlb_vh_offset_to_vp_offset() {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto vp_offset_field_addr = shadow_tlb_get_vp_offset_abs_addr<USE>(slot_index);
            auto *vp_offset_log = try_find_page(vp_offset_field_addr & ~PAGE_OFFSET_MASK);
            const auto vaddr_page_field_addr = shadow_tlb_get_vaddr_page_abs_addr<USE>(slot_index);
            auto *vaddr_page_log = try_find_page(vaddr_page_field_addr & ~PAGE_OFFSET_MASK);
            // If vp_offset was accessed during record, both it and vaddr_apge will appear in the log
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
                const auto paddr_page = page_log->index << PMA_PAGE_SIZE_LOG2;
                const auto vp_offset = paddr_page - vaddr_page;
                aliased_aligned_write<uint64_t>(vp_offset_field_haddr, vp_offset);
            }
        }
    }

    page_type *find_page(uint64_t paddr_page) const {
        auto *page_log = try_find_page(paddr_page);
        if (page_log == nullptr) {
            interop_throw_runtime_error("find_page: page not found");
        }
        return page_log;
    }

    page_type *find_page(host_addr haddr_page) const {
        auto *page_log = try_find_page(haddr_page);
        if (page_log == nullptr) {
            interop_throw_runtime_error("find_page: page not found");
        }
        return page_log;
    }

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

    // \brief Compute the current machine root hash
    hash_type compute_root_hash() {
        for (uint64_t i = 0; i < m_context.page_count; i++) {
            interop_merkle_tree_hash(m_context.pages[i].data, PMA_PAGE_SIZE,
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<interop_hash_type>(&m_context.pages[i].hash));
        }

        size_t next_page = 0;
        size_t next_sibling = 0;
        auto root_hash =
            compute_root_hash_impl(0, interop_log2_root_size - PMA_PAGE_SIZE_LOG2, next_page, next_sibling);
        if (next_page != m_context.page_count) {
            interop_throw_runtime_error("compute_root_hash: next_page != m_context.page_count");
        }
        if (next_sibling != m_context.sibling_count) {
            interop_throw_runtime_error("compute_root_hash: sibling hashes not totally consumed");
        }
        return root_hash;
    }

    // \brief Compute the root hash of a memory range recursively
    // \param page_index Index of the first page in the range
    // \param page_count_log2_size Log2 of the size of number of pages in the range
    // \param next_page Index of the next page to be visited
    // \param next_sibling Index of the next sibling hash to be visited
    // \return Resulting root hash of the range
    hash_type compute_root_hash_impl(address_type page_index, int page_count_log2_size, size_t &next_page,
        size_t &next_sibling) {
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast))
        auto page_count = UINT64_C(1) << page_count_log2_size;
        if (next_page >= m_context.page_count || page_index + page_count <= m_context.pages[next_page].index) {
            if (next_sibling >= m_context.sibling_count) {
                interop_throw_runtime_error(
                    "compute_root_hash_impl: trying to access beyond sibling count while skipping range");
            }
            return m_context.sibling_hashes[next_sibling++];
        }
        if (page_count_log2_size > 0) {
            auto left = compute_root_hash_impl(page_index, page_count_log2_size - 1, next_page, next_sibling);
            auto right = compute_root_hash_impl(page_index + (UINT64_C(1) << (page_count_log2_size - 1)),
                page_count_log2_size - 1, next_page, next_sibling);
            hash_type hash{};
            interop_concat_hash(reinterpret_cast<interop_hash_type>(&left), reinterpret_cast<interop_hash_type>(&right),
                reinterpret_cast<interop_hash_type>(&hash));
            return hash;
        }
        if (m_context.pages[next_page].index == page_index) {
            return m_context.pages[next_page++].hash;
        }
        if (next_sibling >= m_context.sibling_count) {
            interop_throw_runtime_error("compute_root_hash_impl: trying to access beyond sibling count");
        }
        return m_context.sibling_hashes[next_sibling++];
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast))
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    int do_make_scoped_note(const char *text) { // NOLINT(readability-convert-member-functions-to-static)
        (void) text;
        return 0;
    }

    //??D we should probably optimize access to the shadow so it doesn't perform a translation every time
    // We can do this by caching the vh_offset trasnslation of the processor shadow page. This is easy if
    // static_assert(sizeof(shadow_state) <= PMA_PAGE_SIZE, "shadow state must fit in single page");
    uint64_t do_read_x(int reg) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::x0, reg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_x(int reg, uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::x0, reg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_f(int reg) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::f0, reg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_f(int reg, uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::f0, reg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_pc() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::pc));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_pc(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::pc));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_fcsr() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::fcsr));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_fcsr(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::fcsr));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_icycleinstret() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::icycleinstret));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_icycleinstret(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::icycleinstret));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mvendorid() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mvendorid));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t do_read_marchid() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::marchid));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t do_read_mimpid() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mimpid));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t do_read_mcycle() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcycle));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mcycle(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcycle));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mstatus() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mstatus));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mstatus(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mstatus));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mtvec() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mtvec));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mtvec(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mtvec));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mscratch() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mscratch));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mscratch(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mscratch));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mepc() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mepc));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mepc(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mepc));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mcause() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcause));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mcause(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcause));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mtval() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mtval));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mtval(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mtval));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_misa() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::misa));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_misa(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::misa));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mie() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mie));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mie(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mie));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mip() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mip));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mip(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mip));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_medeleg() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::medeleg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_medeleg(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::medeleg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mideleg() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mideleg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mideleg(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mideleg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_mcounteren() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcounteren));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_mcounteren(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::mcounteren));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_senvcfg() const {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::senvcfg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_senvcfg(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::senvcfg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_menvcfg() const {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::menvcfg));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_menvcfg(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::menvcfg));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_stvec() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::stvec));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_stvec(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::stvec));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_sscratch() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::sscratch));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_sscratch(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::sscratch));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_sepc() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::sepc));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_sepc(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::sepc));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_scause() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::scause));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_scause(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::scause));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_stval() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::stval));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_stval(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::stval));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_satp() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::satp));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_satp(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::satp));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_scounteren() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::scounteren));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_scounteren(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::scounteren));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_ilrsc() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::ilrsc));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_ilrsc(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::ilrsc));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_iprv() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iprv));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_iprv(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iprv));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_iflags_X() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_X));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_iflags_X(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_X));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_iflags_Y() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_Y));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_iflags_Y(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_Y));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_iflags_H() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_H));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_iflags_H(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iflags_H));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_iunrep() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iunrep));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_iunrep(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::iunrep));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_clint_mtimecmp() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::clint_mtimecmp));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::clint_mtimecmp));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_plic_girqpend() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::plic_girqpend));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_plic_girqpend(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::plic_girqpend));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_plic_girqsrvd() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::plic_girqsrvd));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::plic_girqsrvd));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_htif_fromhost() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_fromhost));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_htif_fromhost(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_fromhost));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_htif_tohost() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_tohost));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    void do_write_htif_tohost(uint64_t val) {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_tohost));
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    uint64_t do_read_htif_ihalt() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_ihalt));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t do_read_htif_iconsole() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_iconsole));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t do_read_htif_iyield() {
        const auto haddr = do_get_faddr(machine_reg_address(machine_reg::htif_iyield));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    uint64_t read_pma_istart(uint64_t index) {
        const auto haddr = do_get_faddr(shadow_pmas_get_pma_istart_abs_addr(index));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    uint64_t read_pma_ilength(uint64_t index) {
        const auto haddr = do_get_faddr(shadow_pmas_get_pma_ilength_abs_addr(index));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    mock_pma_entry &do_read_pma_entry(uint64_t index) {
        assert(index < PMA_MAX);
        // record_step_state_access will have recorded the access to istart and
        // ilength in its implementation of read_pma_entry.
        const uint64_t istart = read_pma_istart(index);
        const uint64_t ilength = read_pma_ilength(index);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        const int i = static_cast<int>(index);
        if (!m_context.pmas[i]) {
            m_context.pmas[i] =
                make_mock_pma_entry(index, istart, ilength, [](const char *err) { interop_throw_runtime_error(err); });
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return m_context.pmas[index].value();
    }

    template <typename T, typename A>
    void do_read_memory_word(host_addr haddr, uint64_t /* pma_index */, T *pval) {
        *pval = aliased_aligned_read<T, A>(haddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(host_addr haddr, uint64_t /* pma_index */, T val) {
        aliased_aligned_write<T, A>(haddr, val);
    }

    template <TLB_set_use USE>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) {
        const auto haddr = do_get_faddr(shadow_tlb_get_vaddr_page_abs_addr<USE>(slot_index));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    template <TLB_set_use USE>
    host_addr do_read_tlb_vp_offset(uint64_t slot_index) {
        const auto haddr = do_get_faddr(shadow_tlb_get_vp_offset_abs_addr<USE>(slot_index));
        return aliased_aligned_read<host_addr>(haddr);
    }

    template <TLB_set_use USE>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) {
        const auto haddr = do_get_faddr(shadow_tlb_get_pma_index_abs_addr<USE>(slot_index));
        return aliased_aligned_read<uint64_t>(haddr);
    }

    template <TLB_set_use USE>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset, uint64_t pma_index) {
        const auto haddr_vaddr_page = do_get_faddr(shadow_tlb_get_vaddr_page_abs_addr<USE>(slot_index));
        aliased_aligned_write<uint64_t>(haddr_vaddr_page, vaddr_page);
        const auto haddr_vp_offset = do_get_faddr(shadow_tlb_get_vp_offset_abs_addr<USE>(slot_index));
        aliased_aligned_write<host_addr>(haddr_vp_offset, vh_offset);
        const auto haddr_pma_index = do_get_faddr(shadow_tlb_get_pma_index_abs_addr<USE>(slot_index));
        aliased_aligned_write<uint64_t>(haddr_pma_index, pma_index);
    }

    void do_mark_dirty_page(host_addr /* haddr */, uint64_t /* pma_index */) {
        // this is a noop since we have no host machine
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        (void) mcycle_max;
        return {mcycle, false};
    }

};

} // namespace cartesi

#endif
