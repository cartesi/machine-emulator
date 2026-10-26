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
#include "hot-tlb.hpp"
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

template <typename Dumper>
class replay_step_state_access;

// Type trait that should return the fast_addr type for a state access class
template <typename Dumper>
struct i_state_access_fast_addr<replay_step_state_access<Dumper>> {
    using type = host_addr;
};

/// \brief Provides machine state from a whole-page step log buffer
/// Full-page validation at decode makes host-pointer TLB hits and constant register offsets safe.
template <typename Dumper = no_step_log_dumper>
// NOLINTNEXTLINE(misc-multiple-inheritance)
class replay_step_state_access :
    public i_state_access<replay_step_state_access<Dumper>>,
    public i_accept_scoped_notes<replay_step_state_access<Dumper>>,
    public i_prefer_shadow_state<replay_step_state_access<Dumper>> {
public:
    struct context {
        step_log log;                          ///< Parsed step log (witnessed tree)
        mock_address_ranges ars{};             ///< Array of address ranges
        hot_tlb_state tlb{};                   ///< Hot TLB cache for validated entries
        [[no_unique_address]] Dumper dumper{}; ///< Receives the dump; the no-op sink takes no space
    };

private:
    context &m_context;                                     // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    mutable const slice_entry *m_shadow_regs_page{nullptr}; ///< cache shadow registers page

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
        m_context.log =
            step_log::decode(log_image, log_size, slice_storage, required_hash_function, step_log_shape::whole_pages);
        // initialize hot TLB entries as unverified
        for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
            for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
                m_context.tlb[set_index][slot_index].vaddr_page = TLB_UNVERIFIED_PAGE;
                m_context.tlb[set_index][slot_index].vh_offset = host_addr{0};
            }
        }
    }

    // \brief Finish the replay and return the obtained root hash after
    // A machine paused on a rejected input returns its recorded revert root hash.
    machine_hash finish() {
        if (is_rejected_manual_yield(*this)) {
            return this->read_revert_root_hash();
        }
        return m_context.log.compute_root_hash();
    }

private:
    /// \brief Try to find a page in the logged data by the host address of its data
    /// \param haddr Host address of page data
    /// \return A pointer to the slice_entry structure if found, nullptr otherwise
    const slice_entry *try_find_page(host_addr haddr_page) const {
        auto it = std::ranges::lower_bound(m_context.log.pages, haddr_page, std::ranges::less{},
            [](const auto &page) { return cast_ptr_to_host_addr(page.data); });
        if (it != m_context.log.pages.end() && cast_ptr_to_host_addr(it->data) == haddr_page) {
            return &(*it);
        }
        return nullptr;
    }

    const slice_entry *find_page(host_addr haddr_page) const {
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
        *(--it)->hash = machine_hash{};
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
        const auto val = aliased_aligned_read<uint64_t>(get_shadow_reg_host_addr(what));
        m_context.dumper.read(nullptr, static_cast<uint64_t>(what), val);
        return val;
    }

    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        const auto haddr = get_shadow_reg_host_addr(what);
        *m_shadow_regs_page->hash = machine_hash{}; // written page: rehash on the after-root pass
        m_context.dumper.write(nullptr, static_cast<uint64_t>(what), aliased_aligned_read<uint64_t>(haddr), val);
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    machine_hash do_read_revert_root_hash() const {
        machine_hash hash{};
        std::copy_n(m_context.log.find_data(AR_SHADOW_REVERT_ROOT_HASH_START), hash.size(), hash.begin());
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
        return cast_ptr_to_host_addr(m_context.log.find_page(paddr)->data) + (paddr & PAGE_OFFSET_MASK);
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
        if (shadow_tlb_verify_slot(SET, vaddr_page, vp_offset, zero_padding, ar) == TLB_INVALID_PAGE) {
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
            const auto paddr_page = find_page(vaddr_page + vh_offset)->address;
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
