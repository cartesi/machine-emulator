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

#ifndef UARCH_BRIDGE_STATE_ACCESS_HPP
#define UARCH_BRIDGE_STATE_ACCESS_HPP

#include "uarch-runtime.hpp" // must be included first, because of assert

#include "compiler-defines.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-state.hpp"
#include "i-state-access.hpp"
#include "machine-reg.hpp"
#include "pmas.hpp"
#include "riscv-constants.hpp"
#include "shadow-tlb.hpp"
#include "uarch-constants.hpp"
#include "uarch-defines.h"
#include "uarch-ecall.h"
#include "uarch-pma-cache.hpp"
#include "uarch-strict-aliasing.hpp"

namespace cartesi {

class uarch_bridge_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<uarch_bridge_state_access> {
    using type = uint64_t;
};

// Provides access to the state of the big emulator from uarch code
// NOLINTNEXTLINE(misc-multiple-inheritance)
class uarch_bridge_state_access :
    public i_state_access<uarch_bridge_state_access>,
    public i_accept_scoped_notes<uarch_bridge_state_access>,
    public i_prefer_shadow_state<uarch_bridge_state_access> {

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    uarch_pma_cache &m_pmas;

public:
    explicit uarch_bridge_state_access(uarch_pma_cache &pmas) : m_pmas(pmas) {}
    uarch_bridge_state_access(const uarch_bridge_state_access &other) = default;
    uarch_bridge_state_access(uarch_bridge_state_access &&other) = default;
    uarch_bridge_state_access &operator=(const uarch_bridge_state_access &other) = delete;
    uarch_bridge_state_access &operator=(uarch_bridge_state_access &&other) = delete;
    ~uarch_bridge_state_access() = default;

    template <TLB_set_index SET>
    void flush_tlb_set() const {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; slot_index += UARCH_TLB_FLUSH_BATCH_SIZE_DEF) {
            ua_flush_tlb_batch_ECALL(SET, slot_index);
        }
    }

    template <typename T>
    uarch_address_range &find_pma(uint64_t paddr, uint64_t &index) const {
        return m_pmas.find<T>(paddr, index, bridge_read_pma_entry, abort_pma);
    }

private:
    static uint64_t bridge_read_reg(machine_reg reg) {
        return ua_aliased_aligned_read<uint64_t>(machine_reg_address(reg));
    }

    static void bridge_write_reg(machine_reg reg, uint64_t val) {
        ua_aliased_aligned_write<uint64_t>(machine_reg_address(reg), val);
    }

    static pmas_entry bridge_read_pma_entry(uint64_t i) {
        return {.istart = ua_aliased_aligned_read<uint64_t>(pmas_get_abs_addr(i, pmas_what::istart)),
            .ilength = ua_aliased_aligned_read<uint64_t>(pmas_get_abs_addr(i, pmas_what::ilength))};
    }

    static void abort_pma(const char * /*err*/) {
        assert(false && "read_address_range() failed");
        abort();
    }

    static uint64_t bridge_read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) {
        return ua_aliased_aligned_read<uint64_t>(shadow_tlb_get_abs_addr(set_index, slot_index, what));
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<uarch_bridge_state_access>;

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    uint64_t do_read_shadow_register(shadow_registers_what what) const {
        return bridge_read_reg(machine_reg_enum(what));
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        bridge_write_reg(machine_reg_enum(what), val);
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<uarch_bridge_state_access>;

    template <typename T, typename A>
    void do_read_memory_word(uint64_t paddr, uint64_t /* pma_index */, T *pval) const {
        *pval = ua_aliased_aligned_read<T, A>(paddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(uint64_t paddr, uint64_t /* pma_index */, T val) const {
        m_pmas.invalidate_on_write(paddr);
        ua_aliased_aligned_write<T, A>(paddr, val);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t /*paddr*/, unsigned char * /*data*/, uint64_t /*length*/) const {
        // This is not implemented yet because it's not being used
        assert(false && "read_memory() unexpectedly called");
        abort();
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t /*paddr*/, const unsigned char * /*data*/, uint64_t /*length*/) const {
        // This is not implemented yet because it's not being used
        assert(false && "write_memory() unexpectedly called");
        abort();
        return false;
    }

    uarch_address_range &do_read_pma(uint64_t index) const {
        return m_pmas.read(index, bridge_read_pma_entry, abort_pma);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    uint64_t do_get_faddr(uint64_t paddr, uint64_t /* pma_index */) const {
        return paddr;
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vaddr_page(uint64_t slot_index) const {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vaddr_page);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_vf_offset(uint64_t slot_index) const {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vp_offset);
    }

    template <TLB_set_index SET>
    uint64_t do_read_tlb_pma_index(uint64_t slot_index) const {
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::pma_index);
    }

    template <TLB_set_index SET>
    uint64_t do_init_hot_tlb_slot(uint64_t slot_index) const {
        // No hot TLB -- just return the shadow vaddr_page
        return bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vaddr_page);
    }

    template <TLB_set_index SET>
    bool do_verify_cold_tlb_slot(uint64_t slot_index) const {
        const auto vaddr_page = bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vaddr_page);
        const auto vp_offset = bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::vp_offset);
        const auto pma_index = bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::pma_index);
        const auto zero_padding = bridge_read_shadow_tlb(SET, slot_index, shadow_tlb_what::zero_padding_);
        const auto &ar = do_read_pma(pma_index);
        return shadow_tlb_verify_slot(SET, vaddr_page, vp_offset, zero_padding, ar) != TLB_INVALID_PAGE;
    }

    template <TLB_set_index SET>
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index) const {
        ua_write_tlb_ECALL(SET, slot_index, vaddr_page, vp_offset, pma_index);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_putchar(uint8_t c) const {
        ua_putchar_ECALL(c);
        return false;
    }

    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "uarch_bridge_state_access";
    }
};

} // namespace cartesi

#endif
