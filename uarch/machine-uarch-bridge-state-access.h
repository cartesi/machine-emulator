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

#ifndef MACHINE_UARCH_BRIDGE_STATE_ACCESS_H
#define MACHINE_UARCH_BRIDGE_STATE_ACCESS_H

#include "uarch-runtime.h" // must be included first, because of assert

#include <optional>

#include "compiler-defines.h"
#include "i-accept-scoped-notes.h"
#include "i-prefer-shadow-state.h"
#include "i-state-access.h"
#include "machine-reg.h"
#include "mock-address-range.h"
#include "pmas.h"
#include "riscv-constants.h"
#include "shadow-tlb.h"
#include "uarch-constants.h"
#include "uarch-defines.h"
#include "uarch-ecall.h"
#include "uarch-strict-aliasing.h"

namespace cartesi {

class machine_uarch_bridge_state_access;

// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<machine_uarch_bridge_state_access> {
    using type = uint64_t;
};

// Provides access to the state of the big emulator from microcode
class machine_uarch_bridge_state_access :
    public i_state_access<machine_uarch_bridge_state_access>,
    public i_accept_scoped_notes<machine_uarch_bridge_state_access>,
    public i_prefer_shadow_state<machine_uarch_bridge_state_access> {

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    mock_address_ranges &m_ars;

public:
    machine_uarch_bridge_state_access(std::array<mock_address_range, PMA_MAX> &ars) : m_ars(ars) {}
    machine_uarch_bridge_state_access(const machine_uarch_bridge_state_access &other) = default;
    machine_uarch_bridge_state_access(machine_uarch_bridge_state_access &&other) = default;
    machine_uarch_bridge_state_access &operator=(const machine_uarch_bridge_state_access &other) = delete;
    machine_uarch_bridge_state_access &operator=(machine_uarch_bridge_state_access &&other) = delete;
    ~machine_uarch_bridge_state_access() = default;

private:
    static uint64_t bridge_read_reg(machine_reg reg) {
        return ua_aliased_aligned_read<uint64_t>(machine_reg_address(reg));
    }

    static void bridge_write_reg(machine_reg reg, uint64_t val) {
        ua_aliased_aligned_write<uint64_t>(machine_reg_address(reg), val);
    }

    static uint64_t bridge_read_pma_istart(int i) {
        return ua_aliased_aligned_read<uint64_t>(pmas_get_abs_addr(i, pmas_what::istart));
    }

    static uint64_t bridge_read_pma_ilength(int i) {
        return ua_aliased_aligned_read<uint64_t>(pmas_get_abs_addr(i, pmas_what::ilength));
    }

    static uint64_t bridge_read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what what) {
        return ua_aliased_aligned_read<uint64_t>(shadow_tlb_get_abs_addr(set_index, slot_index, what));
    }

    // -----
    // i_prefer_shadow_state interface implementation
    // -----
    friend i_prefer_shadow_state<machine_uarch_bridge_state_access>;

    uint64_t do_read_shadow_state(shadow_state_what what) const {
        return bridge_read_reg(machine_reg_enum(what));
    }

    void do_write_shadow_state(shadow_state_what what, uint64_t val) const {
        bridge_write_reg(machine_reg_enum(what), val);
    }

    // -----
    // i_state_access interface implementation
    // -----
    friend i_state_access<machine_uarch_bridge_state_access>;

    template <typename T, typename A>
    void do_read_memory_word(uint64_t paddr, uint64_t /* pma_index */, T *pval) const {
        *pval = ua_aliased_aligned_read<T, A>(paddr);
    }

    template <typename T, typename A>
    void do_write_memory_word(uint64_t paddr, uint64_t /* pma_index */, T val) const {
        ua_aliased_aligned_write<T, A>(paddr, val);
    }

    bool do_read_memory(uint64_t /*paddr*/, unsigned char * /*data*/, uint64_t /*length*/) const {
        // This is not implemented yet because it's not being used
        assert(false && "read_memory() unexpectedly called");
        abort();
        return false;
    }

    bool do_write_memory(uint64_t /*paddr*/, const unsigned char * /*data*/, uint64_t /*length*/) const {
        // This is not implemented yet because it's not being used
        assert(false && "write_memory() unexpectedly called");
        abort();
        return false;
    }

    address_range &do_read_pma(uint64_t index) const {
        constexpr const auto throw_abort = [](const char * /*err*/) {
            assert(false && "read_address_range() failed");
            abort();
        };
        const uint64_t istart = bridge_read_pma_istart(index);
        const uint64_t ilength = bridge_read_pma_ilength(index);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        int i = static_cast<int>(index);
        if (std::holds_alternative<std::monostate>(m_ars[i])) {
            m_ars[i] = make_mock_address_range(istart, ilength, throw_abort);
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return get_mock_address_range(m_ars[i], throw_abort);
    }

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
    void do_write_tlb(uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index) const {
        ua_write_tlb_ECALL(SET, slot_index, vaddr_page, vp_offset, pma_index);
    }

    void do_putchar(uint8_t c) const {
        ua_putchar_ECALL(c);
    }

    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) const {
        ua_mark_dirty_page_ECALL(paddr, pma_index);
    }

    constexpr const char *do_get_name() const { // NOLINT(readability-convert-member-functions-to-static)
        return "machine_uarch_bridge_state_access";
    }

    // NOLINTEND(readability-convert-member-functions-to-static)
};

} // namespace cartesi

#endif
