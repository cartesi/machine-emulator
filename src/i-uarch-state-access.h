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

#ifndef I_UARCH_STATE_ACCESS_H
#define I_UARCH_STATE_ACCESS_H

#include <cinttypes>
#include <cstdint>

#include "dump.h"
#include "i-prefer-shadow-uarch-state.h"
#include "meta.h"
#include "tlb.h"

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define DEFINE_USA_READ(REG)                                                                                           \
    uint64_t read_##REG() {                                                                                            \
        if constexpr (!is_an_i_prefer_shadow_uarch_state_v<DERIVED>) {                                                 \
            const auto val = derived().do_read_##REG();                                                                \
            DUSA_PRINTF("%s::read_" #REG "() = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), val, val);                   \
            return val;                                                                                                \
        } else {                                                                                                       \
            return prefer_read_shadow_uarch_state(shadow_uarch_state_what::REG);                                       \
        }                                                                                                              \
    }

#define DEFINE_USA_WRITE(REG)                                                                                          \
    void write_##REG(uint64_t val) {                                                                                   \
        if constexpr (!is_an_i_prefer_shadow_uarch_state_v<DERIVED>) {                                                 \
            derived().do_write_##REG(val);                                                                             \
            DUSA_PRINTF("%s::write_" #REG "(%" PRIu64 "(0x%" PRIx64 "))\n", get_name(), val, val);                     \
        } else {                                                                                                       \
            prefer_write_shadow_uarch_state(shadow_uarch_state_what::REG, val);                                        \
        }                                                                                                              \
    }
// NOLINTEND(cppcoreguidelines-macro-usage)

namespace cartesi {

// Interface for microarchitecture state access
template <typename DERIVED>
class i_uarch_state_access { // CRTP
    i_uarch_state_access() = default;
    friend DERIVED;

    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

    uint64_t prefer_read_shadow_uarch_state(shadow_uarch_state_what what) {
        const auto val = derived().read_shadow_uarch_state(what);
        [[maybe_unused]] const auto *const what_name = shadow_uarch_state_get_what_name(what);
        DUSA_PRINTF("%s::read_shadow_uarch_state(%s) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), what_name, val, val);
        return val;
    }

    void prefer_write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) {
        derived().write_shadow_uarch_state(what, val);
        [[maybe_unused]] const auto *const what_name = shadow_uarch_state_get_what_name(what);
        DUSA_PRINTF("%s::write_shadow_uarch_state(%s, %" PRIu64 "(0x%" PRIx64 "))\n", get_name(), what_name, val, val);
    }

public:
    /// \brief Works as printf if we are dumping uarch state accesses, otherwise does nothing
    template <size_t N, typename... ARGS>
    static void DUSA_PRINTF([[maybe_unused]] const char (&fmt)[N], [[maybe_unused]] ARGS... args) {
#ifdef DUMP_UARCH_STATE_ACCESS
        D_PRINTF(fmt, args...);
#endif
    }

    uint64_t read_uarch_x(int i) {
        if constexpr (!is_an_i_prefer_shadow_uarch_state_v<DERIVED>) {
            const auto val = derived().do_read_uarch_x(i);
            DUSA_PRINTF("%s::read_uarch_x(%d) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), i, val, val);
            return val;
        } else {
            return prefer_read_shadow_uarch_state(shadow_uarch_state_get_what(shadow_uarch_state_what::uarch_x0, i));
        }
    }

    void write_uarch_x(int i, uint64_t val) {
        if constexpr (!is_an_i_prefer_shadow_uarch_state_v<DERIVED>) {
            derived().do_write_uarch_x(i, val);
            DUSA_PRINTF("%s::write_uarch_x(%d, %" PRIu64 ")\n", get_name(), i, val);
        } else {
            prefer_write_shadow_uarch_state(shadow_uarch_state_get_what(shadow_uarch_state_what::uarch_x0, i), val);
        }
    }

    // Define read and write methods for each register in the shadow uarch state
    // NOLINTBEGIN(cppcoreguidelines-macro-usage)
    DEFINE_USA_READ(uarch_halt_flag)
    DEFINE_USA_WRITE(uarch_halt_flag)
    DEFINE_USA_READ(uarch_cycle)
    DEFINE_USA_WRITE(uarch_cycle)
    DEFINE_USA_READ(uarch_pc)
    DEFINE_USA_WRITE(uarch_pc)
    // NOLINTEND(cppcoreguidelines-macro-usage)

    uint64_t read_word(uint64_t paddr) {
        const auto val = derived().do_read_word(paddr);
        DUSA_PRINTF("%s::read_word(phys_addr{0x%" PRIx64 "}) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), paddr, val,
            val);
        return val;
    }

    void write_word(uint64_t paddr, uint64_t val) {
        derived().do_write_word(paddr, val);
        DUSA_PRINTF("%s::write_word(phys_addr{0x%" PRIx64 "}, %" PRIu64 "(0x%" PRIx64 "))\n", get_name(), paddr, val,
            val);
    }

    /// \brief Resets uarch to pristine state
    void reset_uarch() {
        return derived().do_reset_uarch();
    }

    void putchar(uint8_t c) {
        derived().do_putchar(c);
    }

    void mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
        return derived().do_mark_dirty_page(paddr, pma_index);
    }

    void write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) {
        derived().do_write_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
    }

    constexpr const char *get_name() const {
        return derived().do_get_name();
    }
};

/// \brief SFINAE test implementation of the i_uarch_state_access interface
template <typename DERIVED>
using is_an_i_uarch_state_access =
    std::integral_constant<bool, is_template_base_of_v<i_uarch_state_access, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_uarch_state_access_v = is_an_i_uarch_state_access<DERIVED>::value;

} // namespace cartesi

#endif
