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

#include <cstdint>

#include "bracket-note.h"
#include "tlb.h"

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

public:
    /// \brief Adds a begin bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_begin_bracket(const char *text) {
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("----> begin %s (%s)\n", text, get_name());
#endif
        return derived().do_push_begin_bracket(text);
    }

    /// \brief Adds an end bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_end_bracket(const char *text) {
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("<---- end %s (%s)\n", text, get_name());
#endif
        return derived().do_push_end_bracket(text);
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

    auto read_x(int i) {
#ifdef DUMP_UARCH_STATE_ACCESS
        const auto val = derived().do_read_x(i);
        printf("%s::read_x(%d) = %llu(0x%llx)\n", get_name(), i, val, val);
        return val;
#else
        return derived().do_read_x(i);
#endif
    }

    auto write_x(int i, uint64_t val) {
        derived().do_write_x(i, val);
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("%s::write_x(%d, %llu)\n", get_name(), i, val);
#endif
    }

    auto read_pc() {
#ifdef DUMP_UARCH_STATE_ACCESS
        const auto val = derived().do_read_pc();
        printf("%s::read_pc() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_pc();
#endif
    }

    auto write_pc(uint64_t val) {
        derived().do_write_pc(val);
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("%s::write_pc(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    auto read_cycle() {
#ifdef DUMP_UARCH_STATE_ACCESS
        const auto val = derived().do_read_cycle();
        printf("%s::read_cycle() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_cycle();
#endif
    }

    auto read_halt_flag() {
#ifdef DUMP_UARCH_STATE_ACCESS
        const auto val = derived().do_read_halt_flag();
        printf("%s::read_halt_flag() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_halt_flag();
#endif
    }

    auto write_halt_flag(uint64_t val) {
        derived().do_write_halt_flag(val);
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("%s::write_halt_flag(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    auto write_cycle(uint64_t val) {
        derived().do_write_cycle(val);
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("%s::write_cycle(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    uint64_t read_word(uint64_t paddr) {
#ifdef DUMP_UARCH_STATE_ACCESS
        const auto val = derived().do_read_word(paddr);
        printf("%s::read_word(phys_addr{0x%llx}) = %llu(0x%llx)\n", get_name(), paddr, val, val);
        return val;
#else
        return derived().do_read_word(paddr);
#endif
    }

    void write_word(uint64_t paddr, uint64_t val) {
        derived().do_write_word(paddr, val);
#ifdef DUMP_UARCH_STATE_ACCESS
        printf("%s::write_word(phys_addr{0x%llx}, %llu(0x%llx))\n", get_name(), paddr, val, val);
#endif
    }

    /// \brief Resets uarch to pristine state
    void reset_state() {
        return derived().do_reset_state();
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

private:
    /// \brief For state access classes that do not need annotations
    void do_push_begin_bracket(const char * /*text*/) {}

    /// \brief For state access classes that do not need annotations
    void do_push_end_bracket(const char * /*text*/) {}

#ifndef DUMP_UARCH_STATE_ACCESS
    /// \brief For state access classes that do not need annotations
    int do_make_scoped_note(const char * /*text*/) {
        return 0;
    }
#endif
};

} // namespace cartesi

#endif
