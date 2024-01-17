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

#include "bracket-note.h"
#include "pma.h"

namespace cartesi {

// Interface for microarchitecture state access
template <typename DERIVED>
class i_uarch_state_access { // CRTP

    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Adds an annotation bracket to the log
    /// \param type Type of bracket
    /// \param text String with the text for the annotation
    void push_bracket(bracket_type type, const char *text) {
        return derived().do_push_bracket(type, text);
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

    auto read_x(int r) {
        return derived().do_read_x(r);
    }

    auto write_x(int r, uint64_t v) {
        return derived().do_write_x(r, v);
    }

    auto read_pc() {
        return derived().do_read_pc();
    }

    auto write_pc(uint64_t v) {
        return derived().do_write_pc(v);
    }

    auto read_cycle() {
        return derived().do_read_cycle();
    }

    auto read_halt_flag() {
        return derived().do_read_halt_flag();
    }

    auto set_halt_flag() {
        return derived().do_set_halt_flag();
    }

    auto reset_halt_flag() {
        return derived().do_reset_halt_flag();
    }

    auto write_cycle(uint64_t v) {
        return derived().do_write_cycle(v);
    }

    uint64_t read_word(uint64_t paddr) {
        return derived().do_read_word(paddr);
    }

    void write_word(uint64_t paddr, uint64_t data) {
        return derived().do_write_word(paddr, data);
    }

    template <typename T>
    pma_entry &find_pma_entry(uint64_t paddr) {
        return derived().template do_find_pma_entry<T>(paddr);
    }

    /// \brief Resets uarch to pristine state
    void reset_state(void) {
        return derived().do_reset_state();
    }
};

} // namespace cartesi

#endif
