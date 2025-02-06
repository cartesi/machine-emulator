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

#ifndef I_ACCEPT_SCOPED_NOTE_H
#define I_ACCEPT_SCOPED_NOTE_H

/// \file
/// \brief State access interface

#include <cstdint>
#include <type_traits>

#ifdef DUMP_SCOPED_NOTE
#include "dump.h"
#endif

#include "meta.h"
#include "scoped-note.h"

namespace cartesi {

#ifdef DUMP_SCOPED_NOTE
template <typename... ARGS>
static inline auto DSN_PRINTF(ARGS... args) {
    return D_PRINTF(args...);
}
#else
template <typename... ARGS>
static inline auto DSN_PRINTF(ARGS... /*args*/) {
    return 0;
}
#endif

/// \class i_accept_scoped_note
/// \brief Interface that lets a state access accept scoped notes.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_accept_scoped_note { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Adds a begin bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_begin_bracket(const char *text) {
        derived().do_push_begin_bracket(text);
        DSN_PRINTF("----> begin %s (%s)\n", text, derived().get_name());
    }

    /// \brief Adds an end bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_end_bracket(const char *text) {
        derived().do_push_end_bracket(text);
        DSN_PRINTF("<---- end %s (%s)\n", text, derived().get_name());
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

protected:
    // Default implementation for classes that do not use scoped notes
    // (It still will dump the scoped notes when requested)
    auto do_make_scoped_note([[maybe_unused]] const char *text) {
#ifdef DUMP_SCOPED_NOTE
        return scoped_note{*this, text};
#else
        return 0;
#endif
    }

    void do_push_begin_bracket(const char * /*text*/) {
        ;
    }

    void do_push_end_bracket(const char * /*text*/) {
        ;
    }
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_accept_scoped_note =
    std::integral_constant<bool, is_template_base_of_v<i_accept_scoped_note, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_accept_scoped_note_v = is_an_i_accept_scoped_note<DERIVED>::value;

} // namespace cartesi

#endif
