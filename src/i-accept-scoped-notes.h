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

#ifndef I_ACCEPT_SCOPED_NOTES_H
#define I_ACCEPT_SCOPED_NOTES_H

/// \file
/// \brief Accept scoped notes interface

#include <cstdint>
#include <type_traits>

#include "dump.h"
#include "i-state-access.h"
#include "i-uarch-state-access.h"
#include "meta.h"
#include "scoped-note.h"

namespace cartesi {

/// \class i_accept_scoped_notes
/// \brief Interface that lets a state access class accept scoped notes.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_accept_scoped_notes { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Works as printf if we are dumping scoped notes, otherwise does nothing
    template <size_t N, typename... ARGS>
    static void DSN_PRINTF([[maybe_unused]] const char (&fmt)[N], [[maybe_unused]] ARGS... args) {
#ifdef DUMP_SCOPED_NOTE
        if constexpr (is_an_i_state_access_v<DERIVED>) {
            DERIVED::DSA_PRINTF(fmt, args...);
        } else if (is_an_i_uarch_state_access_v<DERIVED>) {
            DERIVED::DUSA_PRINTF(fmt, args...);
        } else {
            D_PRINTF(fmt, args...);
        }
#endif
    }

    /// \brief Adds a begin bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_begin_bracket(const char *text) const {
        derived().do_push_begin_bracket(text);
        DSN_PRINTF("----> begin %s (%s)\n", text, derived().get_name());
    }

    /// \brief Adds an end bracket annotation to the log
    /// \param text String with the text for the annotation
    void push_end_bracket(const char *text) const {
        derived().do_push_end_bracket(text);
        DSN_PRINTF("<---- end %s (%s)\n", text, derived().get_name());
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) const {
        return derived().do_make_scoped_note(text);
    }

protected:
    // Default implementation for classes that do not use scoped notes
    // (It still will dump the scoped notes when requested)
    auto do_make_scoped_note([[maybe_unused]] const char *text) const {
#ifdef DUMP_SCOPED_NOTE
        return scoped_note{*this, text};
#else
        return 0;
#endif
    }

    void do_push_begin_bracket(const char * /*text*/) const {
        ;
    }

    void do_push_end_bracket(const char * /*text*/) const {
        ;
    }
};

/// \brief SFINAE test implementation of the i_accept_scoped_notes interface
template <typename DERIVED>
using is_an_i_accept_scoped_notes =
    std::integral_constant<bool, is_template_base_of_v<i_accept_scoped_notes, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_accept_scoped_note_v = is_an_i_accept_scoped_notes<DERIVED>::value;

} // namespace cartesi

#endif
