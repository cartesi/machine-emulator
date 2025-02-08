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

#ifndef SCOPED_NOTE_H
#define SCOPED_NOTE_H

namespace cartesi {

/// \brief Adds annotations to the state, bracketing a scope
template <typename STATE_ACCESS>
class scoped_note {

    STATE_ACCESS m_a;
    const char *const m_text; ///< String with the text for the annotation

public:
    /// \brief Constructor adds the "begin" bracketing note
    /// \param a State access receiving annotations
    /// \param text Pointer to annotation text (must be valid until destruction)
    /// \details A note is added at the moment of construction and destruction
    scoped_note(STATE_ACCESS a, const char *text) : m_a{a}, m_text(text) {
        m_a.push_begin_bracket(m_text);
    }

    /// \brief No assignments/copies
    scoped_note(const scoped_note &) = delete;
    scoped_note &operator=(const scoped_note &) = delete;
    scoped_note(scoped_note &&) = delete;
    scoped_note &operator=(scoped_note &&) = delete;

    /// \brief Destructor adds the "end" bracketing note
    ~scoped_note() {
        m_a.push_end_bracket(m_text);
    }
};

} // namespace cartesi

#endif // SCOPED_NOTE_H
