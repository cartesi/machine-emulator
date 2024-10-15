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

#ifndef BRACKET_NOTE_H
#define BRACKET_NOTE_H

#include <cstdint>
#include <string>

/// \file
/// \brief Bracket annotation for access log

namespace cartesi {

/// \brief Bracket type
enum class bracket_type {
    begin, ///< Start of scope
    end    ///< End of scope
};

/// \brief Bracket note
struct bracket_note {                       // NOLINT(bugprone-exception-escape)
    bracket_type type{bracket_type::begin}; ///< Bracket type
    uint64_t where{0};                      ///< Where it points to in the log
    std::string text;                       ///< Note text
};

} // namespace cartesi

#endif
