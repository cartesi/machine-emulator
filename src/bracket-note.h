// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef BRACKET_NOTE_H
#define BRACKET_NOTE_H

/// \file
/// \brief Bracket annotation for access log

namespace cartesi {

/// \brief Bracket type
enum class bracket_type {
    begin,    ///< Start of scope
    end       ///< End of scope
};

/// \brief Bracket note
struct bracket_note {
    bracket_type type{bracket_type::begin};   ///< Bracket type
    uint64_t where{0};                        ///< Where it points to in the log
    std::string text{};                       ///< Note text
};

} // namespace cartesi

#endif
