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

#ifndef TTY_H
#define TTY_H

#include <cstdint>

/// \file
/// \brief System-specific TTY handling operations

namespace cartesi {

/// \brief TTY commands
enum class tty_command {
    initialize, ///< Prepare TTY for use in cartesi machine
    cleanup     ///< Restore TTY to original state
};

/// \brief Configure TTY
/// \param cmd Indicates if the TTY is to be initialized or restored to initial state
void tty_setup(tty_command cmd);

/// \brief Polls TTY for input characters
/// \param wait Timeout to wait for characters in microseconds
/// \param data buffer to store characters
/// \param max_len max number of characters to read
/// \param actual_len on return, receives the actual number of characters read
/// \returns true, if characters were read
bool tty_poll(uint64_t wait, char *data, size_t max_len, long *actual_len);

/// \brief Writes a character to TTY
/// \param ch Character to write
void tty_putchar(uint8_t ch);

} // namespace cartesi

#endif
