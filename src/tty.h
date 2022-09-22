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

#include <cstddef>
#include <cstdint>

/// \file
/// \brief System-specific TTY handling operations

namespace cartesi {

/// \brief Initialize TTY for console input
void tty_initialize(void);

/// \brief Cleanup TTY console input initialization
void tty_finalize(void);

/// \brief Polls TTY for input characters
/// \param wait Timeout to wait for characters in microseconds
void tty_poll_console(uint64_t wait);

/// \brief  Reads a character from the console
/// \return Charater read from console
int tty_getchar(void);

/// \brief Writes a character to TTY
/// \param ch Character to write
void tty_putchar(uint8_t ch);

} // namespace cartesi

#endif
