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

#ifndef OS_H
#define OS_H

#include <cstddef>
#include <cstdint>

/// \file
/// \brief System-specific OS handling operations

namespace cartesi {

/// \brief Initialize console
void os_open_tty(void);

/// \brief Cleanup console initialization
void os_close_tty(void);

/// \brief Polls console for input characters
/// \param wait Timeout to wait for characters in microseconds
void os_poll_tty(uint64_t wait);

/// \brief Reads an input character from the console
/// \return Charater read from console
int os_getchar(void);

/// \brief Writes an output character to the console
/// \param ch Character to write
void os_putchar(uint8_t ch);

/// \brief Creates a new directory
int os_mkdir(const char *path, int mode);

/// \brief Maps a file to memory
unsigned char *os_map_file(const char *path, uint64_t length, bool shared);

/// \brief Unmaps a file from memory
void os_unmap_file(unsigned char *host_memory, uint64_t length);

} // namespace cartesi

#endif
