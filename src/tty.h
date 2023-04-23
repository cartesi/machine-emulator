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

#include <sys/select.h>

/// \file
/// \brief System-specific TTY handling operations

namespace cartesi {

/// \brief TTY console constants
enum console_constants : uint32_t {
    TTY_CONSOLE_BUF_SIZE = 4096,   ///< Number of characters in console input buffer
    TTY_CONSOLE_DEFAULT_COLS = 80, ///< Default console width (columns)
    TTY_CONSOLE_DEFAULT_ROWS = 25, ///< Default console height (rows)
    TTY_CONSOLE_CTRL_D = 4,        ///< End of session character (Ctrl+D)
};

/// \brief Initialize TTY for console input
void tty_initialize(void);

/// \brief Cleanup TTY console input initialization
void tty_finalize(void);

/// \brief Fill file descriptors to be polled by select() with TTY's file descriptors.
/// \param pmaxfd Pointer to the maximum select() file descriptor (it may be updated).
/// \param readfds Pointer to read file descriptor set to be updated.
void tty_poll_before_select(int *pmaxfd, fd_set *readfds);

/// \brief Poll TTY's file descriptors that were marked as ready by select().
/// \returns True if there are pending TTY characters available to be read, false otherwise.
bool tty_poll_after_select(fd_set *readfds, int select_ret);

/// \brief Polls TTY for input characters
/// \param wait Timeout to wait for characters in microseconds
bool tty_poll_console(uint64_t wait_us);

/// \brief Reads a character from the console
/// \returns Character read from console
int tty_getchar(void);

/// \brief Reads multiple characters from the console.
/// \param data Buffer to receive the console characters.
/// \param max_leng Maximum buffer length.
/// \returns Length of characters read, 0 if no characters were available.
size_t tty_getchars(unsigned char *data, size_t max_len);

/// \brief Writes a character to TTY
/// \param ch Character to write
void tty_putchar(uint8_t ch);

/// \brief Writes multiple characters to TTY.
/// \param data Buffer of characters to write.
/// \param len Length of buffer.
void tty_putchars(const uint8_t *data, size_t len);

/// \brief Get TTY console input size.
/// \param pwidth Receives the console width (number of columns).
/// \param pheight Receives the console height (amount of rows).
void tty_get_size(uint16_t *pwidth, uint16_t *pheight);

} // namespace cartesi

#endif
