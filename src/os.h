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
#include <functional>
#include <span>
#include <utility>

/// \file
/// \brief System-specific OS operations

namespace cartesi::os {

/// \brief TTY console constants.
enum tty_constants : uint32_t {
    TTY_BUF_SIZE = 4096,   ///< Number of characters in TTY input buffer.
    TTY_DEFAULT_COLS = 80, ///< Default width (columns).
    TTY_DEFAULT_ROWS = 25, ///< Default height (rows).
};

/// \brief TTY output.
enum class tty_output {
    to_stderr,
    to_stdout,
};

/// \brief Set of file descriptions to be polled with select().
struct select_fd_sets {
    int maxfd;
    void *readfds;
    void *writefds;
    void *exceptfds;
};

// Callbacks used by select_fds().
using select_before_callback = std::function<void(select_fd_sets *fds, uint64_t *timeout_us)>;
using select_after_callback = std::function<bool(int select_ret, select_fd_sets *fds)>;

/// \brief Open TTY.
/// \throw std::system_error on error.
void open_tty();

/// \brief Close TTY.
void close_tty() noexcept;

/// \brief Fill file descriptors to be polled by select() with TTY's file descriptors.
/// \param fds Pointer to sets of read, write and except file descriptors to be updated.
void prepare_tty_select(select_fd_sets *fds) noexcept;

/// \brief Poll TTY's file descriptors that were marked as ready by select().
/// \param select_ret Return value from the most recent select() call.
/// \param fds Pointer to sets of read, write and except file descriptors to be checked.
/// \returns True if there are pending TTY characters available to be read, false otherwise.
bool poll_selected_tty(int select_ret, select_fd_sets *fds) noexcept;

/// \brief Fill file descriptors to be polled by select() with a given file descriptor for reading.
/// \param fds Pointer to sets of read, write and except file descriptors to be updated.
/// \param fd File descriptor to add to the read set.
void prepare_fd_select(select_fd_sets *fds, int fd) noexcept;

/// \brief Poll a file descriptor that was marked as ready by select().
/// \param select_ret Return value from the most recent select() call.
/// \param fds Pointer to sets of read, write and except file descriptors to be checked.
/// \param fd File descriptor to check.
/// \returns True if the file descriptor is ready to be read, false otherwise.
bool poll_selected_fd(int select_ret, select_fd_sets *fds, int fd) noexcept;

/// \brief Polls TTY console for input characters
/// \param timeout_us Timeout to wait for characters in microseconds
/// \returns True if there are pending TTY characters available to be read, false otherwise.
bool poll_tty(uint64_t timeout_us) noexcept;

/// \brief Get TTY console size.
/// \returns TTY console size as a pair of [columns, rows].
std::pair<uint16_t, uint16_t> get_tty_size() noexcept;

/// \brief Reads multiple characters from the TTY console input.
/// \param buf Buffer to receive the console characters.
/// \returns Number of characters read, 0 if no characters were available, or -1 on error and errno is set.
/// \details This function is non-blocking and may return fewer characters than requested.
/// Use `poll_tty` to wait until characters are available before calling this function.
ptrdiff_t getchars(std::span<uint8_t> buf) noexcept;

/// \brief Writes multiple characters to the TTY console output.
/// \param buf Buffer of characters to write.
/// \returns Number of characters actually written, or -1 on error and `errno` is set.
ptrdiff_t putchars(std::span<const uint8_t> buf, tty_output output = tty_output::to_stdout) noexcept;

/// \brief Duplicates a file descriptor.
/// \param fd File descriptor to duplicate.
/// \returns A new valid file descriptor referring to the same file as fd.
/// \throws std::system_error on error.
int dup_fd(int fd);

/// \brief Closes a file descriptor.
/// \param fd File descriptor to close.
void close_fd(int fd) noexcept;

/// \brief Writes data to a file descriptor.
/// \param fd File descriptor to write to.
/// \param buf Buffer of data to write.
/// \returns Number of bytes actually written, or -1 on error and `errno` is set.
ptrdiff_t write_fd(int fd, std::span<const uint8_t> buf) noexcept;

/// \brief Reads data from a file descriptor.
/// \param fd File descriptor to read from.
/// \param buf Buffer to receive data.
/// \returns Number of bytes actually read, or -1 on error and `errno` is set.
ptrdiff_t read_fd(int fd, std::span<uint8_t> buf) noexcept;

/// \brief Poll file descriptions for events.
/// \param before_cb Callback called before calling select().
/// \param after_cb Callback called after calling select().
/// \param timeout_us Maximum amount of time in microseconds to wait for an event,
/// this value may be updated in case a before_cb() has an deadline timer before the timeout.
/// \returns True if after_cb() reported any event, false otherwise.
bool select_fds(const select_before_callback &before_cb, const select_after_callback &after_cb, uint64_t *timeout_us);

/// \brief Get time elapsed since its first call with microsecond precision.
/// \returns Time in microseconds.
int64_t now_us() noexcept;

/// \brief Sleep until timeout_us microseconds elapsed.
void sleep_us(uint64_t timeout_us) noexcept;

/// \brief Disable sigpipe.
void disable_sigpipe() noexcept;

} // namespace cartesi::os

#endif
