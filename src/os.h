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

/// \file
/// \brief System-specific OS handling operations

namespace cartesi {

/// \brief TTY console constants
enum TTY_constants : uint32_t {
    TTY_BUF_SIZE = 4096,   ///< Number of characters in TTY input buffer
    TTY_DEFAULT_COLS = 80, ///< Default width (columns)
    TTY_DEFAULT_ROWS = 25, ///< Default height (rows)
    TTY_CTRL_D = 4,        ///< End of session character (Ctrl+D)
};

/// \brief Set of file descriptions to be polled with select().
struct select_fd_sets {
    int maxfd;
    void *readfds;
    void *writefds;
    void *exceptfds;
};

/// \brief Initialize console
void os_open_tty();

/// \brief Cleanup console initialization
void os_close_tty();

/// \brief Fill file descriptors to be polled by select() with TTY's file descriptors.
/// \param fds Pointer to sets of read, write and except file descriptors to be updated.
void os_prepare_tty_select(select_fd_sets *fds);

/// \brief Poll TTY's file descriptors that were marked as ready by select().
/// \param select_ret Return value from the most recent select() call.
/// \param fds Pointer to sets of read, write and except file descriptors to be checked.
/// \returns True if there are pending TTY characters available to be read, false otherwise.
bool os_poll_selected_tty(int select_ret, select_fd_sets *fds);

/// \brief Polls console for input characters
/// \param wait Timeout to wait for characters in microseconds
bool os_poll_tty(uint64_t timeout_us);

/// \brief Get console size.
/// \param pwidth Receives the console width (number of columns).
/// \param pheight Receives the console height (amount of rows).
void os_get_tty_size(uint16_t *pwidth, uint16_t *pheight);

/// \brief Reads a character from the console input.
/// \return Character read from console, it may be -1 if there is no character.
int os_getchar();

/// \brief Reads multiple characters from the console input.
/// \param data Buffer to receive the console characters.
/// \param max_leng Maximum buffer length.
/// \returns Length of characters read, 0 if no characters were available.
size_t os_getchars(unsigned char *data, size_t max_len);

/// \brief Writes a character to the console output.
/// \param ch Character to write
void os_putchar(uint8_t ch);

/// \brief Writes multiple characters to the console output.
/// \param data Buffer of characters to write.
/// \param len Length of buffer.
void os_putchars(const uint8_t *data, size_t len);

/// \brief Silences putchar (and putchars) output
/// \param yes If true, putchar is silenced
void os_silence_putchar(bool yes);

/// \brief Creates a new directory
int os_mkdir(const char *path, int mode);

/// \brief Get time elapsed since its first call with microsecond precision
int64_t os_now_us();

/// \brief Get the number of concurrent threads supported by the OS
uint64_t os_get_concurrency();

/// \brief Mutex for os_parallel_for()
struct parallel_for_mutex {
    std::function<void()> lock;
    std::function<void()> unlock;
};

/// \brief Mutex guard for os_parallel_for()
struct parallel_for_mutex_guard {
    explicit parallel_for_mutex_guard(const parallel_for_mutex &mutex) : mutex(mutex) {
        mutex.lock();
    }
    ~parallel_for_mutex_guard() {
        mutex.unlock();
    }

    parallel_for_mutex_guard() = delete;
    parallel_for_mutex_guard(const parallel_for_mutex_guard &) = default;
    parallel_for_mutex_guard(parallel_for_mutex_guard &&) = default;
    parallel_for_mutex_guard &operator=(const parallel_for_mutex_guard &) = delete;
    parallel_for_mutex_guard &operator=(parallel_for_mutex_guard &&) = delete;

private:
    parallel_for_mutex mutex;
};

/// \brief Runs a for loop in parallel using up to n threads
/// \return True if all thread tasks succeeded
bool os_parallel_for(uint64_t n, const std::function<bool(uint64_t j, const parallel_for_mutex &mutex)> &task);

// Callbacks used by os_select_fds().
using os_select_before_callback = std::function<void(select_fd_sets *fds, uint64_t *timeout_us)>;
using os_select_after_callback = std::function<bool(int select_ret, select_fd_sets *fds)>;

/// \brief Poll file descriptions for events.
/// \param before_cb Callback called before calling select().
/// \param after_cb Callback called after calling select().
/// \param timeout_us Maximum amount of time in microseconds to wait for an event,
/// this value may be updated in case a before_cb() has an deadline timer before the timeout.
bool os_select_fds(const os_select_before_callback &before_cb, const os_select_after_callback &after_cb,
    uint64_t *timeout_us);

/// \brief Disable sigpipe
void os_disable_sigpipe();

/// \brief Sleep until timeout_us microseconds elapsed
void os_sleep_us(uint64_t timeout_us);

// \brief Double-fork implementation
// \param emancipate If true, the grand-child breaks out of grand-parent program group into its own.
// \returns In case of success, grand-child returns 0 and the parent returns the grand-child pid.
// In case of error, parent throws and there is no grand-child.
int os_double_fork_or_throw(bool emancipate);

// \brief Double-fork implementation
// \param emancipate If true, the grand-child breaks out of grand-parent program group into its own.
// \err_msg In case of error, returns a string with an error message, guaranteed
// to remain valid only until the the next time this same function is called
// again on the same thread. Set to nullptr otherwise.
// \returns In case of success, grand-child returns 0 and the parent returns the grand-child pid.
// In case of error, parent returns -1 and there is no grand-child.
int os_double_fork(bool emancipate, const char **err_msg);

/// \brief Get the length of a file
int64_t os_get_file_length(const char *filename, const char *text = "");

/// \brief Check if a file exists
bool os_file_exists(const char *filename);

} // namespace cartesi

#endif
