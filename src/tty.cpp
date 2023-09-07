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

#include <array>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef NO_TERMIOS
#include <termios.h>
#endif

#include "tty.h"

namespace cartesi {

static const int CONSOLE_BUF_SIZE = 1024; ///< Number of characters in console input buffer

/// \brief TTY global state
struct tty_state {
    bool initialized{false};
    std::array<char, CONSOLE_BUF_SIZE> buf{};
    ssize_t buf_pos{};
    ssize_t buf_len{};
#ifndef NO_TERMIOS
    int ttyfd{-1};
    termios oldtty{};
#endif
};

#ifndef NO_TERMIOS
static int new_ttyfd(const char *path) {
    int fd{};
    do {
        fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    } while (fd == -1 && errno == EINTR);
    return fd;
}

static int get_ttyfd(void) {
    char *path{};
    // NOLINTBEGIN(bugprone-assignment-in-if-condition)
    if ((path = ttyname(STDERR_FILENO)) != nullptr) {
        return new_ttyfd(path);
    } else if ((path = ttyname(STDOUT_FILENO)) != nullptr) {
        return new_ttyfd(path);
    } else if ((path = ttyname(STDIN_FILENO)) != nullptr) {
        return new_ttyfd(path);
    } else if ((path = ctermid(nullptr)) != nullptr) {
        return new_ttyfd(path);
    } else {
        errno = ENOTTY; /* No terminal */
    }
    // NOLINTEND(bugprone-assignment-in-if-condition)
    return -1;
}
#endif

static bool try_read_chars_from_stdin(uint64_t wait, char *data, size_t max_len, long *actual_len) {
    const int fd_max{0};
    fd_set rfds{};
    timeval tv{};
    tv.tv_usec = static_cast<suseconds_t>(wait);
    FD_ZERO(&rfds); // NOLINT: suppress cause on MacOSX it resolves to __builtin_bzero
    FD_SET(STDIN_FILENO, &rfds);
    if (select(fd_max + 1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(0, &rfds)) {
        *actual_len = read(STDIN_FILENO, data, max_len);
        // If stdin is closed, pass EOF to client
        if (*actual_len <= 0) {
            *actual_len = 1;
            data[0] = 4; // CTRL+D
        }
        return true;
    }
    return false;
}

/// Returns pointer to the global TTY state
static tty_state *get_state() {
    static tty_state data;
    return &data;
}

void tty_initialize(void) {
    auto *s = get_state();
    if (s->initialized) {
        throw std::runtime_error("TTY already initialized.");
    }
    s->initialized = true;
#ifndef NO_TERMIOS
    // NOLINTNEXTLINE(bugprone-assignment-in-if-condition)
    if ((s->ttyfd = get_ttyfd()) >= 0) {
        struct termios tty {};
        tcgetattr(s->ttyfd, &tty);
        s->oldtty = tty;
        // Set terminal to "raw" mode
        tty.c_lflag &= ~(ECHO | // Echo off
            ICANON |            // Canonical mode off
            ECHONL |            // Do not echo NL (redundant with ECHO and ICANON)
            ISIG |              // Signal chars off
            IEXTEN              // Extended input processing off
        );
        tty.c_iflag &= ~(IGNBRK | // Generate \377 \0 \0 on BREAK
            BRKINT |              //
            PARMRK |              //
            ICRNL |               // No CR-to-NL
            ISTRIP |              // Do not strip off 8th bit
            INLCR |               // No NL-to-CR
            IGNCR |               // Do not ignore CR
            IXON                  // Disable XON/XOFF flow control on output
        );
        tty.c_oflag |= OPOST; // Enable output processing
        // Enable parity generation on output and checking for input
        tty.c_cflag &= ~(CSIZE | PARENB);
        tty.c_cflag |= CS8;
        // Read returns with 1 char and no delay
        tty.c_cc[VMIN] = 1;
        tty.c_cc[VTIME] = 0;
        tcsetattr(s->ttyfd, TCSANOW, &tty);
        //??D Should we check to see if changes stuck?
    }
#endif
}

void tty_finalize(void) {
    auto *s = get_state();
    if (!s->initialized) {
        throw std::runtime_error("TTY not initialized");
    }
    s->initialized = false;
#ifndef NO_TERMIOS
    if (s->ttyfd >= 0) {
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = -1;
    }
#endif
}

void tty_poll_console(uint64_t wait) {
    auto *s = get_state();
    if (!s->initialized) {
        throw std::runtime_error("can't poll TTY, it is not initialized");
    }
    // Check for input from console, if requested by HTIF
    // Obviously, somethind different must be done in blockchain
    // If we don't have any characters left in buffer, try to obtain more
    if (s->buf_pos >= s->buf_len) {
        if (try_read_chars_from_stdin(wait, s->buf.data(), s->buf.size(), &s->buf_len)) {
            s->buf_pos = 0;
        }
    }
}

int tty_getchar(void) {
    auto *s = get_state();
    if (!s->initialized) {
        throw std::runtime_error("can't get char, TTY is not initialized");
    }
    tty_poll_console(0);
    if (s->buf_pos < s->buf_len) {
        return s->buf[s->buf_pos++] + 1;
    }
    return 0;
}

void tty_putchar(uint8_t ch) {
    auto *s = get_state();
    if (!s->initialized) {
        // Write through fputc(), so we can take advantage of buffering.
        (void) fputc(ch, stdout);
        // On Linux, stdout in fully buffered by default when it's not a TTY,
        // here we flush every new line to perform line buffering.
        if (ch == '\n') {
            (void) fflush(stdout);
        }
    } else {
        // In interactive sessions we want to immediately write the character to stdout,
        // without any buffering.
        if (write(STDOUT_FILENO, &ch, 1) < 1) {
            ;
        }
    }
}

} // namespace cartesi
