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

#include <array>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "tty.h"

namespace cartesi {

/// \brief TTY global state
struct tty_state {
    bool initialized{false};
    bool resize_pending{false};
    int ttyfd{-1};
    termios oldtty{};
    std::array<char, TTY_CONSOLE_BUF_SIZE> buf{};
    ssize_t buf_pos{};
    ssize_t buf_len{};
    unsigned short cols{TTY_CONSOLE_DEFAULT_COLS};
    unsigned short rows{TTY_CONSOLE_DEFAULT_ROWS};
};

static int new_ttyfd(const char *path) {
    int fd{};
    do {
        fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    } while (fd == -1 && errno == EINTR);
    return fd;
}

static int get_ttyfd(void) {
    char *path{};
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
    return -1;
}

/// Returns pointer to the global TTY state
static tty_state *get_state() {
    static tty_state data;
    return &data;
}

/// \brief Signal raised whenever TTY size changes
static void signal_SIGWINCH_handler(int sig) {
    (void) sig;
    auto *s = get_state();
    if (!s->initialized) {
        return;
    }
    // It's not safe to do complex logic in signal handlers,
    // therefore we will actually update the console size in the next get size request.
    s->resize_pending = true;
}

void tty_initialize(void) {
    auto *s = get_state();
    if (s->initialized) { // Already initialized, just ignore
        return;
    }
    s->initialized = true;
    s->ttyfd = get_ttyfd();
    if (s->ttyfd >= 0) {
        //??(edubart) For some unknown reason TIOCGWINSZ ioctl doesn't return correct value in its first call.
        // A workaround is to get size multiple times on startup to fix the issue.
        for (int i = 0; i < 16; ++i) {
            // Get the window size for the first time
            winsize ws{};
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
                if (ws.ws_col >= 1 && ws.ws_row >= 1) {
                    s->cols = ws.ws_col;
                    s->rows = ws.ws_row;
                }
            }
        }

        // Install console resize signal handler
        struct sigaction sigact {};
        sigact.sa_handler = signal_SIGWINCH_handler;
        if (sigaction(SIGWINCH, &sigact, nullptr) != 0) {
            throw std::runtime_error{"error setting SIGWINCH signal handler"};
        }

        struct termios tty {};
        if (tcgetattr(s->ttyfd, &tty) != 0) {
            throw std::runtime_error{"tcgetattr failed"};
        }
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
        if (tcsetattr(s->ttyfd, TCSANOW, &tty) != 0) {
            throw std::runtime_error{"tcsetattr failed"};
        }
        //??D Should we check to see if changes stuck?
    }
}

void tty_finalize(void) {
    auto *s = get_state();
    if (!s->initialized) { // Not initialized, just ignore
        return;
    }
    s->initialized = false;
    if (s->ttyfd >= 0) {
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = -1;
    }
}

void tty_poll_before_select(int *pmaxfd, fd_set *readfds) {
    auto *s = get_state();
    // Ignore if TTY is not initialized or stdin was closed
    if (!s->initialized) {
        return;
    }
    FD_SET(STDIN_FILENO, readfds);
    if (STDIN_FILENO > *pmaxfd) {
        *pmaxfd = STDIN_FILENO;
    }
}

bool tty_poll_after_select(fd_set *readfds, int select_ret) {
    auto *s = get_state();
    if (!s->initialized) { // We can't poll when TTY is not initialized
        return false;
    }
    // If we have characters left in buffer, we don't need to obtain more characters
    if (s->buf_pos < s->buf_len) {
        return true;
    }
    // If the stdin file description is not ready, we can't obtain more characters
    if (select_ret <= 0 || !FD_ISSET(STDIN_FILENO, readfds)) {
        return false;
    }
    const ssize_t len = read(STDIN_FILENO, s->buf.data(), s->buf.size());
    // If stdin is closed, pass EOF to client
    if (len <= 0) {
        s->buf_len = 1;
        s->buf[0] = TTY_CONSOLE_CTRL_D;
    } else {
        s->buf_len = len;
    }
    s->buf_pos = 0;
    return true;
}

bool tty_poll_console(uint64_t wait_us) {
    int maxfd = -1;
    fd_set readfds{};
    FD_ZERO(&readfds);
    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(wait_us / 1000000);
    timeout.tv_usec = static_cast<suseconds_t>(wait_us % 1000000);
    tty_poll_before_select(&maxfd, &readfds);
    const int select_ret = select(maxfd + 1, &readfds, nullptr, nullptr, &timeout);
    return tty_poll_after_select(&readfds, select_ret);
}

int tty_getchar(void) {
    auto *s = get_state();
    if (s->initialized && s->buf_pos < s->buf_len) {
        return s->buf[s->buf_pos++] + 1;
    }
    return 0;
}

size_t tty_getchars(unsigned char *data, size_t max_len) {
    auto *s = get_state();
    if (!s->initialized) {
        return 0;
    }
    size_t written_len = 0;
    // Fill data until the buffer is full or there no more characters available in TTY input
    while (written_len < max_len) {
        // Are there characters available in TTY input?
        if (s->buf_pos >= s->buf_len) {
            return written_len;
        }
        const size_t buf_avail = static_cast<size_t>(s->buf_len - s->buf_pos);
        const size_t chunk_len = std::min(buf_avail, max_len - written_len);
        memcpy(&data[written_len], &s->buf[s->buf_pos], chunk_len);
        s->buf_pos += static_cast<ssize_t>(chunk_len);
        written_len += chunk_len;
    }
    return written_len;
}

void tty_putchar(uint8_t ch) {
    (void) write(STDOUT_FILENO, &ch, 1);
}

void tty_putchars(const uint8_t *data, size_t len) {
    if (len > 0) {
        (void) write(STDOUT_FILENO, data, len);
    }
}

void tty_get_size(uint16_t *pwidth, uint16_t *pheight) {
    auto *s = get_state();
    if (!s->initialized) {
        // fallback values
        *pwidth = TTY_CONSOLE_DEFAULT_COLS;
        *pheight = TTY_CONSOLE_DEFAULT_ROWS;
        return;
    }
    // Update console size after a SIGWINCH signal
    if (s->resize_pending) {
        winsize ws{};
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 1 && ws.ws_row >= 1) {
            s->cols = ws.ws_col;
            s->rows = ws.ws_row;
            s->resize_pending = false;
        }
    }
    *pwidth = s->cols;
    *pheight = s->rows;
}

} // namespace cartesi
