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

#include "os-features.h"

// Must be included first
#include "os-posix-compat.h" // IWYU pragma: keep

#include "os.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept> // IWYU pragma: keep
#include <tuple>

#include <sys/time.h> // IWYU pragma: keep

#ifdef HAVE_SIGACTION
#include <csignal>
#endif

#if defined(HAVE_TTY) || defined(HAVE_TERMIOS) || defined(_WIN32)
#include <fcntl.h> // open
#endif

#ifdef HAVE_TERMIOS
#include <termios.h> // tcgetattr/tcsetattr
#ifdef HAVE_IOCTL
#include <sys/ioctl.h> // ioctl
#endif
#endif

#ifdef _WIN32

#if defined(HAVE_SELECT)
#include <winsock2.h> // select
#endif

#else // not _WIN32

#if defined(HAVE_TTY) || defined(HAVE_TERMIOS) || defined(HAVE_USLEEP)
#include <unistd.h> // write/read/close/usleep/fork
#endif

#if defined(HAVE_SELECT)
#include <sys/select.h> // select
#endif

#endif // _WIN32

// Enable these defines to debug
// #define DEBUG_OS

namespace cartesi {

#ifdef HAVE_TTY
/// \brief TTY global state
struct tty_state {
    bool initialized{false};
    bool resize_pending{false};
    bool silence_putchar{false};
    uint64_t use_count{0};
    std::array<char, TTY_BUF_SIZE> buf{}; // Characters in console input buffer
    intptr_t buf_pos{};
    intptr_t buf_len{};
    uint16_t cols{TTY_DEFAULT_COLS};
    uint16_t rows{TTY_DEFAULT_ROWS};
#ifdef HAVE_TERMIOS
    int ttyfd{-1};
    termios oldtty{};
#elif defined(_WIN32)
    HANDLE hStdin{};
    DWORD dwOldStdinMode{};
#endif
};

/// Returns pointer to the global TTY state
static tty_state *get_tty_state() {
    static THREAD_LOCAL tty_state data;
    return &data;
}
#endif // HAVE_TTY

/// \brief putchar global state
struct putchar_state {
    bool silence;
};

/// Returns pointer to the global TTY state
static putchar_state *get_putchar_state() {
    static THREAD_LOCAL putchar_state data;
    return &data;
}

#ifdef HAVE_TERMIOS
static int new_ttyfd(const char *path) {
    int fd{};
    do { // NOLINT(cppcoreguidelines-avoid-do-while)
        fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    } while (fd == -1 && errno == EINTR);
    return fd;
}

static int get_ttyfd() {
    const char *path{};
    path = ttyname(STDERR_FILENO);
    if (path != nullptr) {
        return new_ttyfd(path);
    }
    path = ttyname(STDOUT_FILENO);
    if (path != nullptr) {
        return new_ttyfd(path);
    }
    path = ttyname(STDIN_FILENO);
    if (path != nullptr) {
        return new_ttyfd(path);
    }
    path = ctermid(nullptr);
    if (path != nullptr) {
        return new_ttyfd(path);
    }
    errno = ENOTTY; /* No terminal */
    return -1;
}
#endif // HAVE_TERMIOS

#ifdef HAVE_SIGACTION
/// \brief Signal raised whenever TTY size changes
static void os_SIGWINCH_handler(int /*sig*/) {
    auto *s = get_tty_state();
    if (!s->initialized) {
        return;
    }
    // It's not safe to do complex logic in signal handlers,
    // therefore we will actually update the console size in the next get size request.
    s->resize_pending = true;
}
#endif

static bool os_update_tty_size([[maybe_unused]] tty_state *s) {
#ifdef HAVE_TTY
#if defined(HAVE_TERMIOS) && defined(HAVE_IOCTL)
    winsize ws{};
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col >= 1 && ws.ws_row >= 1) {
            s->cols = ws.ws_col;
            s->rows = ws.ws_row;
            return true;
        }
    } else {
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_update_tty_size(): ioctl TIOCGWINSZ failed\n");
#endif
    }

#elif defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        int rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (cols >= 1 && rows >= 1) {
            s->cols = cols;
            s->rows = rows;
            return true;
        }
    } else {
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_update_tty_size(): GetConsoleScreenBufferInfo failed\n");
#endif
    }

#endif // defined(HAVE_TERMIOS) && defined(HAVE_IOCTL)
#endif // HAVE_TTY
    return false;
}

void os_open_tty() {
#ifdef HAVE_TTY
    auto *s = get_tty_state();
    if (s->initialized) {
        s->use_count++;
        // Already initialized
        return;
    }

    s->initialized = true;
    s->use_count = 1;

#ifdef HAVE_TERMIOS
    if (s->ttyfd >= 0) { // Already open
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): tty already open\n");
#endif
        return;
    }
    const int ttyfd = get_ttyfd();
    if (ttyfd < 0) { // Failed to open tty fd
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): get_tty() failed\n");
#endif
        return;
    }
    struct termios tty{};
    if (tcgetattr(ttyfd, &tty) < 0) { // Failed to retrieve old mode
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): failed retrieve old mode\n");
#endif
        close(ttyfd);
        return;
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
    if (tcsetattr(ttyfd, TCSANOW, &tty) < 0) { // Failed to set raw mode
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): failed to set raw mode\n");
#endif
        close(ttyfd);
        return;
    }
    s->ttyfd = ttyfd;
#elif defined(_WIN32)
    // Get stdin handle
    s->hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (!s->hStdin) {
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): GetStdHandle() failed\n");
#endif
        return;
    }
    // Set console in raw mode
    if (GetConsoleMode(s->hStdin, &s->dwOldStdinMode)) {
        DWORD dwMode = s->dwOldStdinMode;
        dwMode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        if (!SetConsoleMode(s->hStdin, dwMode)) {
#ifdef DEBUG_OS
            std::ignore = fprintf(stderr, "os_open_tty(): SetConsoleMode() failed\n");
#endif
        }
    }
#endif // HAVE_TERMIOS

    // Get tty initial size
    os_update_tty_size(s);

#ifdef HAVE_SIGACTION
    // Install console resize signal handler
    struct sigaction sigact{};
    sigact.sa_flags = SA_RESTART;
    sigact.sa_handler = os_SIGWINCH_handler;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGWINCH, &sigact, nullptr) != 0) {
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_open_tty(): failed to install SIGWINCH handler\n");
#endif
    }
#endif

#else
    throw std::runtime_error("unable to open console input, stdin is unsupported in this platform");
#endif // HAVE_TTY
}

void os_close_tty() {
#ifdef HAVE_TTY
#ifdef HAVE_TERMIOS
    auto *s = get_tty_state();
    if (!s->initialized) {
        return;
    }
    if (--s->use_count > 0) {
        // Still in use by some other machine
        return;
    }
    if (s->ttyfd >= 0) { // Restore old mode
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = -1;
    }

#elif defined(_WIN32)
    auto *s = get_tty_state();
    if (s->hStdin) {
        SetConsoleMode(s->hStdin, s->dwOldStdinMode);
        s->hStdin = NULL;
    }

#endif // HAVE_TERMIOS
#endif // HAVE_TTY
}

void os_get_tty_size(uint16_t *pwidth, uint16_t *pheight) {
    auto *s = get_tty_state();
    if (!s->initialized) {
        // fallback values
        *pwidth = TTY_DEFAULT_COLS;
        *pheight = TTY_DEFAULT_ROWS;
        return;
    }
    // Update console size after a SIGWINCH signal
    if (s->resize_pending) {
        if (os_update_tty_size(s)) {
            s->resize_pending = false;
        }
    }
    *pwidth = s->cols;
    *pheight = s->rows;
}

void os_prepare_tty_select([[maybe_unused]] select_fd_sets *fds) {
#ifdef HAVE_TTY
    auto *s = get_tty_state();
    // Ignore if TTY is not initialized or stdin was closed
    if (!s->initialized) {
        return;
    }
#ifndef _WIN32
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    FD_SET(STDIN_FILENO, readfds);
    fds->maxfd = std::max(STDIN_FILENO, fds->maxfd);
#endif
#endif
}

bool os_poll_selected_tty([[maybe_unused]] int select_ret, [[maybe_unused]] select_fd_sets *fds) {
    auto *s = get_tty_state();
    if (!s->initialized) { // We can't poll when TTY is not initialized
        return false;
    }
    // If we have characters left in buffer, we don't need to obtain more characters
    if (s->buf_pos < s->buf_len) {
        return true;
    }

#ifdef _WIN32
    intptr_t len = -1;
    if (s->hStdin) {
        // Consume input events until buffer is full or the event list is empty
        INPUT_RECORD inputRecord{};
        DWORD numberOfEventsRead = 0;
        while (PeekConsoleInput(s->hStdin, &inputRecord, 1, &numberOfEventsRead)) {
            if (numberOfEventsRead == 0) {
                // Nothing to read
                return false;
            } else if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
                // Key was pressed
                DWORD numberOfCharsRead = 0;
                // We must read input buffer through ReadConsole() to read raw terminal input
                if (ReadConsole(s->hStdin, s->buf.data(), s->buf.size(), &numberOfCharsRead, NULL)) {
                    len = static_cast<intptr_t>(numberOfCharsRead);
                }
                break;
            } else {
                // Consume input event
                ReadConsoleInput(s->hStdin, &inputRecord, 1, &numberOfEventsRead);
            }
        }
    }
#else
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    // If the stdin file description is not ready, we can't obtain more characters
    if (select_ret <= 0 || !FD_ISSET(STDIN_FILENO, readfds)) {
        return false;
    }
    const auto len = static_cast<intptr_t>(read(STDIN_FILENO, s->buf.data(), s->buf.size()));

#endif // _WIN32

    // If stdin is closed, pass EOF to client
    if (len <= 0) {
        s->buf_len = 1;
        s->buf[0] = TTY_CTRL_D;
    } else {
        s->buf_len = len;
    }
    s->buf_pos = 0;
    return true;
}

bool os_poll_tty(uint64_t timeout_us) {
#ifdef _WIN32
    auto *s = get_tty_state();
    if (!s->initialized) { // We can't poll when TTY is not initialized
        return false;
    }
    if (s->hStdin) {
        // Wait for an input event
        const uint64_t wait_ms = (timeout_us + 999) / 1000;
        if (WaitForSingleObject(s->hStdin, wait_ms) != WAIT_OBJECT_0) {
            // No input events
            return false;
        }
    }
    return os_poll_selected_tty(-1, nullptr);

#else
    return os_select_fds(
        [](select_fd_sets *fds, const uint64_t * /*timeout_us*/) -> void { os_prepare_tty_select(fds); },
        [](int select_ret, select_fd_sets *fds) -> bool { return os_poll_selected_tty(select_ret, fds); }, &timeout_us);

#endif // _WIN32
}

int os_getchar() {
#ifdef HAVE_TTY
    auto *s = get_tty_state();
    if (!s->initialized) {
        return -1;
    }
    if (s->buf_pos < s->buf_len) {
        return s->buf[s->buf_pos++];
    }
#endif // HAVE_TTY
    return -1;
}

size_t os_getchars(unsigned char *data, size_t max_len) {
    size_t i = 0;
    for (; i < max_len; ++i) {
        const int c = os_getchar();
        if (c < 0) {
            break;
        }
        data[i] = c;
    }
    return i;
}

static void fputc_with_line_buffering(uint8_t ch) {
    // Write through fputc(), so we can take advantage of buffering.
    std::ignore = fputc(ch, stdout);
    // On Linux, stdout in fully buffered by default when it's not a TTY,
    // here we flush every new line to perform line buffering.
    if (ch == '\n') {
        std::ignore = fflush(stdout);
    }
}

void os_silence_putchar(bool yes) {
    auto *ps = get_putchar_state();
    ps->silence = yes;
}

void os_putchar(uint8_t ch) {
    auto *ps = get_putchar_state();
    if (ps->silence) {
        return;
    }
#ifdef HAVE_TTY
    auto *s = get_tty_state();
    if (!s->initialized) {
        // Write through fputc(), so we can take advantage of buffering.
        fputc_with_line_buffering(ch);
    } else {
        // In interactive sessions we want to immediately write the character to stdout,
        // without any buffering.
        if (write(STDOUT_FILENO, &ch, 1) < 1) {
            ;
        }
    }
#else
    fputc_with_line_buffering(ch);
#endif // HAVE_TTY
}

void os_putchars(const uint8_t *data, size_t len) {
    auto *ps = get_putchar_state();
    if (ps->silence) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        os_putchar(data[i]);
    }
}

int64_t os_now_us() {
    static const std::chrono::time_point<std::chrono::high_resolution_clock> start{
        std::chrono::high_resolution_clock::now()};
    auto end = std::chrono::high_resolution_clock::now();
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
}

bool os_select_fds(const os_select_before_callback &before_cb, const os_select_after_callback &after_cb,
    uint64_t *timeout_us) {
    // Create empty fd sets
    select_fd_sets fds{};
    fds.maxfd = -1;
#ifdef HAVE_SELECT
    fd_set readfds{};
    fd_set writefds{};
    fd_set exceptfds{};
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    fds.readfds = &readfds;
    fds.writefds = &writefds;
    fds.exceptfds = &exceptfds;
    // Fill fds
    before_cb(&fds, timeout_us);
    // Configure timeout
    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(*timeout_us / 1000000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(*timeout_us % 1000000);
    // Wait for events
    const int select_ret = select(fds.maxfd + 1, &readfds, &writefds, &exceptfds, &tv);
    return after_cb(select_ret, &fds);
#else
    // Act like select failed
    before_cb(&fds, timeout_us);
    const int select_ret = -1;
#endif
    // Process ready fds
    return after_cb(select_ret, &fds);
}

void os_disable_sigpipe() {
#ifdef HAVE_SIGACTION
    struct sigaction sigact{};
    sigact.sa_handler = SIG_IGN;
    sigact.sa_flags = SA_RESTART;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGPIPE, &sigact, nullptr) != 0) {
#ifdef DEBUG_OS
        std::ignore = fprintf(stderr, "os_disable_sigpipe(): failed to disable SIGPIPE handler\n");
#endif
    }
#endif
}

void os_sleep_us(uint64_t timeout_us) {
    if (timeout_us == 0) {
        return;
    }
#ifdef HAVE_SELECT
    // Select without fds just to sleep
    os_select_fds([](select_fd_sets * /*fds*/, const uint64_t * /*timeout_us*/) -> void {},
        [](int /*select_ret*/, select_fd_sets * /*fds*/) -> bool { return false; }, &timeout_us);
#elif defined(HAVE_USLEEP)
    usleep(static_cast<useconds_t>(*timeout_us));
#elif defined(_WIN32)
    Sleep(timeout_us / 1000);
#endif
}

} // namespace cartesi
