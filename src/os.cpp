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

#include "scope-exit.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio> // IWYU pragma: keep
#include <iterator>
#include <span>
#include <stdexcept> // IWYU pragma: keep
#include <system_error>
#include <tuple>
#include <utility>

#ifdef HAVE_THREADS
#include <mutex>
#endif

#include <sys/time.h> // IWYU pragma: keep

#ifdef HAVE_SIGACTION
#include <csignal> // IWYU pragma: keep
#endif

#if defined(HAVE_TTY) || defined(HAVE_TERMIOS) || defined(_WIN32) || defined(HAVE_SELECT)
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

namespace cartesi::os {

#ifdef HAVE_TTY
/// \brief TTY global state
struct tty_state {
    bool resize_pending{false};
    std::array<char, TTY_BUF_SIZE> buf{}; // Characters in console input buffer
    ptrdiff_t buf_pos{};
    ptrdiff_t buf_len{};
    bool buf_eof{false};
    uint16_t cols{TTY_DEFAULT_COLS};
    uint16_t rows{TTY_DEFAULT_ROWS};
    int64_t use_count{0};
#ifdef HAVE_THREADS
    std::mutex mutex;
#endif
#ifdef HAVE_TERMIOS
    int fd{-1};
    termios old_mode{};
#elif defined(_WIN32)
    HANDLE handle{};
    DWORD old_mode{};
#endif

    bool is_tty_open() const {
        return use_count > 0;
    }
};

/// Returns pointer to the global TTY state
static tty_state &get_tty_state() {
    static tty_state s;
    return s;
}

#ifdef HAVE_TERMIOS
static int get_ttyfd() {
    const char *path{};
    // Try to find a terminal file descriptor in priority order
    for (const auto fileno : {STDERR_FILENO, STDOUT_FILENO, STDIN_FILENO}) {
        path = ttyname(fileno);
        if (path != nullptr) {
            break;
        }
    }
    // Fallback to ctermid
    if (path == nullptr) {
        path = ctermid(nullptr);
    }
    if (path == nullptr) {
        errno = ENOTTY; // No terminal
        return -1;
    }
    // Open path
    int fd{-1};
    do { // NOLINT(cppcoreguidelines-avoid-do-while)
        fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    } while (fd == -1 && errno == EINTR);
    return fd;
}
#endif // HAVE_TERMIOS

#ifdef HAVE_SIGACTION
/// \brief Signal raised whenever TTY size changes
static void SIGWINCH_handler(int /*sig*/) {
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (!s.is_tty_open()) {
        return;
    }
    // It's not safe to do complex logic in signal handlers,
    // therefore we will actually update the console size in the next get size request.
    s.resize_pending = true;
}
#endif // HAVE_SIGACTION

static bool update_tty_size() {
#if defined(HAVE_TERMIOS) && defined(HAVE_IOCTL)
    winsize ws{};
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col >= 1 && ws.ws_row >= 1) {
            auto &s = get_tty_state();
            s.cols = ws.ws_col;
            s.rows = ws.ws_row;
            return true;
        }
    }

#elif defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        int rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (cols >= 1 && rows >= 1) {
            auto &s = get_tty_state();
            s.cols = cols;
            s.rows = rows;
            return true;
        }
    }

#endif // defined(HAVE_TERMIOS) && defined(HAVE_IOCTL)
    return false;
}

#endif // HAVE_TTY

void open_tty() {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (s.is_tty_open()) { // Already initialized
        s.use_count++;
        return;
    }

#ifdef HAVE_TERMIOS
    // Open TTY
    const int fd = get_ttyfd();
    if (fd < 0) { // Failed to open tty fd
        throw std::system_error{errno, std::generic_category(), "unable to open a TTY"};
    }
    auto ttyfd_closer = make_scope_fail([&] { close(fd); });

    // Retrieve current TTY mode
    termios old_mode{};
    if (tcgetattr(fd, &old_mode) < 0) {
        throw std::system_error{errno, std::generic_category(), "unable to get TTY mode"};
    }

    // Set terminal to "raw" mode
    termios tty = old_mode;
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
    if (tcsetattr(fd, TCSANOW, &tty) < 0) { // Failed to set raw mode
        throw std::system_error{errno, std::generic_category(), "unable set TTY to raw mode"};
    }

    s.fd = fd;
    s.old_mode = old_mode;

#elif defined(_WIN32)
    // Get stdin handle
    HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
    if (!handle) {
        throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
            "unable to get TTY input handle"};
    }
    // Set console in raw mode
    DWORD old_mode{};
    if (!GetConsoleMode(handle, &old_mode)) {
        throw std::system_error{static_cast<int>(GetLastError()), std::system_category(), "unable to get TTY mode"};
    }
    DWORD tty_mode = old_mode;
    tty_mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    tty_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
    if (!SetConsoleMode(handle, tty_mode)) {
        throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
            "unable to set TTY to raw mode"};
    }

    s.handle = handle;
    s.old_mode = old_mode;
#endif // HAVE_TERMIOS

    // Initialize tty
    s.use_count = 1;

    // Get tty initial size
    std::ignore = update_tty_size();

#ifdef HAVE_SIGACTION
    // Install console resize signal handler
    struct sigaction sigact{};
    sigact.sa_flags = SA_RESTART;
    sigact.sa_handler = SIGWINCH_handler;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGWINCH, &sigact, nullptr) != 0) {
        // Silently ignore the error
    }
#endif

#else
    throw std::runtime_error("unable to open console input, stdin is unsupported in this platform");
#endif // HAVE_TTY
}

void close_tty() noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (--s.use_count > 0) {
        // Still in use by some other machine
        return;
    }

#ifdef HAVE_TERMIOS
    if (s.fd >= 0) { // Restore old mode
        std::ignore = tcsetattr(s.fd, TCSANOW, &s.old_mode);
        std::ignore = close(s.fd);
        s.fd = -1;
        s.old_mode = termios{};
    }

#elif defined(_WIN32)
    if (s.handle) {
        std::ignore = SetConsoleMode(s.handle, s.old_mode);
        s.handle = NULL;
        s.old_mode = 0;
    }

#endif // HAVE_TERMIOS
#endif // HAVE_TTY
}

std::pair<uint16_t, uint16_t> get_tty_size() noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (s.is_tty_open()) {
        // Update console size after a SIGWINCH signal
        if (s.resize_pending) {
            if (update_tty_size()) {
                s.resize_pending = false;
            }
        }
        return {s.cols, s.rows};
    }
#endif
    // Fallback values
    return {TTY_DEFAULT_COLS, TTY_DEFAULT_ROWS};
}

void prepare_tty_select([[maybe_unused]] select_fd_sets *fds) noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    // Ignore if TTY is not initialized or stdin was closed
    if (!s.is_tty_open() || s.buf_eof) {
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

bool poll_selected_tty([[maybe_unused]] int select_ret, [[maybe_unused]] select_fd_sets *fds) noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (!s.is_tty_open()) { // Ignore if TTY is not initialized or stdin was closed
        return false;
    }
    // If we have characters left in buffer, we don't need to obtain more characters
    if (s.buf_pos < s.buf_len || s.buf_eof) {
        return true;
    }

#ifdef _WIN32
    ptrdiff_t len = -1;
    if (s.handle) {
        // Consume input events until buffer is full or the event list is empty
        INPUT_RECORD inputRecord{};
        DWORD numberOfEventsRead = 0;
        while (PeekConsoleInput(s.handle, &inputRecord, 1, &numberOfEventsRead)) {
            if (numberOfEventsRead == 0) {
                // Nothing to read
                return false;
            } else if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
                // Key was pressed
                DWORD numberOfCharsRead = 0;
                // We must read input buffer through ReadConsole() to read raw terminal input
                if (ReadConsole(s.handle, s.buf.data(), s.buf.size(), &numberOfCharsRead, NULL)) {
                    len = static_cast<ptrdiff_t>(numberOfCharsRead);
                }
                break;
            } else {
                // Consume input event
                ReadConsoleInput(s.handle, &inputRecord, 1, &numberOfEventsRead);
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
    // NOLINTNEXTLINE(clang-analyzer-unix.BlockInCriticalSection)
    const auto len = static_cast<ptrdiff_t>(read(STDIN_FILENO, s.buf.data(), s.buf.size()));

#endif // _WIN32

    // If stdin is closed, set EOF
    if (len <= 0) {
        s.buf_eof = true;
        s.buf_len = 0;
    } else {
        s.buf_len = len;
    }
    s.buf_pos = 0;
    return true;
#else
    return false;
#endif
}

void prepare_fd_select([[maybe_unused]] select_fd_sets *fds, [[maybe_unused]] int fd) noexcept {
#ifdef HAVE_SELECT
    if (fd < 0) {
        return;
    }
#ifndef _WIN32
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    FD_SET(fd, readfds);
    fds->maxfd = std::max(fd, fds->maxfd);
#endif
#endif
}

bool poll_selected_fd([[maybe_unused]] int select_ret, [[maybe_unused]] select_fd_sets *fds,
    [[maybe_unused]] int fd) noexcept {
#ifdef HAVE_SELECT
    if (fd < 0) {
        return false;
    }
#ifndef _WIN32
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *readfds = reinterpret_cast<const fd_set *>(fds->readfds);
    return select_ret > 0 && FD_ISSET(fd, readfds);
#else
    return false;
#endif
#else
    return false;
#endif
}

bool poll_tty(uint64_t timeout_us) noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
    {
#ifdef HAVE_THREADS
        const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
        if (!s.is_tty_open()) { // We can't poll when TTY is not initialized
            return false;
        }
    }

#ifdef _WIN32
    // Wait for an input event
    const uint64_t wait_ms = (timeout_us + 999) / 1000;
    if (WaitForSingleObject(s.handle, wait_ms) != WAIT_OBJECT_0) {
        // No input events
        return false;
    }
    return poll_selected_tty(-1, nullptr);

#else
    return select_fds([](select_fd_sets *fds, const uint64_t * /*timeout_us*/) -> void { prepare_tty_select(fds); },
        [](int select_ret, select_fd_sets *fds) -> bool { return poll_selected_tty(select_ret, fds); }, &timeout_us);

#endif // _WIN32

#else
    (void) timeout_us;
    return false;

#endif // HAVE_TTY
}

ptrdiff_t getchars(std::span<uint8_t> buf) noexcept {
#ifdef HAVE_TTY
    auto &s = get_tty_state();
#ifdef HAVE_THREADS
    const std::scoped_lock<std::mutex> lock(s.mutex);
#endif
    if (!s.is_tty_open() || s.buf_eof) {
        errno = EPIPE;
        return -1;
    }
    const auto n = std::min(static_cast<ptrdiff_t>(buf.size()), s.buf_len - s.buf_pos);
    if (n > 0) {
        std::copy_n(std::next(s.buf.begin(), s.buf_pos), n, buf.begin());
        s.buf_pos += n;
    }
    return n;
#else
    return -1;
#endif // HAVE_TTY
}

/// \brief Retry a function call on EINTR error.
/// \param func Function to be retried.
/// \details Some POSIX functions may be interrupted by external signal handlers,
/// this helper ensures that the function is retried until it succeeds or fails with a different error.
template <typename F>
static constexpr auto retry_on_eintr(const F &func) {
    while (true) {
        auto result = func();
        if (!(result == -1 && errno == EINTR)) {
            return result;
        }
    }
}

ptrdiff_t putchars(std::span<const uint8_t> buf, tty_output output) noexcept {
    if (buf.empty()) {
        return 0;
    }
#ifdef HAVE_TTY
    const int fd = (output == tty_output::to_stdout) ? STDOUT_FILENO : STDERR_FILENO;
    return retry_on_eintr([&] { return write(fd, buf.data(), buf.size()); });
#else
    auto *fp = (output == tty_output::to_stdout) ? stdout : stderr;
    errno = 0;
    const auto written_bytes = fwrite(buf.data(), 1, buf.size(), fp);
    if (written_bytes == 0 && ferror(fp) != 0) {
        if (errno == 0) {
            errno = EIO;
        }
        return -1;
    } else if (written_bytes == 0 && feof(fp) != 0) {
        errno = EPIPE;
        return -1;
    }
    if (written_bytes > 0) {
        std::ignore = fflush(fp);
    }
    return static_cast<ptrdiff_t>(written_bytes);
#endif // HAVE_TTY
}

int dup_fd(int fd) {
    if (fd < 0) {
        throw std::system_error{EBADF, std::generic_category(), "invalid file descriptor"};
    }
    const int new_fd = dup(fd);
    if (new_fd == -1) {
        throw std::system_error{errno, std::generic_category(), "dup failed"};
    }
    return new_fd;
}

void close_fd(int fd) noexcept {
    close(fd);
}

ptrdiff_t write_fd(int fd, std::span<const uint8_t> buf) noexcept {
    if (buf.empty()) {
        return 0;
    }
    const auto result = retry_on_eintr([&] { return write(fd, buf.data(), buf.size()); });
    return static_cast<ptrdiff_t>(result);
}

ptrdiff_t read_fd(int fd, std::span<uint8_t> buf) noexcept {
    if (buf.empty()) {
        return 0;
    }
    const auto result = retry_on_eintr([&] { return read(fd, buf.data(), buf.size()); });
    return static_cast<ptrdiff_t>(result);
}

bool select_fds(const select_before_callback &before_cb, const select_after_callback &after_cb, uint64_t *timeout_us) {
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

int64_t now_us() noexcept {
    static const std::chrono::time_point<std::chrono::high_resolution_clock> start{
        std::chrono::high_resolution_clock::now()};
    auto end = std::chrono::high_resolution_clock::now();
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
}

void sleep_us(uint64_t timeout_us) noexcept {
    if (timeout_us == 0) {
        return;
    }
#ifdef HAVE_SELECT
    // Select without fds just to sleep
    select_fds([](select_fd_sets * /*fds*/, const uint64_t * /*timeout_us*/) -> void {},
        [](int /*select_ret*/, select_fd_sets * /*fds*/) -> bool { return false; }, &timeout_us);
#elif defined(HAVE_USLEEP)
    usleep(static_cast<useconds_t>(*timeout_us));
#elif defined(_WIN32)
    Sleep(timeout_us / 1000);
#endif
}

void disable_sigpipe() noexcept {
#ifdef HAVE_SIGACTION
    struct sigaction sigact{};
    sigact.sa_handler = SIG_IGN;
    sigact.sa_flags = SA_RESTART;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGPIPE, &sigact, nullptr) != 0) {
        // Silently ignore the error
    }
#endif
}

} // namespace cartesi::os
