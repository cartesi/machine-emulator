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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "is-pristine.h"
#include "os-features.h"
#include "os.h"
#include "unique-c-ptr.h"

#ifdef HAVE_SIGACTION
#include <csignal>
#endif

#ifdef HAVE_THREADS
#include <future>
#include <mutex>
#include <thread>
#endif

#if defined(HAVE_TTY) || defined(HAVE_MMAP) || defined(HAVE_TERMIOS) || defined(_WIN32)
#include <fcntl.h> // open
#endif

#ifdef HAVE_TERMIOS
#include <termios.h> // tcgetattr/tcsetattr
#ifdef HAVE_IOCTL
#include <sys/ioctl.h> // ioctl
#endif
#endif

#ifdef HAVE_MMAP
#include <sys/mman.h> // mmap/munmap
#endif

#if defined(HAVE_MMAP) || defined(HAVE_MKDIR) || defined(_WIN32)
#include <sys/stat.h> // fstat/mkdir
#endif

#if defined(HAVE_FLOCK)
#include <sys/file.h> // flock
#endif

#ifdef HAVE_FICLONE
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
#endif

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <direct.h> // mkdir
#include <io.h>     // _write/_close
#include <windows.h>

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 0
#endif

#define plat_write _write
#define plat_mkdir(a, mode) _mkdir(a)

#if defined(HAVE_SELECT)
#include <winsock2.h> // select
#endif

#else // not _WIN32

#if defined(HAVE_TTY) || defined(HAVE_MMAP) || defined(HAVE_TERMIOS) || defined(HAVE_USLEEP)
#include <unistd.h> // write/read/close
#endif

#if defined(HAVE_SELECT)
#include <sys/select.h> // select
#endif

#define plat_write write
#define plat_mkdir mkdir

#endif // _WIN32

// Enable these defines to debug
// #define DEBUG_OS

namespace cartesi {

using namespace std::string_literals;

#ifdef HAVE_TTY
/// \brief TTY global state
struct tty_state {
    bool initialized{false};
    bool resize_pending{false};
    std::array<char, TTY_BUF_SIZE> buf{}; // Characters in console input buffer
    intptr_t buf_pos{};
    intptr_t buf_len{};
    unsigned short cols{TTY_DEFAULT_COLS};
    unsigned short rows{TTY_DEFAULT_ROWS};
#ifdef HAVE_TERMIOS
    int ttyfd{-1};
    termios oldtty{};
#elif defined(_WIN32)
    HANDLE hStdin{};
    DWORD dwOldStdinMode{};
#endif
};

/// Returns pointer to the global TTY state
static tty_state *get_state() {
    static tty_state data;
    return &data;
}
#endif // HAVE_TTY

#ifdef HAVE_TERMIOS
static int new_ttyfd(const char *path) {
    int fd{};
    do { // NOLINT(cppcoreguidelines-avoid-do-while)
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
#endif // HAVE_TERMIOS

#ifdef HAVE_SIGACTION
/// \brief Signal raised whenever TTY size changes
static void os_SIGWINCH_handler(int sig) {
    (void) sig;
    auto *s = get_state();
    if (!s->initialized) {
        return;
    }
    // It's not safe to do complex logic in signal handlers,
    // therefore we will actually update the console size in the next get size request.
    s->resize_pending = true;
}
#endif

bool os_update_tty_size(tty_state *s) {
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
        (void) fprintf(stderr, "os_update_tty_size(): ioctl TIOCGWINSZ failed\n");
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
        (void) fprintf(stderr, "os_update_tty_size(): GetConsoleScreenBufferInfo failed\n");
#endif
    }

#endif // defined(HAVE_TERMIOS) && defined(HAVE_IOCTL)
#endif // HAVE_TTY
    return false;
}

void os_open_tty(void) {
#ifdef HAVE_TTY
    auto *s = get_state();
    if (s->initialized) {
        // Already initialized
        return;
    }

    s->initialized = true;

#ifdef HAVE_TERMIOS
    if (s->ttyfd >= 0) { // Already open
#ifdef DEBUG_OS
        (void) fprintf(stderr, "os_open_tty(): tty already open\n");
#endif
        return;
    }
    const int ttyfd = get_ttyfd();
    if (ttyfd < 0) { // Failed to open tty fd
#ifdef DEBUG_OS
        (void) fprintf(stderr, "os_open_tty(): get_tty() failed\n");
#endif
        return;
    }
    struct termios tty {};
    if (tcgetattr(ttyfd, &tty) < 0) { // Failed to retrieve old mode
#ifdef DEBUG_OS
        (void) fprintf(stderr, "os_open_tty(): failed retrieve old mode\n");
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
        (void) fprintf(stderr, "os_open_tty(): failed to set raw mode\n");
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
        (void) fprintf(stderr, "os_open_tty(): GetStdHandle() failed\n");
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
            (void) fprintf(stderr, "os_open_tty(): SetConsoleMode() failed\n");
#endif
        }
    }
#endif // HAVE_TERMIOS

    // Get tty initial size
    os_update_tty_size(s);

#ifdef HAVE_SIGACTION
    // Install console resize signal handler
    struct sigaction sigact {};
    sigact.sa_flags = SA_RESTART;
    sigact.sa_handler = os_SIGWINCH_handler;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGWINCH, &sigact, nullptr) != 0) {
#ifdef DEBUG_OS
        (void) fprintf(stderr, "os_open_tty(): failed to install SIGWINCH handler\n");
#endif
    }
#endif

#else
    throw std::runtime_error("unable to open console input, stdin is unsupported in this platform");
#endif // HAVE_TTY
}

void os_close_tty(void) {
#ifdef HAVE_TTY
#ifdef HAVE_TERMIOS
    auto *s = get_state();
    if (s->ttyfd >= 0) { // Restore old mode
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = 1;
    }

#elif defined(_WIN32)
    auto *s = get_state();
    if (s->hStdin) {
        SetConsoleMode(s->hStdin, s->dwOldStdinMode);
        s->hStdin = NULL;
    }

#endif // HAVE_TERMIOS
#endif // HAVE_TTY
}

void os_get_tty_size(uint16_t *pwidth, uint16_t *pheight) {
    auto *s = get_state();
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

void os_prepare_tty_select(select_fd_sets *fds) {
#ifdef HAVE_TTY
    auto *s = get_state();
    // Ignore if TTY is not initialized or stdin was closed
    if (!s->initialized) {
        return;
    }
#ifndef _WIN32
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    fd_set *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    FD_SET(STDIN_FILENO, readfds);
    if (STDIN_FILENO > fds->maxfd) {
        fds->maxfd = STDIN_FILENO;
    }
#else
    (void) fds;
#endif
#endif
}

bool os_poll_selected_tty(int select_ret, select_fd_sets *fds) {
    auto *s = get_state();
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
    fd_set *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    // If the stdin file description is not ready, we can't obtain more characters
    if (select_ret <= 0 || !FD_ISSET(STDIN_FILENO, readfds)) {
        return false;
    }
    const intptr_t len = static_cast<intptr_t>(read(STDIN_FILENO, s->buf.data(), s->buf.size()));

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
    auto *s = get_state();
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
        [](select_fd_sets *fds, const uint64_t *timeout_us) -> void {
            (void) timeout_us;
            os_prepare_tty_select(fds);
        },
        [](int select_ret, select_fd_sets *fds) -> bool { return os_poll_selected_tty(select_ret, fds); }, &timeout_us);

#endif // _WIN32
}

int os_getchar(void) {
#ifdef HAVE_TTY
    auto *s = get_state();
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
    (void) fputc(ch, stdout);
    // On Linux, stdout in fully buffered by default when it's not a TTY,
    // here we flush every new line to perform line buffering.
    if (ch == '\n') {
        (void) fflush(stdout);
    }
}

void os_putchar(uint8_t ch) {
#ifdef HAVE_TTY
    auto *s = get_state();
    if (!s->initialized) {
        // Write through fputc(), so we can take advantage of buffering.
        fputc_with_line_buffering(ch);
    } else {
        // In interactive sessions we want to immediately write the character to stdout,
        // without any buffering.
        if (plat_write(STDOUT_FILENO, &ch, 1) < 1) {
            ;
        }
    }
#else
    fputc_with_line_buffering(ch);
#endif // HAVE_TTY
}

void os_putchars(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        os_putchar(data[i]);
    }
}

void os_mkdir(const char *path, int mode) {
#ifdef HAVE_MKDIR
    if (plat_mkdir(path, mode) != 0) {
        throw std::system_error{errno, std::generic_category(),
            "error creating directory '"s + std::string(path) + "'"s};
    }
#else
    throw std::runtime_error("mkdir() is not supported");
#endif // HAVE_MKDIR
}

int64_t os_now_us() {
    std::chrono::time_point<std::chrono::high_resolution_clock> start{};
    static bool started = false;
    if (!started) {
        started = true;
        start = std::chrono::high_resolution_clock::now();
    }
    auto end = std::chrono::high_resolution_clock::now();
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
}

uint64_t os_get_concurrency() {
#ifdef HAVE_THREADS
    return std::thread::hardware_concurrency();
#else
    return 1;
#endif
}

bool os_parallel_for(uint64_t n, const std::function<bool(uint64_t j, const parallel_for_mutex &mutex)> &task) {
#ifdef HAVE_THREADS
    if (n > 1) {
        std::mutex mutex;
        const parallel_for_mutex for_mutex = {[&] { mutex.lock(); }, [&] { mutex.unlock(); }};
        std::vector<std::future<bool>> futures;
        futures.reserve(n);
        for (uint64_t j = 0; j < n; ++j) {
            futures.emplace_back(std::async(std::launch::async, task, j, for_mutex));
        }
        // Check if any thread failed
        bool succeeded = true;
        for (auto &f : futures) {
            succeeded = succeeded && f.get();
        }
        // Return overall status
        return succeeded;
    }
#endif
    // Run without extra threads when concurrency is 1 or as fallback
    const parallel_for_mutex for_mutex{[] {}, [] {}};
    bool succeeded = true;
    for (uint64_t j = 0; j < n; ++j) {
        succeeded = succeeded && task(j, for_mutex);
    }
    return succeeded;
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
    struct sigaction sigact {};
    sigact.sa_handler = SIG_IGN;
    sigact.sa_flags = SA_RESTART;
    if (sigemptyset(&sigact.sa_mask) != 0 || sigaction(SIGPIPE, &sigact, nullptr) != 0) {
#ifdef DEBUG_OS
        (void) fprintf(stderr, "os_disable_sigpipe(): failed to disable SIGPIPE handler\n");
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
    os_select_fds(
        [](select_fd_sets *fds, const uint64_t *timeout_us) -> void {
            (void) fds;
            (void) timeout_us;
        },
        [](int select_ret, select_fd_sets *fds) -> bool {
            (void) select_ret;
            (void) fds;
            return false;
        },
        &timeout_us);
#elif defined(HAVE_USLEEP)
    usleep(static_cast<useconds_t>(*timeout_us));
#elif defined(_WIN32)
    Sleep(timeout_us / 1000);
#endif
}

void os_copy_reflink(const char *oldpath, const char *newpath) {
#ifdef HAVE_POSIX_FS
    int src_fd = -1;
    int dest_fd = -1;
    try {
        // Open source file
        src_fd = open(oldpath, O_RDONLY);
        if (src_fd < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to open file '"s + oldpath + "' for read"s};
        }
#ifdef HAVE_FLOCK
        // Lock source file
        if (flock(src_fd, LOCK_SH | LOCK_NB) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to lock file '"s + oldpath + "' for read"s};
        }
#endif

        // Open destination file
        const int mode = (S_IRUSR | S_IWUSR) | S_IRGRP | S_IROTH;
        dest_fd = open(newpath, O_WRONLY | O_CREAT | O_EXCL, mode);
        if (dest_fd < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to open file '"s + newpath + "' for write"s};
        }
#ifdef HAVE_FLOCK
        // Lock destination file
        if (flock(dest_fd, LOCK_EX | LOCK_NB) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to lock file '"s + newpath + "' for write"s};
        }
#endif

        // Clone file
        if (ioctl(dest_fd, FICLONE, src_fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to clone file '"s + newpath + "'"s};
        }

        // Close source file
        if (close(src_fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + oldpath + "'"s};
        }
        src_fd = -1;

        // Close destination file
        if (close(dest_fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + newpath + "'"s};
        }
        dest_fd = -1;
    } catch (std::exception &e) {
        if (src_fd != -1) {
            close(src_fd);
        }
        if (dest_fd != -1) {
            close(dest_fd);
            unlink(newpath); // revert file creation
        }
        throw;
    }
#else
    throw std::runtime_error{"copy reflink is unsupported in this platform"};
#endif
}

void os_copy_file(const char *oldpath, const char *newpath) {
    // TODO(edubart): copy read-only files with hardlinks ?
    // TODO(edubart): copy using COW

#ifdef HAVE_POSIX_FS
    int src_fd = -1;
    int dest_fd = -1;
    try {
        // Open source file
        src_fd = open(oldpath, O_RDONLY);
        if (src_fd < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to open file '"s + oldpath + "' for read"s};
        }
#ifdef HAVE_FLOCK
        // Lock source file
        if (flock(src_fd, LOCK_SH | LOCK_NB) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to lock file '"s + oldpath + "' for read"s};
        }
#endif
        // Get source file length
        struct stat src_statbuf {};
        if (fstat(src_fd, &src_statbuf) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to obtain length of file '"s + oldpath + "'"s};
        }
        const uint64_t src_length = static_cast<uint64_t>(src_statbuf.st_size);

        // Open destination file
        const int mode = (S_IRUSR | S_IWUSR) | S_IRGRP | S_IROTH;
        dest_fd = open(newpath, O_RDWR | O_CREAT | O_EXCL, mode);
        if (dest_fd < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to open file '"s + newpath + "' for write"s};
        }
#ifdef HAVE_FLOCK
        // Lock destination file
        if (flock(dest_fd, LOCK_EX | LOCK_NB) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to lock file '"s + newpath + "' for write"s};
        }
#endif
        // Truncate destination file to a sparse file
        if (ftruncate(dest_fd, static_cast<off_t>(src_length)) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to truncate file '"s + newpath + "'"s};
        }

        // Copy in chunks of 4096 bytes
        uint8_t buf[4096];
        for (uint64_t off = 0; off < src_length;) {
            const size_t len = std::min<size_t>(static_cast<size_t>(src_length - off), sizeof(buf));
            const ssize_t read_len = pread(src_fd, buf, len, static_cast<off_t>(off));
            if (read_len < 0) {
                throw std::system_error{errno, std::generic_category(), "unable to read file '"s + oldpath + "'"s};
            } else if (static_cast<size_t>(read_len) != len) {
                throw std::runtime_error{"unable to read file '"s + oldpath + "'"s};
            }
            // Write only non zeros chunks (to keep file sparse)
            if (!is_pristine(buf, len)) {
                const ssize_t written_len = pwrite(dest_fd, buf, len, static_cast<off_t>(off));
                if (written_len < 0) {
                    throw std::system_error{errno, std::generic_category(), "unable to write file '"s + newpath + "'"s};
                } else if (static_cast<size_t>(written_len) != len) {
                    throw std::runtime_error{"unable to write file '"s + newpath + "'"s};
                }
            }
            off += len;
        }

        // Close source file
        if (close(src_fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + oldpath + "'"s};
        }
        src_fd = -1;

        // Close destination file
        if (close(dest_fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + newpath + "'"s};
        }
        dest_fd = -1;
    } catch (std::exception &e) {
        if (src_fd != -1) {
            close(src_fd);
        }
        if (dest_fd != -1) {
            close(dest_fd);
            unlink(newpath); // revert file creation
        }
        throw;
    }

#else
    // TODO(edubart): remove file on failure
    auto src_fp = unique_fopen(oldpath, "rb");
    auto dest_fp = unique_fopen(newpath, "wb");

    char buf[4096];
    while (true) {
        const size_t size = fread(buf, 1, sizeof(buf), src_fp.get());
        if (size == 0) {
            if (feof(src_fp.get()) != 0) { // end of file
                break;
            } else {
                throw std::system_error{errno, std::generic_category(),
                    "could not read file '"s + std::string(oldpath) + "'"s};
            }
        }
        const size_t written = fwrite(buf, 1, size, dest_fp.get());
        if (written != size) {
            throw std::system_error{errno, std::generic_category(),
                "could not write file '"s + std::string(newpath) + "'"s};
        }
    }

#endif
}

void os_write_file(const char *path, const unsigned char *data, size_t length) {

#ifdef HAVE_POSIX_FS
    int fd = -1;
    try {
        // Open destination file
        const int mode = (S_IRUSR | S_IWUSR) | S_IRGRP | S_IROTH;
        fd = open(path, O_RDWR | O_CREAT | O_EXCL, mode);
        if (fd < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to open file '"s + path + "' for write"s};
        }
#ifdef HAVE_FLOCK
        // Lock destination file
        if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to lock file '"s + path + "' for write"s};
        }
#endif
        // Truncate destination file to a sparse file
        if (ftruncate(fd, static_cast<off_t>(length)) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to truncate file '"s + path + "'"s};
        }

        // Copy in chunks of 4096 bytes
        for (size_t off = 0; off < length;) {
            const size_t len = std::min<size_t>(static_cast<size_t>(length - off), 4096);
            const unsigned char *buf = &data[off];
            // Write only non zeros chunks (to keep file sparse)
            if (!is_pristine(buf, len)) {
                const ssize_t written_len = pwrite(fd, buf, len, static_cast<off_t>(off));
                if (written_len < 0) {
                    throw std::system_error{errno, std::generic_category(), "unable to write file '"s + path + "'"s};
                } else if (static_cast<size_t>(written_len) != len) {
                    throw std::runtime_error{"unable to write file '"s + path + "'"s};
                }
            }
            off += len;
        }

        // Close destination file
        if (close(fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + path + "'"s};
        }
        fd = -1;
    } catch (std::exception &e) {
        if (fd != -1) {
            close(fd);
            unlink(path); // revert file creation
        }
        throw;
    }
#else
    auto fp = unique_fopen(name.c_str(), "wb");
    if (fwrite(data, 1, length, fp.get()) != pma.get_length()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }

#endif
}

void os_grow_file(const char *path, uint64_t length, bool create) {
    // TODO(edubart): fallback implementation

    int fd = -1;
    try {
        int oflags = O_RDWR;
        int omode = 0;
        if (create) {
            oflags |= O_CREAT | O_EXCL;
            omode = (S_IRUSR | S_IWUSR) | S_IRGRP | S_IROTH;
        }
        fd = open(path, oflags, omode);
        if (fd < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to create file '"s + path + "'"s};
        }
        struct stat statbuf {};
        if (fstat(fd, &statbuf) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to obtain length of file '"s + path + "'"s};
        }
        const uint64_t file_length = static_cast<uint64_t>(statbuf.st_size);
        if (length < file_length) {
            throw std::system_error{errno, std::generic_category(), "shrinking file '"s + path + "' is not allowed"s};
        }
        if (ftruncate(fd, static_cast<off_t>(length)) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to truncate file '"s + path + "'"s};
        }
        if (close(fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "unable to close file '"s + path + "'"s};
        }
    } catch (std::exception &e) {
        if (fd != -1) {
            close(fd);
            if (create) { // revert file creation
                unlink(path);
            }
        }
        throw;
    }
}

bool os_exists(const char *path) {
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

void os_unlink(const char *path, bool force) {
    if (unlink(path) < 0 && !force) {
        throw std::system_error{errno, std::generic_category(), "unable to unlink file '"s + path + "'"s};
    }
}

void os_rmdir(const char *path, bool force) {
    if (rmdir(path) < 0 && force) {
        throw std::system_error{errno, std::generic_category(), "unable to remove directory '"s + path + "'"s};
    }
}

void os_unlock_fd(int fd, const char *path) {
    if (flock(fd, LOCK_UN | LOCK_NB) < 0) {
        throw std::system_error{errno, std::generic_category(), "unable to unlock file'"s + path + "' for write"s};
    }
}

void os_lock_fd(int fd, const char *path, bool write) {
    if (flock(fd, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) < 0) {
        throw std::system_error{errno, std::generic_category(), "unable to lock file'"s + path + "' for write"s};
    }
}

} // namespace cartesi
