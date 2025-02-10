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
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

#include "compiler-defines.h"
#include "os-features.h"
#include "os.h"
#include "unique-c-ptr.h"

#include <sys/time.h>

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
#include <unistd.h> // write/read/close/usleep/fork
#endif

#if defined(HAVE_FORK)
#include <sys/wait.h> // waitpid
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
    bool silence_putchar{false};
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
    static tty_state data;
    return &data;
}
#endif // HAVE_TTY

/// \brief putchar global state
struct putchar_state {
    bool silence;
};

/// Returns pointer to the global TTY state
static putchar_state *get_putchar_state() {
    static putchar_state data;
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
    char *path{};
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
        // Already initialized
        return;
    }

    s->initialized = true;

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
    if (s->ttyfd >= 0) { // Restore old mode
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = 1;
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
        if (plat_write(STDOUT_FILENO, &ch, 1) < 1) {
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

int os_mkdir(const char *path, [[maybe_unused]] int mode) {
#ifdef HAVE_MKDIR
    return plat_mkdir(path, mode);
#else
    return -1;
#endif // HAVE_MKDIR
}

unsigned char *os_map_file(const char *path, uint64_t length, bool shared) {
    if ((path == nullptr) || *path == '\0') {
        throw std::runtime_error{"image file path must be specified"s};
    }

#ifdef HAVE_MMAP
    const int oflag = shared ? O_RDWR : O_RDONLY;

    // Try to open image file
    const int backing_file = open(path, oflag);
    if (backing_file < 0) {
        throw std::system_error{errno, std::generic_category(), "could not open image file '"s + path + "'"s};
    }

    // Try to get file size
    struct stat statbuf{};
    if (fstat(backing_file, &statbuf) < 0) {
        close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "unable to obtain length of image file '"s + path + "'"s};
    }

    // Check that it matches range length
    if (static_cast<uint64_t>(statbuf.st_size) != length) {
        close(backing_file);
        throw std::invalid_argument{"image file '"s + path + "' size ("s +
            std::to_string(static_cast<uint64_t>(statbuf.st_size)) + ") does not match range length ("s +
            std::to_string(length) + ")"s};
    }

    // Try to map image file to host memory
    const int mflag = shared ? MAP_SHARED : MAP_PRIVATE;
    auto *host_memory =
        static_cast<unsigned char *>(mmap(nullptr, length, PROT_READ | PROT_WRITE, mflag, backing_file, 0));
    if (host_memory == MAP_FAILED) { // NOLINT(cppcoreguidelines-pro-type-cstyle-cast,performance-no-int-to-ptr)
        close(backing_file);
        throw std::system_error{errno, std::generic_category(), "could not map image file '"s + path + "' to memory"s};
    }

    // We can close the file after mapping it, because the OS will retain a reference of the file on its own
    close(backing_file);
    return host_memory;

#elif defined(_WIN32)
    const int oflag = (shared ? _O_RDWR : _O_RDONLY) | _O_BINARY;

    // Try to open image file
    const int backing_file = _open(path, oflag);
    if (backing_file < 0) {
        throw std::system_error{errno, std::generic_category(), "could not open image file '"s + path + "'"s};
    }

    // Try to get file size
    struct __stat64 statbuf{};
    if (_fstat64(backing_file, &statbuf) < 0) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "unable to obtain length of image file '"s + path + "'"s};
    }

    // Check that it matches range length
    if (static_cast<uint64_t>(statbuf.st_size) != length) {
        _close(backing_file);
        throw std::invalid_argument{"image file '"s + path + "' size ("s +
            std::to_string(static_cast<uint64_t>(statbuf.st_size)) + ") does not match range length ("s +
            std::to_string(length) + ")"s};
    }

    // Try to map image file to host memory
    DWORD flProtect = shared ? PAGE_READWRITE : PAGE_READONLY;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    HANDLE hFile = reinterpret_cast<HANDLE>(_get_osfhandle(backing_file));
    HANDLE hFileMappingObject = CreateFileMapping(hFile, NULL, flProtect, length >> 32, length & 0xffffffff, NULL);
    if (!hFileMappingObject) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(), "could not map image file '"s + path + "' to memory"s};
    }

    DWORD dwDesiredAccess = shared ? FILE_MAP_WRITE : FILE_MAP_COPY;
    auto *host_memory = static_cast<unsigned char *>(MapViewOfFile(hFileMappingObject, dwDesiredAccess, 0, 0, length));
    if (!host_memory) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(), "could not map image file '"s + path + "' to memory"s};
    }

    // We can close the file after mapping it, because the OS will retain a reference of the file on its own
    _close(backing_file);
    return host_memory;

#else
    if (shared) {
        throw std::runtime_error{"shared image file mapping is unsupported"s};
    }

    auto fp = unique_fopen(path, "rb", std::nothrow_t{});
    if (!fp) {
        throw std::system_error{errno, std::generic_category(), "error opening image file '"s + path + "'"s};
    }
    // Get file size
    if (fseek(fp.get(), 0, SEEK_END)) {
        throw std::system_error{errno, std::generic_category(),
            "error obtaining length of image file '"s + path + "'"s};
    }
    auto file_length = ftell(fp.get());
    if (fseek(fp.get(), 0, SEEK_SET)) {
        throw std::system_error{errno, std::generic_category(),
            "error obtaining length of image file '"s + path + "'"s};
    }
    // Check against PMA range size
    if (static_cast<uint64_t>(file_length) > length) {
        throw std::runtime_error{"image file '"s + path + "' of "s + " is too large for range"s};
    }

    // use calloc to improve performance
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    auto host_memory = static_cast<unsigned char *>(std::calloc(1, length));
    if (!host_memory) {
        throw std::runtime_error{"error allocating memory"s};
    }

    // Read to host memory
    std::ignore = fread(host_memory, 1, length, fp.get());
    if (ferror(fp.get())) {
        throw std::system_error{errno, std::generic_category(), "error reading from image file '"s + path + "'"s};
    }
    return host_memory;

#endif // HAVE_MMAP
}

void os_unmap_file(unsigned char *host_memory, [[maybe_unused]] uint64_t length) {
#ifdef HAVE_MMAP
    munmap(host_memory, length);

#elif defined(_WIN32)
    UnmapViewOfFile(host_memory);

#else
    std::free(host_memory);

#endif // HAVE_MMAP
}

int64_t os_now_us() {
    static std::chrono::time_point<std::chrono::high_resolution_clock> start{};
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
        const parallel_for_mutex for_mutex = {.lock = [&] { mutex.lock(); }, .unlock = [&] { mutex.unlock(); }};
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
    const parallel_for_mutex for_mutex{.lock = [] {}, .unlock = [] {}};
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

#ifdef HAVE_FORK
static void sig_alrm(int /*unused*/) {
    ;
}
#endif

// this function forks and intermediate child, and the intermediate child forks a final child
// the intermediate child simply exits immediately
// the final child sends its pid to the parent via a pipe
// the parent returns the final child pid
// the final child returns 0
// on error, the parent throws and the final child does not return
int os_double_fork_or_throw([[maybe_unused]] bool emancipate) {
#ifdef HAVE_FORK
    int fd[2] = {-1, -1};
    struct sigaction chld_act{};
    bool restore_sigchld = false;
    struct sigaction alrm_act{};
    bool restore_sigalrm = false;
    sigset_t omask{};
    bool restore_sigprocmask = false;
    try {
        if (pipe(fd) < 0) {
            throw std::system_error{errno, std::generic_category(), "pipe failed"};
        }
        // make sure we can wait on our child
        struct sigaction act{};
        sigemptyset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        act.sa_flags = 0;
        if (sigaction(SIGCHLD, &act, &chld_act) < 0) {
            throw std::system_error{errno, std::generic_category(), "sigaction failed setting SIGCHLD handler"};
        }
        restore_sigchld = true;
        // make sure we will receive an alarm that will interrupt a call to read()
        act.sa_handler = sig_alrm;
        act.sa_flags = 0;
        if (sigaction(SIGALRM, &act, &alrm_act) < 0) {
            throw std::system_error{errno, std::generic_category(), "sigaction failed setting SIGALRM handler"};
        }
        restore_sigalrm = true;
        sigset_t mask{};
        sigemptyset(&mask);        // always returns 0
        sigaddset(&mask, SIGALRM); // always returns 0
        sigaddset(&mask, SIGCHLD); // always returns 0
        if (sigprocmask(SIG_UNBLOCK, &mask, &omask) < 0) {
            throw std::system_error{errno, std::generic_category(), "sigprocmask unblocking SIGALRM and SIGCHLD"};
        }
        restore_sigprocmask = true;
        auto ipid = fork();
        if (ipid == 0) { // intermediate child (fork succeeded)
            auto fpid = fork();
            if (fpid == 0) { // final child (fork succeeded)
                // restore signal mask
                if (sigprocmask(SIG_SETMASK, &omask, nullptr) < 0) {
                    exit(1);
                }
                // restore SIGALRM handler
                if (sigaction(SIGALRM, &alrm_act, nullptr) < 0) {
                    exit(1);
                }
                // restore SIGCHLD handler
                if (sigaction(SIGCHLD, &chld_act, nullptr) < 0) {
                    exit(1);
                }
                // close read-end of pipe
                close(fd[0]);
                fd[0] = -1;
                // break out into our own program group, if requested
                if (emancipate) {
                    setpgid(0, 0);
                }
                // write fpid so parent can read
                fpid = getpid();
                if (write(fd[1], &fpid, sizeof(fpid)) != sizeof(fpid)) {
                    exit(0);
                }
                // close write-end of pipe
                close(fd[1]);
                fd[1] = -1;
                // we are done and can return to whatever caller wants to do as a child
                return 0;
            }
            // intermediate child, fork either failed or succeeded
            exit(0); // intermediate child exits right away

        } else if (ipid > 0) {         // still parent (fork succeeded)
            waitpid(ipid, nullptr, 0); // wait on dead intermediate child so it doesn't become a zombie
            // set alarm so we can't hang while waiting to read final child pid from pipe
            struct itimerval timer{};
            memset(&timer, 0, sizeof(timer));
            timer.it_interval.tv_sec = 0;
            timer.it_interval.tv_usec = 0;
            timer.it_value.tv_sec = 10;
            timer.it_value.tv_usec = 0;
            struct itimerval oitimer{};
            memset(&oitimer, 0, sizeof(oitimer));
            if (setitimer(ITIMER_REAL, &timer, &oitimer) < 0) {
                throw std::system_error{errno, std::generic_category(), "setitimer failed"};
            }
            try {
                int fpid = 0;
                const auto ret = read(fd[0], &fpid, sizeof(fpid));
                if (ret != sizeof(fpid)) {
                    if (ret < 0) {
                        auto e = errno;
                        if (e == EINTR) {
                            throw std::runtime_error{"parent gave up waiting for child pid"};
                        }
                        throw std::system_error{e, std::generic_category(), "failed to read child pid"};
                    }
                    throw std::runtime_error{"failed to read child pid"};
                }
                // cleanup
                close(fd[1]);
                fd[1] = -1; // close write-end of pipe
                close(fd[0]);
                fd[0] = -1; // close read-end of pipe
                sigaction(SIGCHLD, &chld_act, nullptr);
                sigaction(SIGALRM, &alrm_act, nullptr);
                sigprocmask(SIG_SETMASK, &omask, nullptr);
                setitimer(ITIMER_REAL, &oitimer, nullptr);
                // we are done and can return to whatever caller wants to do as parent
                return fpid;
            } catch (...) {
                setitimer(ITIMER_REAL, &oitimer, nullptr);
                throw; // rethrow so we can finish cleaning up
            }
        } else {
            throw std::system_error{errno, std::generic_category(), "fork failed"};
        }
    } catch (...) {
        if (restore_sigchld) {
            sigaction(SIGCHLD, &chld_act, nullptr);
        }
        if (restore_sigalrm) {
            sigaction(SIGALRM, &alrm_act, nullptr);
        }
        if (restore_sigprocmask) {
            sigprocmask(SIG_SETMASK, &omask, nullptr);
        }
        if (fd[0] >= 0) {
            close(fd[0]);
        }
        if (fd[1] >= 0) {
            close(fd[1]);
        }
        throw; // rethrow so caller can see why we failed
    }
#else
    throw std::runtime_error{"fork() is unsupported in this platform"s};
    return -1;
#endif
}

int os_double_fork([[maybe_unused]] bool emancipate, [[maybe_unused]] const char **err_msg) {
#ifdef HAVE_FORK
    static THREAD_LOCAL std::string error_storage;
    try {
        *err_msg = nullptr;
        return os_double_fork_or_throw(emancipate);
    } catch (std::exception &e) {
        error_storage = e.what();
        *err_msg = error_storage.c_str();
        return -1;
    }
#else
    *err_msg = "fork() is unsupported in this platform";
    return -1;
#endif
}

int64_t os_get_file_length(const char *filename, const char *text) {
    auto fp = unique_fopen(filename, "rb");
    if (fseek(fp.get(), 0, SEEK_END) != 0) {
        throw std::system_error{errno, std::generic_category(),
            "unable to obtain length of file '"s + filename + "' "s + text};
    }
    const auto length = ftell(fp.get());
    if (length < 0) {
        throw std::system_error{errno, std::generic_category(),
            "unable to obtain length of file '"s + filename + "' "s + text};
    }
    return length;
}

bool os_file_exists(const char *filename) {
    struct stat buffer{};
    return (stat(filename, &buffer) == 0);
}

} // namespace cartesi
