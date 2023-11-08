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

#if !defined(_WIN32) && !defined(NO_TTY)
#define HAVE_TTY
#endif

#if !defined(_WIN32) && !defined(__wasi__) && !defined(NO_TERMIOS)
#define HAVE_TERMIOS
#endif

#if !defined(_WIN32) && !defined(__wasi__) && !defined(NO_MMAP)
#define HAVE_MMAP
#endif

#include <array>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <system_error>

#include "os.h"
#include "unique-c-ptr.h"

#if defined(HAVE_TTY) || defined(HAVE_MMAP) || defined(HAVE_TERMIOS)
#include <fcntl.h>  // open
#include <unistd.h> // write/read/close
#endif

#ifdef HAVE_TTY
#include <sys/select.h> // select
#endif

#ifdef HAVE_TERMIOS
#include <termios.h> // tcgetattr/tcsetattr
#endif

#ifdef HAVE_MMAP
#include <sys/mman.h> // mmap/munmap
#endif

#ifdef _WIN32
#include <direct.h> // mkdir
#define mkdir(a, b) _mkdir(a)
#else
#include <sys/stat.h> // fstat/mkdir
#endif

namespace cartesi {

using namespace std::string_literals;

#ifdef HAVE_TTY
/// \brief TTY global state
struct tty_state {
    bool initialized{false};
    std::array<char, 1024> buf{}; // Characters in console input buffer
    ssize_t buf_pos{};
    ssize_t buf_len{};
#ifdef HAVE_TERMIOS
    int ttyfd{-1};
    termios oldtty{};
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

void os_open_tty(void) {
#ifdef HAVE_TTY
    auto *s = get_state();
    s->initialized = true;
#ifdef HAVE_TERMIOS
    if (s->ttyfd >= 0) { // Already open
        return;
    }
    const int ttyfd = get_ttyfd();
    if (ttyfd < 0) { // Failed to open tty fd
        return;
    }
    struct termios tty {};
    if (tcgetattr(ttyfd, &tty) < 0) { // Failed to retrieve old mode
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
        close(ttyfd);
        return;
    }
    s->ttyfd = ttyfd;
#endif // HAVE_TERMIOS
#else  // HAVE_TTY
    throw std::runtime_error("unable to open console input, stdin is unsupported in this platform");
#endif // HAVE_TTY
}

void os_close_tty(void) {
#ifdef HAVE_TERMIOS
    auto *s = get_state();
    if (s->ttyfd >= 0) { // Restore old mode
        tcsetattr(s->ttyfd, TCSANOW, &s->oldtty);
        close(s->ttyfd);
        s->ttyfd = 1;
    }
#endif // HAVE_TERMIOS
}

void os_poll_tty(uint64_t wait) {
#ifdef HAVE_TTY
    auto *s = get_state();
    if (!s->initialized) {
        throw std::runtime_error("can't poll console input, it is not initialized");
    }
    if (s->buf_pos < s->buf_len) {
        // Input buffer still has pending characters to be read
        return;
    }

    const int fd_max{0};
    fd_set rfds{};
    timeval tv{};
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(wait);
    FD_ZERO(&rfds); // NOLINT: suppress cause on MacOSX it resolves to __builtin_bzero
    FD_SET(STDIN_FILENO, &rfds);
    if (select(fd_max + 1, &rfds, nullptr, nullptr, &tv) <= 0 || !FD_ISSET(0, &rfds)) {
        // Nothing to read
        return;
    }
    s->buf_len = static_cast<ssize_t>(read(STDIN_FILENO, s->buf.data(), s->buf.size()));

    // If stdin is closed, pass EOF to client
    if (s->buf_len <= 0) {
        s->buf_len = 1;
        s->buf[0] = 4; // CTRL+D
    }
    s->buf_pos = 0;

#else  // HAVE_TTY
    (void) wait;
    throw std::runtime_error("can't poll console input, it is unsupported in this platform");
#endif // HAVE_TTY
}

int os_getchar(void) {
#ifdef HAVE_TTY
    auto *s = get_state();
    if (!s->initialized) {
        throw std::runtime_error("can't get char, console input is not initialized");
    }
    os_poll_tty(0);
    if (s->buf_pos < s->buf_len) {
        return s->buf[s->buf_pos++] + 1;
    }
#else
    throw std::runtime_error("can't get char, console input is unsupported in this platform");
#endif // HAVE_TTY
    return 0;
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
        (void) write(STDOUT_FILENO, &ch, 1);
    }
#else
    fputc_with_line_buffering(ch);
#endif // HAVE_TTY
}

int os_mkdir(const char *path, int mode) {
#ifdef _WIN32
    (void) mode;
    return _mkdir(path);
#else
    return mkdir(path, mode);
#endif
}

unsigned char *os_map_file(const char *path, uint64_t length, bool shared) {
    if (!path || *path == '\0') {
        throw std::runtime_error{"image file path must be specified"s};
    }

#ifdef HAVE_MMAP
    const int oflag = shared ? O_RDWR : O_RDONLY;
    const int mflag = shared ? MAP_SHARED : MAP_PRIVATE;

    // Try to open image file
    const int backing_file = open(path, oflag);
    if (backing_file < 0) {
        throw std::system_error{errno, std::generic_category(), "could not open image file '"s + path + "'"s};
    }

    // Try to get file size
    struct stat statbuf {};
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
    auto *host_memory =
        static_cast<unsigned char *>(mmap(nullptr, length, PROT_READ | PROT_WRITE, mflag, backing_file, 0));
    if (host_memory == MAP_FAILED) { // NOLINT(cppcoreguidelines-pro-type-cstyle-cast,performance-no-int-to-ptr)
        close(backing_file);
        throw std::system_error{errno, std::generic_category(), "could not map image file '"s + path + "' to memory"s};
    }

    // We are can close the file after mapping it, because the OS will retain a reference of the file on its own
    close(backing_file);
#else  // HAVE_MMAP
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
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc, cppcoreguidelines-prefer-member-initializer)
    auto host_memory = static_cast<unsigned char *>(std::calloc(1, length));
    if (!host_memory) {
        throw std::runtime_error{"error allocating memory"s};
    }

    // Read to host memory
    auto read = fread(host_memory, 1, length, fp.get());
    (void) read;
    if (ferror(fp.get())) {
        throw std::system_error{errno, std::generic_category(), "error reading from image file '"s + path + "'"s};
    }
#endif // HAVE_MMAP
    return host_memory;
}

void os_unmap_file(unsigned char *host_memory, uint64_t length) {
#ifdef HAVE_MMAP
    munmap(host_memory, length);
#else
    (void) length;
    std::free(host_memory);
#endif
}

} // namespace cartesi
