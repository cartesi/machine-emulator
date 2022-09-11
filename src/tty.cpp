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

#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "tty.h"

namespace cartesi {

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

void tty_setup(tty_command cmd) {
    static int ttyfd{-1};
    static termios oldtty{};
    switch (cmd) {
        case tty_command::initialize:
            if ((ttyfd = get_ttyfd()) >= 0) {
                struct termios tty {};
                tcgetattr(ttyfd, &tty);
                oldtty = tty;
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
                tcsetattr(ttyfd, TCSANOW, &tty);
                //??D Should we check to see if changes stuck?
            }
            break;
        case tty_command::cleanup:
            if (ttyfd >= 0) {
                tcsetattr(ttyfd, TCSANOW, &oldtty);
                close(ttyfd);
                ttyfd = -1;
            }
            break;
            ;
    }
}

bool tty_poll(uint64_t wait, char *data, size_t max_len, long *actual_len) {
    int fd_max{0};
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

void tty_putchar(uint8_t ch) {
    if (write(STDOUT_FILENO, &ch, 1) < 1) {
        ;
    }
}

} // namespace cartesi
