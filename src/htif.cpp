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

#include "htif.h"
#include "i-device-state-access.h"
#include "machine.h"
#include "strict-aliasing.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

#include <csignal>
#include <iostream>

namespace cartesi {

static constexpr auto htif_tohost_rel_addr = static_cast<uint64_t>(htif::csr::tohost);
static constexpr auto htif_fromhost_rel_addr = static_cast<uint64_t>(htif::csr::fromhost);
static constexpr auto htif_ihalt_rel_addr = static_cast<uint64_t>(htif::csr::ihalt);
static constexpr auto htif_iconsole_rel_addr = static_cast<uint64_t>(htif::csr::iconsole);
static constexpr auto htif_iyield_rel_addr = static_cast<uint64_t>(htif::csr::iyield);

int htif::console_getchar(void) {
    if (m_console_getchar) { // to be extra safe
        poll_console(0);
        if (m_buf_pos < m_buf_len) {
            return m_buf[m_buf_pos++] + 1;
        }
    }
    return 0;
}

uint64_t htif::get_csr_rel_addr(csr reg) {
    return static_cast<uint64_t>(reg);
}

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

void htif::init_console(void) {
    if ((m_ttyfd = get_ttyfd()) >= 0) {
        struct termios tty {};
        tcgetattr(m_ttyfd, &tty);
        m_oldtty = tty;
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
        tcsetattr(m_ttyfd, TCSANOW, &tty);
        //??D Should we check to see if changes stuck?
    }
}

void htif::poll_console(uint64_t wait) {
    // Check for input from console, if requested by HTIF
    // Obviously, somethind different must be done in blockchain
    // If we don't have any characters left in buffer, try to obtain more
    if (m_buf_pos >= m_buf_len) {
        int fd_max{0};
        fd_set rfds{};
        timeval tv{};
        tv.tv_usec = static_cast<suseconds_t>(wait);
        FD_ZERO(&rfds); // NOLINT: suppress cause on MacOSX it resolves to __builtin_bzero
        FD_SET(STDIN_FILENO, &rfds);
        if (select(fd_max + 1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(0, &rfds)) {
            m_buf_pos = 0;
            m_buf_len = read(STDIN_FILENO, m_buf.data(), m_buf.size());
            // If stdin is closed, pass EOF to client
            if (m_buf_len <= 0) {
                m_buf_len = 1;
                m_buf[0] = 4; // CTRL+D
            }
        }
    }
}

void htif::end_console(void) {
    if (m_ttyfd >= 0) {
        tcsetattr(m_ttyfd, TCSANOW, &m_oldtty);
        close(m_ttyfd);
    }
}

// The constructor for the associated machine is typically *not* done
// yet when the constructor for the HTIF device is invoked.
htif::htif(const htif_config &h) :
    m_console_getchar{h.console_getchar},
    m_buf{},
    m_buf_pos{},
    m_buf_len{},
    m_ttyfd{-1},
    m_oldtty{} {
    if (m_console_getchar) {
        init_console();
    }
}

htif::~htif() {
    if (m_console_getchar) {
        end_console();
    }
}

/// \brief HTIF device read callback. See ::pma_read.
static bool htif_read(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t *pval, int log2_size) {
    (void) pma;

    // Our HTIF only supports aligned 64-bit reads
    if (log2_size != 3 || offset & 7) {
        return false;
    }

    switch (offset) {
        case htif_tohost_rel_addr:
            *pval = a->read_htif_tohost();
            return true;
        case htif_fromhost_rel_addr:
            *pval = a->read_htif_fromhost();
            return true;
        case htif_ihalt_rel_addr:
            *pval = a->read_htif_ihalt();
            return true;
        case htif_iconsole_rel_addr:
            *pval = a->read_htif_iconsole();
            return true;
        case htif_iyield_rel_addr:
            *pval = a->read_htif_iyield();
            return true;
        default:
            // other reads are exceptions
            return false;
    }
}

static bool htif_halt(i_device_state_access *a, htif *h, uint64_t cmd, uint64_t data) {
    (void) h;
    if (cmd == HTIF_HALT_HALT && (data & 1)) {
        a->set_iflags_H();
    }
    //??D Write acknowledgement to fromhost???
    // a->write_htif_fromhost(htif_build(HTIF_DEVICE_HALT,
    //     HTIF_HALT_HALT, cmd))
    return true;
}

static bool htif_yield(i_device_state_access *a, htif *h, uint64_t cmd, uint64_t data) {
    (void) data;
    (void) h;
    // If yield command is enabled, yield and acknowledge
    if ((a->read_htif_iyield() >> cmd) & 1) {
        if (cmd == HTIF_YIELD_MANUAL) {
            a->set_iflags_Y();
        } else if (cmd == HTIF_YIELD_AUTOMATIC) {
            a->set_iflags_X();
        }
        a->write_htif_fromhost(HTIF_BUILD(HTIF_DEVICE_YIELD, cmd, 0));
    }
    // Otherwise, silently ignore it
    return true;
}

static bool htif_console(i_device_state_access *a, htif *h, uint64_t cmd, uint64_t data) {
    // If console command is enabled, perform it and acknowledge
    if ((a->read_htif_iconsole() >> cmd) & 1) {
        if (cmd == HTIF_CONSOLE_PUTCHAR) {
            uint8_t ch = data & 0xff;
            // In blockchain, there is no place to output a character, so either ignore it or log it somewhere
            if (write(STDOUT_FILENO, &ch, 1) < 1) {
                ;
            }
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEVICE_CONSOLE, cmd, 0));
        } else if (cmd == HTIF_CONSOLE_GETCHAR) {
            // In blockchain, this command will never be enabled as there is no way to input the same character
            // to every participant in a dispute: where would c come from? So if the code reached here in the
            // blockchain, there must be some serious bug
            // In interactive mode, we just get the next character from the console and send it back in the ack
            int c = h ? h->console_getchar() : 0;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEVICE_CONSOLE, cmd, c));
        }
    }
    // Otherwise, silently ignore it
    return true;
}

static bool htif_write_tohost(i_device_state_access *a, htif *h, uint64_t tohost) {
    // Decode tohost
    uint32_t device = HTIF_DEV_FIELD(tohost);
    uint32_t cmd = HTIF_CMD_FIELD(tohost);
    uint64_t data = HTIF_DATA_FIELD(tohost);
    // Log write to tohost
    a->write_htif_tohost(tohost);
    // Handle devices
    switch (device) {
        case HTIF_DEVICE_HALT:
            return htif_halt(a, h, cmd, data);
        case HTIF_DEVICE_CONSOLE:
            return htif_console(a, h, cmd, data);
        case HTIF_DEVICE_YIELD:
            return htif_yield(a, h, cmd, data);
        //??D Unknown HTIF devices are silently ignored
        default:
            return true;
    }
}

/// \brief HTIF device write callback. See ::pma_write.
static bool htif_write(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t val, int log2_size) {
    auto *h = static_cast<htif *>(pma.get_device().get_context());

    // Our HTIF only supports aligned 64-bit writes
    if (log2_size != 3 || offset & 7) {
        return false;
    }

    switch (offset) {
        case htif_tohost_rel_addr:
            return htif_write_tohost(a, h, val);
        case htif_fromhost_rel_addr:
            a->write_htif_fromhost(val);
            return true;
        default:
            // other writes are exceptions
            return false;
    }
}

/// \brief HTIF device peek callback. See ::pma_peek.
static bool htif_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *scratch) {
    // Check for alignment and range
    if (page_offset % PMA_PAGE_SIZE != 0 || page_offset >= pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // Page 0 is the only non-pristine page
    if (page_offset != 0) {
        *page_data = nullptr;
        return true;
    }
    // Clear entire page.
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy tohost and fromhost to their places within page.
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::tohost), m.read_htif_tohost());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::fromhost), m.read_htif_fromhost());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::ihalt), m.read_htif_ihalt());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::iconsole), m.read_htif_iconsole());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::iyield), m.read_htif_iyield());
    *page_data = scratch;
    return true;
}

static const pma_driver htif_driver{"HTIF", htif_read, htif_write};

pma_entry make_htif_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                // R
        true,                // W
        false,               // X
        false,               // IR
        false,               // IW
        PMA_ISTART_DID::HTIF // DID
    };
    return make_device_pma_entry(start, length, htif_peek, &htif_driver).set_flags(f);
}

pma_entry make_htif_pma_entry(htif &h, uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                // R
        true,                // W
        false,               // X
        false,               // IR
        false,               // IW
        PMA_ISTART_DID::HTIF // DID
    };
    return make_device_pma_entry(start, length, htif_peek, &htif_driver, &h).set_flags(f);
}

} // namespace cartesi
