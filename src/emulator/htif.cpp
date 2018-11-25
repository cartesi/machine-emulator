#include "machine.h"
#include "htif.h"
#include "i-virtual-state-access.h"

#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define HTIF_INTERACT_DIVISOR 10
#define HTIF_CONSOLE_BUF_SIZE 1024

#define HTIF_TOHOST_REL_ADDR (static_cast<uint64_t>(htif_csr::tohost))
#define HTIF_FROMHOST_REL_ADDR (static_cast<uint64_t>(htif_csr::fromhost))

uint64_t htif_get_csr_rel_addr(htif_csr reg) {
    return static_cast<uint64_t>(reg);
}

//??D Maybe the console behavior should change if STDIN is not a TTY?
struct htif_state {
    struct termios oldtty;
    int old_fd0_flags;
    uint8_t buf[HTIF_CONSOLE_BUF_SIZE];
    ssize_t buf_len, buf_pos;
    bool fromhost_pending;
    int divisor_counter;
    bool interactive;
    machine_state *machine;
};

static void htif_console_poll(htif_state *htif) {
    //??D We do not need to register any access to state here because
    //    the console is always disabled during verifiable execution

    // Check for input from console, if requested by HTIF
    // Obviously, somethind different must be done in blockchain
    if (!htif->fromhost_pending) {
        // If we don't have any characters left in buffer, try to obtain more
        if (htif->buf_pos >= htif->buf_len) {
            fd_set rfds;
            int fd_max;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(STDIN_FILENO, &rfds);
            fd_max = 0;
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            if (select(fd_max+1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(0, &rfds)) {
                htif->buf_pos = 0;
                htif->buf_len = read(STDIN_FILENO, htif->buf, HTIF_CONSOLE_BUF_SIZE);
                // If stdin is closed, pass EOF to client
                if (htif->buf_len <= 0) {
                    htif->buf_len = 1;
                    htif->buf[0] = 4; // CTRL+D
                }
            }
        }
        // If we have data to return
        if (htif->buf_pos < htif->buf_len) {
            machine_write_htif_fromhost(htif->machine,
                ((uint64_t)1 << 56) | ((uint64_t)0 << 48) | htif->buf[htif->buf_pos++]);
            htif->fromhost_pending = true;
        }
    }
}

/// \brief HTIF device read callback. See ::pma_read.
static bool htif_read(const pma_entry &pma, i_virtual_state_access *a, uint64_t offset, uint64_t *pval, int size_log2) {
    (void) pma;

    // Our HTIF only supports aligned 64-bit reads
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case HTIF_TOHOST_REL_ADDR:
            *pval = a->read_htif_tohost();
            return true;
        case HTIF_FROMHOST_REL_ADDR:
            *pval = a->read_htif_fromhost();
            return true;
        default:
            // other reads are exceptions
            return false;
    }
}

/// \brief HTIF device peek callback. See ::pma_peek.
static bool htif_peek(const pma_entry &pma, uint64_t page_offset, const uint8_t **page_data, uint8_t *scratch) {
    const htif_state *htif = reinterpret_cast<htif_state *>(
        pma.get_device().get_context());
    const machine_state *s = htif->machine;
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
    *reinterpret_cast<uint64_t *>(scratch +
        htif_get_csr_rel_addr(htif_csr::tohost)) = machine_read_htif_tohost(s);
    *reinterpret_cast<uint64_t *>(scratch +
        htif_get_csr_rel_addr(htif_csr::fromhost)) = machine_read_htif_fromhost(s);
    *page_data = scratch;
    return true;
}

static bool htif_getchar(i_virtual_state_access *a, htif_state *htif, uint64_t payload) {
    //??D Not sure exactly what role this command plays
    (void) htif; (void) payload;
    a->write_htif_tohost(0); // Acknowledge command
    // a->write_fromhost(((uint64_t)1 << 56) | ((uint64_t)1 << 48));
    return true;
}

static bool htif_putchar(i_virtual_state_access *a, htif_state *htif, uint64_t payload) {
    (void) htif;
    a->write_htif_tohost(0); // Acknowledge command
    uint8_t ch = payload & 0xff;
    // Obviously, somethind different must be done in blockchain
    if (write(STDOUT_FILENO, &ch, 1) < 1) { ; }
    a->write_htif_fromhost(((uint64_t)1 << 56) | ((uint64_t)1 << 48));
    return true;
}

static bool htif_halt(i_virtual_state_access *a, htif_state *htif, uint64_t payload) {
    (void) htif; (void) payload;
    a->set_iflags_H();
    // Leave tohost value alone so the payload can be read afterwards
    return true;
}

static bool htif_write_tohost(i_virtual_state_access *a, htif_state *htif, uint64_t tohost) {
    // Decode tohost
    uint32_t device = tohost >> 56;
    uint32_t cmd = (tohost >> 48) & 0xff;
    uint64_t payload = (tohost & (~1ULL >> 16));
    // Log write to tohost
    a->write_htif_tohost(tohost);
    // Handle commands
    if (device == 0 && cmd == 0 && (payload & 1)) {
        return htif_halt(a, htif, payload);
    } else if (device == 1 && cmd == 1) {
        return htif_putchar(a, htif, payload);
    } else if (device == 1 && cmd == 0) {
        return htif_getchar(a, htif, payload);
    }
    //??D Unknown HTIF commands are sillently ignored
    return true;
}

static bool htif_write_fromhost(i_virtual_state_access *a, htif_state *htif, uint64_t val) {
    a->write_htif_fromhost(val);
    if (htif->interactive) {
        htif->fromhost_pending = false;
        htif_console_poll(htif);
    }
    return true;
}

/// \brief HTIF device write callback. See ::pma_write.
static bool htif_write(const pma_entry &pma, i_virtual_state_access *a, uint64_t offset, uint64_t val, int size_log2) {
    htif_state *htif = reinterpret_cast<htif_state *>(
        pma.get_device().get_context());

    // Our HTIF only supports aligned 64-bit writes
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case HTIF_TOHOST_REL_ADDR:
            return htif_write_tohost(a, htif, val);
        case HTIF_FROMHOST_REL_ADDR:
            return htif_write_fromhost(a, htif, val);
        default:
            // other writes are exceptions
            return false;
    }
}

static void set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags &= (~(O_NONBLOCK));
    fcntl(fd, F_SETFL, flags);
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

static void htif_console_init(htif_state *htif) {
    if (isatty(STDIN_FILENO)) {
        struct termios tty;
        memset(&tty, 0, sizeof(tty));
        tcgetattr (STDIN_FILENO, &tty);
        htif->oldtty = tty;
        htif->old_fd0_flags = fcntl(STDIN_FILENO, F_GETFL);
        // Set terminal to "raw" mode
        tty.c_lflag &= ~(
            ECHO   | // Echo off
            ICANON | // Canonical mode off
            ECHONL | // Do not echo NL (redundant with ECHO and ICANON)
            ISIG   | // Signal chars off
            IEXTEN   // Extended input processing off
        );
        tty.c_iflag &= ~(
            IGNBRK | // Generate \377 \0 \0 on BREAK
            BRKINT | //
            PARMRK | //
            ICRNL  | // No CR-to-NL
            ISTRIP | // Do not strip off 8th bit
            INLCR  | // No NL-to-CR
            IGNCR  | // Do not ignore CR
            IXON     // Disable XON/XOFF flow control on output
        );
        tty.c_oflag |=
            OPOST;   // Enable output processing
        // Enable parity generation on output and checking for input
        tty.c_cflag &= ~(CSIZE|PARENB);
        tty.c_cflag |= CS8;
        // Read returns with 1 char and no delay
        tty.c_cc[VMIN] = 1;
        tty.c_cc[VTIME] = 0;
        tcsetattr (STDIN_FILENO, TCSANOW, &tty);
        //??D Should we check to see if changes stuck?
    }
    set_nonblocking(STDIN_FILENO);
}

static void htif_console_end(htif_state *htif) {
    if (isatty(STDIN_FILENO)) {
        tcsetattr (STDIN_FILENO, TCSANOW, &htif->oldtty);
        fcntl(STDIN_FILENO, F_SETFL, htif->old_fd0_flags);
    }
    set_blocking(STDIN_FILENO);
}

htif_state *htif_init(machine_state *machine, bool interactive) {
    htif_state *htif = reinterpret_cast<htif_state *>(calloc(1, sizeof(htif_state)));
    if (htif) {
        htif->machine = machine;
        if (interactive) {
            htif->interactive = true;
            htif_console_init(htif);
        }
    }
    return htif;
}

void htif_end(htif_state *htif) {
    if (htif->interactive) {
        htif_console_end(htif);
    }
    free(htif);
}

void htif_interact(htif_state *htif) {
    // Only interact every
    if (htif->interactive && ++htif->divisor_counter == HTIF_INTERACT_DIVISOR) {
        htif->divisor_counter = 0;
        // Check if there is user input from stdin
        htif_console_poll(htif);
    }
}

static const pma_driver htif_driver {
    "HTIF",
    htif_read,
    htif_write
};

void htif_register_mmio(htif_state *htif, uint64_t start, uint64_t length) {
    auto &pma = machine_register_mmio(htif->machine, start, length, htif_peek,
        htif, &htif_driver);
    if (!machine_set_htif_pma(htif->machine, &pma))
        throw std::runtime_error("HTIF already registered");
}
