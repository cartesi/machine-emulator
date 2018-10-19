#include "machine.h"
#include "machine-state.h"
#include "htif.h"
#include "i-device-state-access.h"

#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define HTIF_INTERACT_DIVISOR 10
#define HTIF_CONSOLE_BUF_SIZE 1024

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
    if (!htif->fromhost_pending) {
        // If we don't have any characters left in buffer, try to obtain more
        if (htif->buf_pos >= htif->buf_len) {
            fd_set rfds;
            int fd_max;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(0, &rfds);
            fd_max = 0;
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            if (select(fd_max+1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(0, &rfds)) {
                htif->buf_pos = 0;
                htif->buf_len = read(0, htif->buf, HTIF_CONSOLE_BUF_SIZE);
                // If stdin is closed, pass EOF to client
                if (htif->buf_len <= 0) {
                    htif->buf_len = 1;
                    htif->buf[0] = 4; // CTRL+D
                }
            }
        }
        // If we have data to return
        if (htif->buf_pos < htif->buf_len) {
            processor_write_fromhost(htif->machine, ((uint64_t)1 << 56) | ((uint64_t)0 << 48) | htif->buf[htif->buf_pos++]);
            htif->fromhost_pending = true;
        }
    }
}

/// \brief HTIF device read callback. See ::pma_device_read.
static bool htif_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *pval, int size_log2) {
    (void) context;

    // Our HTIF only supports aligned 64-bit reads
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case 0: // tohost
            *pval = a->read_tohost();
            return true;
        case 8: // fromhost
            *pval = a->read_fromhost();
            return true;
        default:
            // other reads are exceptions
            return false;
    }
}

/// \brief HTIF device peek callback. See ::pma_device_peek.
static device_peek_status htif_peek(const machine_state *s, void *context, uint64_t page_index, uint8_t *page_data) {
    (void) context;
    // There is a single non-pristine page: 0;
    if (page_index % PMA_PAGE_SIZE != 0)
        return device_peek_status::invalid_page;
    if (page_index != 0)
        return device_peek_status::pristine_page;
    // Clear entire page.
    memset(page_data, 0, PMA_PAGE_SIZE);
    // Copy tohost and fromhost to their places within page.
    reinterpret_cast<uint64_t *>(page_data)[0] = s->tohost;
    reinterpret_cast<uint64_t *>(page_data)[1] = s->fromhost;
    return device_peek_status::success;
}

static bool htif_getchar(i_device_state_access *a, htif_state *htif, uint64_t payload) {
    //??D Not sure exactly what role this command plays
    (void) htif; (void) payload;
    a->write_tohost(0); // Acknowledge command
    // a->write_fromhost(((uint64_t)1 << 56) | ((uint64_t)1 << 48));
    return true;
}

static bool htif_putchar(i_device_state_access *a, htif_state *htif, uint64_t payload) {
    (void) htif;
    a->write_tohost(0); // Acknowledge command
    uint8_t ch = payload & 0xff;
    if (write(1, &ch, 1) < 1) { ; } // Obviously, this is not done in blockchain
    a->write_fromhost(((uint64_t)1 << 56) | ((uint64_t)1 << 48));
    return true;
}

static bool htif_halt(i_device_state_access *a, htif_state *htif, uint64_t payload) {
    (void) htif; (void) payload;
    a->set_iflags_H();
    // Leave tohost value alone so the payload can be read afterwards
    return true;
}

static bool htif_write_tohost(i_device_state_access *a, htif_state *htif, uint64_t tohost) {
    // Decode tohost
    uint32_t device = tohost >> 56;
    uint32_t cmd = (tohost >> 48) & 0xff;
    uint64_t payload = (tohost & (~1ULL >> 16));
    // Log write to tohost
    a->write_tohost(tohost);
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

static bool htif_write_fromhost(i_device_state_access *a, htif_state *htif, uint64_t val) {
    a->write_fromhost(val);
    if (htif->interactive) {
        htif->fromhost_pending = false;
        htif_console_poll(htif);
    }
    return true;
}

/// \brief HTIF device write callback. See ::pma_device_write.
static bool htif_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2) {
    htif_state *htif = reinterpret_cast<htif_state *>(context);

    // Our HTIF only supports aligned 64-bit writes
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case 0: // tohost
            return htif_write_tohost(a, htif, val);
        case 8: // fromhost
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
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    htif->oldtty = tty;
    htif->old_fd0_flags = fcntl(0, F_GETFL);
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;
    tcsetattr (0, TCSANOW, &tty);
    set_nonblocking(0);
}

static void htif_console_end(htif_state *htif) {
    tcsetattr (0, TCSANOW, &htif->oldtty);
    fcntl(0, F_SETFL, htif->old_fd0_flags);
    set_blocking(0);
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

const pma_device_driver htif_driver {
    "HTIF",
    htif_read,
    htif_write,
    htif_peek
};
