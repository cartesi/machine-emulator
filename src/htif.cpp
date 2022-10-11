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
#include "pma-constants.h"
#include "strict-aliasing.h"
#include "tty.h"

namespace cartesi {

static constexpr auto htif_tohost_rel_addr = static_cast<uint64_t>(htif_csr::tohost);
static constexpr auto htif_fromhost_rel_addr = static_cast<uint64_t>(htif_csr::fromhost);
static constexpr auto htif_ihalt_rel_addr = static_cast<uint64_t>(htif_csr::ihalt);
static constexpr auto htif_iconsole_rel_addr = static_cast<uint64_t>(htif_csr::iconsole);
static constexpr auto htif_iyield_rel_addr = static_cast<uint64_t>(htif_csr::iyield);

uint64_t htif_get_csr_rel_addr(htif_csr reg) {
    return static_cast<uint64_t>(reg);
}

/// \brief HTIF device read callback. See ::pma_read.
static bool htif_read(void *context, i_device_state_access *a, uint64_t offset, uint64_t *pval, int log2_size) {
    (void) context;

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

static bool htif_halt(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    if (cmd == HTIF_HALT_HALT && (data & 1)) {
        a->set_iflags_H();
    }
    //??D Write acknowledgement to fromhost???
    // a->write_htif_fromhost(htif_build(HTIF_DEVICE_HALT,
    //     HTIF_HALT_HALT, cmd))
    return true;
}

static bool htif_yield(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    (void) data;
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

static bool htif_console(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    // If console command is enabled, perform it and acknowledge
    if ((a->read_htif_iconsole() >> cmd) & 1) {
        if (cmd == HTIF_CONSOLE_PUTCHAR) {
            uint8_t ch = data & 0xff;
            tty_putchar(ch);
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEVICE_CONSOLE, cmd, 0));
        } else if (cmd == HTIF_CONSOLE_GETCHAR) {
            // In blockchain, this command will never be enabled as there is no way to input the same character
            // to every participant in a dispute: where would c come from? So if the code reached here in the
            // blockchain, there must be some serious bug
            // In interactive mode, we just get the next character from the console and send it back in the ack
            int c = tty_getchar();
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEVICE_CONSOLE, cmd, c));
        }
    }
    // Otherwise, silently ignore it
    return true;
}

static bool htif_write_tohost(i_device_state_access *a, uint64_t tohost) {
    // Decode tohost
    uint32_t device = HTIF_DEV_FIELD(tohost);
    uint32_t cmd = HTIF_CMD_FIELD(tohost);
    uint64_t data = HTIF_DATA_FIELD(tohost);
    // Log write to tohost
    a->write_htif_tohost(tohost);
    // Handle devices
    switch (device) {
        case HTIF_DEVICE_HALT:
            return htif_halt(a, cmd, data);
        case HTIF_DEVICE_CONSOLE:
            return htif_console(a, cmd, data);
        case HTIF_DEVICE_YIELD:
            return htif_yield(a, cmd, data);
        //??D Unknown HTIF devices are silently ignored
        default:
            return true;
    }
}

/// \brief HTIF device write callback. See ::pma_write.
static bool htif_write(void *context, i_device_state_access *a, uint64_t offset, uint64_t val, int log2_size) {
    (void) context;
    // Our HTIF only supports aligned 64-bit writes
    if (log2_size != 3 || offset & 7) {
        return false;
    }

    switch (offset) {
        case htif_tohost_rel_addr:
            return htif_write_tohost(a, val);
        case htif_fromhost_rel_addr:
            a->write_htif_fromhost(val);
            return true;
        default:
            // other writes are exceptions
            return false;
    }
}

const pma_driver htif_driver{"HTIF", htif_read, htif_write};

} // namespace cartesi
