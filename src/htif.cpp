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

#include "htif.h"
#include "i-device-state-access.h"
#include "machine-runtime-config.h"
#include "os.h"

namespace cartesi {

static constexpr auto htif_tohost_rel_addr = static_cast<uint64_t>(htif_csr::tohost);
static constexpr auto htif_fromhost_rel_addr = static_cast<uint64_t>(htif_csr::fromhost);
static constexpr auto htif_ihalt_rel_addr = static_cast<uint64_t>(htif_csr::ihalt);
static constexpr auto htif_iconsole_rel_addr = static_cast<uint64_t>(htif_csr::iconsole);
static constexpr auto htif_iyield_rel_addr = static_cast<uint64_t>(htif_csr::iyield);

/// \brief HTIF device read callback. See ::pma_read.
static bool htif_read(void *context, i_device_state_access *a, uint64_t offset, uint64_t *pval, int log2_size) {
    (void) context;

    // Our HTIF only supports 64-bit reads
    if (log2_size != 3) {
        return false;
    }

    // Only these 64-bit aligned offsets are valid
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

static execute_status htif_halt(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    (void) a;
    if (cmd == HTIF_HALT_CMD_HALT && (data & 1)) {
        a->set_iflags_H();
        return execute_status::success_and_halt;
    }
    //??D Write acknowledgement to fromhost???
    // a->write_htif_fromhost(htif_build(HTIF_DEV_HALT, HTIF_HALT_CMD_HALT, cmd))
    return execute_status::success;
}

static execute_status htif_yield(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    (void) data;
    execute_status status = execute_status::success;
    // If yield command is enabled, yield and acknowledge
    if (cmd < 64 && (a->read_htif_iyield() >> cmd) & 1) {
        if (cmd == HTIF_YIELD_CMD_MANUAL) {
            a->set_iflags_Y();
            status = execute_status::success_and_yield;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_YIELD, cmd, 0, 0));
        } else if (cmd == HTIF_YIELD_CMD_AUTOMATIC) {
            a->set_iflags_X();
            status = execute_status::success_and_yield;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_YIELD, cmd, 0, 0));
        }
    }
    // Otherwise, silently ignore it
    return status;
}

static execute_status htif_console(htif_runtime_config *runtime_config, i_device_state_access *a, uint64_t cmd,
    uint64_t data) {
    // If console command is enabled, perform it and acknowledge
    if (cmd < 64 && (a->read_htif_iconsole() >> cmd) & 1) {
        if (cmd == HTIF_CONSOLE_CMD_PUTCHAR) {
            const uint8_t ch = data & 0xff;
            // In microarchitecture runtime_config will always be nullptr,
            // therefore the HTIF runtime config is actually ignored.
            if (!runtime_config || !runtime_config->no_console_putchar) {
                os_putchar(ch);
            }
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_CONSOLE, cmd, 0, 0));
        } else if (cmd == HTIF_CONSOLE_CMD_GETCHAR) {
            // In blockchain, this command will never be enabled as there is no way to input the same character
            // to every participant in a dispute: where would c come from? So if the code reached here in the
            // blockchain, there must be some serious bug
            // In interactive mode, we just get the next character from the console and send it back in the ack
            os_poll_tty(0);
            const int c = os_getchar() + 1;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_CONSOLE, cmd, 0, static_cast<uint32_t>(c)));
        }
    }
    // Otherwise, silently ignore it
    return execute_status::success;
}

static execute_status htif_write_tohost(htif_runtime_config *runtime_config, i_device_state_access *a,
    uint64_t tohost) {
    // Decode tohost
    const uint32_t device = HTIF_DEV_FIELD(tohost);
    const uint32_t cmd = HTIF_CMD_FIELD(tohost);
    const uint64_t data = HTIF_DATA_FIELD(tohost);
    // Log write to tohost
    a->write_htif_tohost(tohost);
    // Handle devices
    switch (device) {
        case HTIF_DEV_HALT:
            return htif_halt(a, cmd, data);
        case HTIF_DEV_CONSOLE:
            return htif_console(runtime_config, a, cmd, data);
        case HTIF_DEV_YIELD:
            return htif_yield(a, cmd, data);
        //??D Unknown HTIF devices are silently ignored
        default:
            return execute_status::success;
    }
}

/// \brief HTIF device write callback. See ::pma_write.
static execute_status htif_write(void *context, i_device_state_access *a, uint64_t offset, uint64_t val,
    int log2_size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    htif_runtime_config *runtime_config = reinterpret_cast<htif_runtime_config *>(context);
    // Our HTIF only supports 64-bit writes
    if (log2_size != 3) {
        return execute_status::failure;
    }

    // Only these 64-bit aligned offsets are valid
    switch (offset) {
        case htif_tohost_rel_addr:
            return htif_write_tohost(runtime_config, a, val);
        case htif_fromhost_rel_addr:
            a->write_htif_fromhost(val);
            return execute_status::success;
        default:
            // other writes are exceptions
            return execute_status::failure;
    }
}

const pma_driver htif_driver{"HTIF", htif_read, htif_write};

} // namespace cartesi
