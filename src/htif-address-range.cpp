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

#include "htif-address-range.h"

#include <cstdint>

#include "htif-constants.h"
#include "i-device-state-access.h"
#include "interpret.h"

namespace cartesi {

static constexpr auto htif_tohost_rel_addr = static_cast<uint64_t>(htif_csr::tohost);
static constexpr auto htif_fromhost_rel_addr = static_cast<uint64_t>(htif_csr::fromhost);
static constexpr auto htif_ihalt_rel_addr = static_cast<uint64_t>(htif_csr::ihalt);
static constexpr auto htif_iconsole_rel_addr = static_cast<uint64_t>(htif_csr::iconsole);
static constexpr auto htif_iyield_rel_addr = static_cast<uint64_t>(htif_csr::iyield);

bool htif_address_range::do_read_device(i_device_state_access *a, uint64_t offset, int log2_size,
    uint64_t *pval) const noexcept {
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
    if (cmd == HTIF_HALT_CMD_HALT && ((data & 1) != 0)) {
        a->write_iflags_H(1);
        return execute_status::success_and_halt;
    }
    //??D Write acknowledgement to fromhost???
    // a->write_htif_fromhost(htif_build(HTIF_DEV_HALT, HTIF_HALT_CMD_HALT, cmd))
    return execute_status::success;
}

static execute_status htif_yield(i_device_state_access *a, uint64_t cmd, uint64_t /*data*/) {
    execute_status status = execute_status::success;
    // If yield command is enabled, yield and acknowledge
    if (cmd < 64 && (((a->read_htif_iyield() >> cmd) & 1) != 0)) {
        if (cmd == HTIF_YIELD_CMD_MANUAL) {
            a->write_iflags_Y(1);
            status = execute_status::success_and_yield;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_YIELD, cmd, 0, 0));
        } else if (cmd == HTIF_YIELD_CMD_AUTOMATIC) {
            a->write_iflags_X(1);
            status = execute_status::success_and_yield;
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_YIELD, cmd, 0, 0));
        }
    }
    // Otherwise, silently ignore it
    return status;
}

static execute_status htif_console(i_device_state_access *a, uint64_t cmd, uint64_t data) {
    auto status = execute_status::success;
    // If console command is enabled, perform it and acknowledge
    if (cmd < 64 && (((a->read_htif_iconsole() >> cmd) & 1) != 0)) {
        if (cmd == HTIF_CONSOLE_CMD_PUTCHAR) {
            const uint8_t ch = data & 0xff;
            const bool should_flush_output = a->putchar(ch);
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_CONSOLE, cmd, 0, 0));
            if (should_flush_output) {
                status = execute_status::success_and_console_output;
            }
        } else if (cmd == HTIF_CONSOLE_CMD_GETCHAR) {
            // In blockchain, this command will never be enabled as there is no way to input the same character
            // to every participant in a dispute: where would c come from? So if the code reached here in the
            // blockchain, there must be some serious bug
            // In interactive mode, we just get the next character from the console and send it back in the ack
            const auto [c, should_refill_input] = a->getchar();
            a->write_htif_fromhost(HTIF_BUILD(HTIF_DEV_CONSOLE, cmd, 0, static_cast<uint32_t>(c + 1)));
            if (should_refill_input) {
                status = execute_status::success_and_console_input;
            }
        }
    }
    // Otherwise, silently ignore it
    return status;
}

static execute_status htif_write_tohost(i_device_state_access *a, uint64_t tohost) {
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
            return htif_console(a, cmd, data);
        case HTIF_DEV_YIELD:
            return htif_yield(a, cmd, data);
        //??D Unknown HTIF devices are silently ignored
        default:
            return execute_status::success;
    }
}

execute_status htif_address_range::do_write_device(i_device_state_access *a, uint64_t offset, int log2_size,
    uint64_t val) noexcept {

    // Our HTIF only supports 64-bit writes
    if (log2_size != 3) {
        return execute_status::failure;
    }

    // Only these 64-bit aligned offsets are valid
    switch (offset) {
        case htif_tohost_rel_addr:
            return htif_write_tohost(a, val);
        case htif_fromhost_rel_addr:
            a->write_htif_fromhost(val);
            return execute_status::success;
        default:
            // other writes are exceptions
            return execute_status::failure;
    }
}

} // namespace cartesi
