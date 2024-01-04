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

#include "virtio-console.h"
#include "os.h"

namespace cartesi {

virtio_console::virtio_console(uint32_t virtio_idx) :
    virtio_device(virtio_idx, VIRTIO_DEVICE_CONSOLE, VIRTIO_CONSOLE_F_SIZE, sizeof(virtio_console_config_space)) {}

void virtio_console::on_device_reset() {
    m_stdin_ready = false;
}

void virtio_console::on_device_ok(i_device_state_access *a) {
    // Upon initialization, we need to notify the initial console size
    notify_console_size_to_guest(a);
}

bool virtio_console::on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t read_avail_len, uint32_t write_avail_len) {
    (void) write_avail_len;
    if (queue_idx == VIRTIO_CONSOLE_RECEIVEQ) { // Guest has a new slot available in the write queue
        // Do nothing, host stdin characters will be written to the guest in the next poll
        return false;
    } else if (queue_idx == VIRTIO_CONSOLE_TRANSMITQ) { // Guest sent new characters to the host
        // Write guest characters to host stdout
        return write_next_chars_to_host(a, queue_idx, desc_idx, read_avail_len);
    } else {
        // Other queues are unexpected
        notify_device_needs_reset(a);
        return false;
    }
}

bool virtio_console::write_next_chars_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t read_avail_len) {
    const virtq &vq = queue[queue_idx];
    // Read stdout characters from queue buffer in chunks
    std::array<uint8_t, TTY_BUF_SIZE> chunk{};
    for (uint32_t off = 0; off < read_avail_len; off += chunk.size()) {
        // Read from queue buffer
        const uint32_t chunk_len = std::min<uint32_t>(chunk.size(), read_avail_len - off);
        if (!vq.read_desc_mem(a, desc_idx, off, chunk.data(), chunk_len)) {
            notify_device_needs_reset(a);
            return false;
        }
        // Write to stdout
        os_putchars(chunk.data(), chunk_len);
    }
    // Consume the queue and notify the driver
    if (!consume_and_notify_queue(a, queue_idx, desc_idx)) {
        notify_device_needs_reset(a);
        return false;
    }
    return true;
}

bool virtio_console::write_next_chars_to_guest(i_device_state_access *a) {
    if (!driver_ok) {
        return false;
    }
    // Bytes from host stdin must be written to queue 0 (guest input)
    constexpr uint32_t queue_idx = VIRTIO_CONSOLE_RECEIVEQ;
    const virtq &vq = queue[queue_idx];
    // Prepare queue buffer for writing
    uint16_t desc_idx{};
    uint32_t write_avail_len{};
    if (!prepare_queue_write(a, queue_idx, &desc_idx, &write_avail_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Write buffer length can be zero in case the queue is not ready or full
    if (write_avail_len == 0) {
        return false;
    }
    // Read from stdin
    std::array<uint8_t, TTY_BUF_SIZE> chunk{};
    const uint32_t chunk_len = os_getchars(chunk.data(), std::min<uint32_t>(write_avail_len, chunk.size()));
    // Chunk length is zero when there are no more characters available to write
    if (chunk_len == 0) {
        return false;
    }
    // Write to queue buffer
    if (!vq.write_desc_mem(a, desc_idx, 0, chunk.data(), chunk_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Consume the queue and notify the driver
    if (!consume_and_notify_queue(a, queue_idx, desc_idx, chunk_len, VIRTQ_USED_F_NO_NOTIFY)) {
        notify_device_needs_reset(a);
        return false;
    }
    return true;
}

bool virtio_console::notify_console_size_to_guest(i_device_state_access *a) {
    // Get current console size
    uint16_t cols{};
    uint16_t rows{};
    os_get_tty_size(&cols, &rows);
    virtio_console_config_space *config = get_config();
    // Notify the driver only when console size changes
    if (cols == config->cols && rows == config->rows) {
        return false;
    }
    config->rows = rows;
    config->cols = cols;
    notify_config_change(a);
    return true;
}

void virtio_console::prepare_select(select_fd_sets *fds, uint64_t *timeout_us) {
    // Ignore if driver is not initialized
    if (!driver_ok) {
        return;
    }
    // We should not poll console before the guest has started waiting for inputs,
    // otherwise the inputs will be sent before the driver console is actually being used,
    // then inputs will be consumed before the guest starts an interactive session,
    // and this will cause piped commands to work incorrectly.
    if (!m_stdin_ready) {
        // Unfortunately the Linux driver does not send any event when stdin becomes "ready",
        // but a trick is to consider stdin to be ready in the next WFI instruction,
        // in that case timeout is non 0 because we will wait for interrupts.
        //??(edubart) Maybe this workaround could be removed with multiport feature support?
        if (*timeout_us != 0) {
            m_stdin_ready = true;
        } else {
            return;
        }
    }
    os_prepare_tty_select(fds);
}

bool virtio_console::poll_selected(int select_ret, select_fd_sets *fds, i_device_state_access *da) {
    // Ignore if driver is not initialized or stdin is not ready
    if (!driver_ok || !m_stdin_ready) {
        return false;
    }
    bool interrupt_requested = notify_console_size_to_guest(da);
    if (os_poll_selected_tty(select_ret, fds)) {
        while (write_next_chars_to_guest(da)) {
            interrupt_requested = true;
        }
    }
    return interrupt_requested;
}

} // namespace cartesi
