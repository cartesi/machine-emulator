// Copyright 2023 Cartesi Pte. Ltd.
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

#include "virtio-net.h"

namespace cartesi {

virtio_net::virtio_net(uint32_t virtio_idx, std::unique_ptr<virtio_net_carrier> &&carrier) :
    virtio_device(virtio_idx, VIRTIO_DEVICE_NETWORK, 0, 0),
    m_carrier(std::move(carrier)) {}

void virtio_net::on_device_reset() {
    m_carrier->reset();
}

void virtio_net::on_device_ok(i_device_state_access *a) {
    (void) a;
    // Nothing to do.
}

bool virtio_net::on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t read_avail_len, uint32_t write_avail_len) {
    (void) write_avail_len;
    if (queue_idx == VIRTIO_NET_RECEIVEQ) { // Guest has a new slot available in the write queue
        // Write any pending packets from host to guest
        return poll_nowait(a);
    } else if (queue_idx == VIRTIO_NET_TRANSMITQ) { // Guest sent a new packet to the host
        if (write_next_packet_to_host(a, queue_idx, desc_idx, read_avail_len)) {
            // When a packet is just sent, poll for a response right-away.
            // This is necessary to have fast communication between the guest and its host
            // with the Slirp carrier.
            poll_nowait(a);
            return true;
        }
        return false;
    } else {
        // Other queues are unexpected
        notify_device_needs_reset(a);
        return false;
    }
}

void virtio_net::poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    timeval *timeout) {
    if (!driver_ok) {
        return;
    }
    m_carrier->do_poll_before_select(pmaxfd, readfds, writefds, exceptfds, timeout);
}

bool virtio_net::poll_after_select(i_device_state_access *a, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    int select_ret) {
    if (!driver_ok) {
        return false;
    }
    // Is there any pending to be read from the host?
    if (!m_carrier->do_poll_after_select(readfds, writefds, exceptfds, select_ret)) {
        return false;
    }
    bool interrupt_requested = false;
    // Read packets from host and write them the guest,
    // until the are no more pending packets to write or the write queue is full.
    while (read_next_packet_from_host(a)) {
        interrupt_requested = true;
    }
    return interrupt_requested;
}

bool virtio_net::write_next_packet_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t read_avail_len) {
    virtq &vq = queue[queue_idx];
    // Write a single packet to the network interface
    uint32_t read_len{};
    if (!m_carrier->write_packet_to_host(a, vq, desc_idx, read_avail_len, &read_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Consume the queue and notify the driver
    if (!consume_and_notify_queue(a, queue_idx, desc_idx)) {
        notify_device_needs_reset(a);
        return false;
    }
    return true;
}

bool virtio_net::read_next_packet_from_host(i_device_state_access *a) {
    // Bytes from host must be written to queue 0
    constexpr uint32_t queue_idx = VIRTIO_NET_RECEIVEQ;
    virtq &vq = queue[queue_idx];
    // Prepare queue buffer for writing
    uint16_t desc_idx{};
    uint32_t write_avail_len{};
    if (!prepare_queue_write(a, queue_idx, &desc_idx, &write_avail_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Write buffer length can be zero in case the queue is not ready or full
    if (write_avail_len == 0) {
        // This is not a fatal a failure, so no device reset is needed.
        return false;
    }
    // Read a single packet from the network interface
    uint32_t written_len{};
    if (!m_carrier->read_packet_from_host(a, vq, desc_idx, write_avail_len, &written_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    // The carrier is allowed may have no packets to send or may even drop packets,
    // so we consume the buffer and notify the driver only when something was actually written.
    if (written_len <= VIRTIO_NET_ETHERNET_FRAME_OFFSET) {
        // This is not a fatal a failure, so no device reset is needed.
        return false;
    }
    // Write the net header, we can simply fill the header with zeros
    virtio_net_header hdr{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (!vq.write_desc_mem(a, desc_idx, 0, reinterpret_cast<unsigned char *>(&hdr), VIRTIO_NET_ETHERNET_FRAME_OFFSET)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Consume and notify the queue
    if (!consume_and_notify_queue(a, queue_idx, desc_idx, written_len)) {
        notify_device_needs_reset(a);
        return false;
    }
    return true;
}

} // namespace cartesi
