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

#ifndef VIRTIO_NET_H
#define VIRTIO_NET_H

#include "virtio-device.h"

#include <memory>

namespace cartesi {

/// \brief VirtIO net packet header
struct virtio_net_header {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    uint16_t num_buffers;
};

/// \brief VirtIO net constants
enum virtio_net_constants : uint32_t {
    VIRTIO_NET_ETHERNET_FRAME_OFFSET = sizeof(virtio_net_header), ///< Offset for writing Ethernet frames
    VIRTIO_NET_ETHERNET_MAX_LENGTH = 2048,                        ///< Large enough to fit Ethernet maximum frame size
};

/// \brief VirtIO net Virtqueue indexes
enum virtio_net_virtq : uint32_t {
    VIRTIO_NET_RECEIVEQ = 0,  ///< Queue of packets from host to guest
    VIRTIO_NET_TRANSMITQ = 1, ///< Queue of packets from guest to host
};

/// \brief Generic interface for a network carrier on the host.
/// \details The sole purpose of a network carrier
/// is to carry incoming or outgoing packets between the host and the guest.
class virtio_net_carrier {
public:
    virtio_net_carrier() = default;
    virtual ~virtio_net_carrier() = default;
    virtio_net_carrier(const virtio_net_carrier &other) = delete;
    virtio_net_carrier(virtio_net_carrier &&other) = delete;
    virtio_net_carrier &operator=(const virtio_net_carrier &other) = delete;
    virtio_net_carrier &operator=(virtio_net_carrier &&other) = delete;

    /// \brief Reset carrier internal state, discarding all network state.
    virtual void reset() = 0;

    /// \brief Fill file descriptors to be polled by select().
    virtual void do_poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        timeval *timeout) = 0;

    /// \brief Poll file descriptors that were marked as ready by select().
    virtual bool do_poll_after_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds, int select_ret) = 0;

    /// \brief Called for carrying outgoing packets from the guest to the host.
    /// \param vq Queue reference.
    /// \param desc_idx Queue's descriptor index.
    /// \param read_avail_len Total readable length in the descriptor buffer.
    /// \param pread_len Receives how many bytes were actually read.
    /// \returns True on success, false otherwise.
    /// \details This function will return true even if when the write queue is full,
    /// pread_len will be set to 0 in this case and the packet dropped.
    virtual bool write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) = 0;

    /// \brief Called for carrying incoming packets from the host to the guest.
    /// \param vq Queue reference.
    /// \param desc_idx Queue's descriptor index.
    /// \param write_avail_len Total writable length in the descriptor buffer.
    /// \param pwrite_len Receives how many bytes were actually written.
    /// \returns True on success, false otherwise.
    /// \details This function will true even if when there are no more packets to write,
    /// pwritten_len will be set to 0 in this case.
    virtual bool read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) = 0;
};

/// \brief VirtIO net device
class virtio_net final : public virtio_device {
public:
    virtio_net(uint32_t virtio_idx, std::unique_ptr<virtio_net_carrier> &&carrier);

    void on_device_reset() override;
    void on_device_ok(i_device_state_access *a) override;
    bool on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len) override;

    void poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        timeval *timeout) override;
    bool poll_after_select(i_device_state_access *a, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        int select_ret) override;

    bool write_next_packet_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len);
    bool read_next_packet_from_host(i_device_state_access *a);

private:
    std::unique_ptr<virtio_net_carrier> m_carrier;
};

} // namespace cartesi

#endif
