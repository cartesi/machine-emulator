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

#ifndef VIRTIO_NET_ADDRESS_RANGE_H
#define VIRTIO_NET_ADDRESS_RANGE_H

#include "os-features.h"

#if defined(HAVE_SLIRP) || defined(HAVE_TUNTAP)

#include <cstdint>

#include "i-device-state-access.h"
#include "os.h"
#include "virtio-address-range.h"

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

/// \brief VirtIO net device
class virtio_net_address_range : public virtio_address_range {
public:
    virtio_net_address_range(const char *description, uint64_t start, uint64_t length, uint32_t virtio_idx);

    virtio_net_address_range(const virtio_net_address_range &other) = delete;
    virtio_net_address_range &operator=(const virtio_net_address_range &other) = delete;
    virtio_net_address_range &operator=(virtio_net_address_range &&other) = delete;

    virtio_net_address_range(virtio_net_address_range &&other) = default;
    ~virtio_net_address_range() override = default;

    bool write_next_packet_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len);
    bool read_next_packet_from_host(i_device_state_access *a);

    /// \brief Reset carrier internal state, discarding all network state.
    void net_reset() {
        do_net_reset();
    }

    /// \brief Fill file descriptors to be polled by select().
    void net_prepare_select(os::select_fd_sets *fds, uint64_t *timeout_us) {
        do_net_prepare_select(fds, timeout_us);
    }

    /// \brief Poll file descriptors that were marked as ready by select().
    bool net_poll_selected(int select_ret, os::select_fd_sets *fds) {
        return do_net_poll_selected(select_ret, fds);
    }

    /// \brief Called for carrying outgoing packets from the guest to the host.
    /// \param vq Queue reference.
    /// \param desc_idx Queue's descriptor index.
    /// \param read_avail_len Total readable length in the descriptor buffer.
    /// \param pread_len Receives how many bytes were actually read.
    /// \returns True on success, false otherwise.
    /// \details This function will return true even if when the write queue is full,
    /// pread_len will be set to 0 in this case and the packet dropped.
    bool net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) {
        return do_net_write_packet_to_host(a, vq, desc_idx, read_avail_len, pread_len);
    }

    /// \brief Called for carrying incoming packets from the host to the guest.
    /// \param vq Queue reference.
    /// \param desc_idx Queue's descriptor index.
    /// \param write_avail_len Total writable length in the descriptor buffer.
    /// \param pwrite_len Receives how many bytes were actually written.
    /// \returns True on success, false otherwise.
    /// \details This function will true even if when there are no more packets to write,
    /// pwritten_len will be set to 0 in this case.
    bool net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) {
        return do_net_read_packet_from_host(a, vq, desc_idx, write_avail_len, pwritten_len);
    }

private:
    void do_on_device_reset() override;
    void do_on_device_ok(i_device_state_access *a) override;
    bool do_on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len, virtq_event &e) override;
    void do_prepare_select(os::select_fd_sets *fds, uint64_t *timeout_us) override;
    bool do_poll_selected(int select_ret, os::select_fd_sets *fds, i_device_state_access *da) override;

    virtual void do_net_reset() = 0;
    virtual void do_net_prepare_select(os::select_fd_sets *fds, uint64_t *timeout_us) = 0;
    virtual bool do_net_poll_selected(int select_ret, os::select_fd_sets *fds) = 0;
    virtual bool do_net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t *pread_len) = 0;
    virtual bool do_net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
        uint32_t write_avail_len, uint32_t *pwritten_len) = 0;
};

} // namespace cartesi

#endif // defined(HAVE_SLIRP) || defined(HAVE_TUNTAP)

#endif
