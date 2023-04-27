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

#ifndef VIRTIO_NET_CARRIER_TUNTAP_H
#define VIRTIO_NET_CARRIER_TUNTAP_H

#include "virtio-net.h"

namespace cartesi {

class virtio_net_carrier_tuntap final : public virtio_net_carrier {
    int m_tapfd = -1;

public:
    virtio_net_carrier_tuntap(const std::string &tap_name);
    ~virtio_net_carrier_tuntap() override;
    virtio_net_carrier_tuntap(const virtio_net_carrier_tuntap &other) = delete;
    virtio_net_carrier_tuntap(virtio_net_carrier_tuntap &&other) = delete;
    virtio_net_carrier_tuntap &operator=(const virtio_net_carrier_tuntap &other) = delete;
    virtio_net_carrier_tuntap &operator=(virtio_net_carrier_tuntap &&other) = delete;

    void reset() override;

    void do_poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        timeval *timeout) override;
    bool do_poll_after_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds, int select_ret) override;

    bool write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) override;
    bool read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) override;
};

} // namespace cartesi

#endif
