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

#ifndef VIRTIO_NET_TUNTAP_ADDRESS_RANGE_H
#define VIRTIO_NET_TUNTAP_ADDRESS_RANGE_H

#include "os-features.h"

#ifdef HAVE_TUNTAP

#include <cstdint>
#include <string>

#include "i-device-state-access.h"
#include "os.h"
#include "virtio-net-address-range.h"

namespace cartesi {

class virtio_net_tuntap_address_range final : public virtio_net_address_range {
    int m_tapfd = -1;

public:
    virtio_net_tuntap_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx, const std::string &tap_name);

    virtio_net_tuntap_address_range(const virtio_net_tuntap_address_range &other) = delete;
    virtio_net_tuntap_address_range &operator=(const virtio_net_tuntap_address_range &other) = delete;
    virtio_net_tuntap_address_range &operator=(virtio_net_tuntap_address_range &&other) = delete;

    virtio_net_tuntap_address_range(virtio_net_tuntap_address_range &&other) = default;
    ~virtio_net_tuntap_address_range() override;

protected:
    void net_reset() override;

    void net_prepare_select(select_fd_sets *fds, uint64_t *timeout_us) override;
    bool net_poll_selected(int select_ret, select_fd_sets *fds) override;

    bool net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) override;
    bool net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) override;
};

static inline auto make_virtio_net_tuntap_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx,
    const std::string &tap_name) {
    return virtio_net_tuntap_address_range{start, length, virtio_idx, tap_name};
}

} // namespace cartesi

#endif // HAVE_TUNTAP

#endif
