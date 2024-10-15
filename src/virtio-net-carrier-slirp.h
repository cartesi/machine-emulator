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

#ifndef VIRTIO_NET_CARRIER_SLIRP_H
#define VIRTIO_NET_CARRIER_SLIRP_H

#include "os-features.h"

#ifdef HAVE_SLIRP

#include "machine-config.h"
#include "virtio-net.h"

#include <list>
#include <unordered_set>

#include <slirp/libslirp.h>

#if SLIRP_CONFIG_VERSION_MAX < 3
#error "slirp version must be 3 or higher"
#endif

/// \brief Slirp constants
enum slirp_constants {
    SLIRP_VERSION = 4,
    SLIRP_MAX_PENDING_PACKETS = 1024,
};

/// \brief Default IPv4 settings historically used with slirp
enum slirp_ipv4_addresses : uint32_t {
    SLIRP_DEFAULT_IPV4_VNETWORK = 0x0a000200,    ///< 10.0.2.0
    SLIRP_DEFAULT_IPV4_VNETMASK = 0xffffff00,    ///< 255.255.255.0
    SLIRP_DEFAULT_IPV4_VHOST = 0x0a000202,       ///< 10.0.2.2
    SLIRP_DEFAULT_IPV4_VDHCP_START = 0x0a00020f, ///< 10.0.2.15
    SLIRP_DEFAULT_IPV4_VNAMESERVER = 0x0a000203, ///< 10.0.2.3
};

namespace cartesi {

struct slirp_timer {
    SlirpTimerCb cb = nullptr;
    void *cb_opaque = nullptr;
    int64_t expire_timer_msec = -1;
};

struct slirp_packet {
    size_t len = 0;
    std::array<unsigned char, VIRTIO_NET_ETHERNET_MAX_LENGTH> buf{};
};

class virtio_net_carrier_slirp final : public virtio_net_carrier {
public:
    Slirp *slirp = nullptr;
    SlirpConfig slirp_cfg{};
    SlirpCb slirp_cbs{};
    std::list<slirp_packet> send_packets;
    std::unordered_set<slirp_timer *> timers;

    explicit virtio_net_carrier_slirp(const cartesi::virtio_net_user_config &config);
    ~virtio_net_carrier_slirp() override;
    virtio_net_carrier_slirp(const virtio_net_carrier_slirp &other) = delete;
    virtio_net_carrier_slirp(virtio_net_carrier_slirp &&other) = delete;
    virtio_net_carrier_slirp &operator=(const virtio_net_carrier_slirp &other) = delete;
    virtio_net_carrier_slirp &operator=(virtio_net_carrier_slirp &&other) = delete;

    void reset() override;

    void do_prepare_select(select_fd_sets *fds, uint64_t *timeout_us) override;
    bool do_poll_selected(int select_ret, select_fd_sets *fds) override;

    bool write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) override;
    bool read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) override;
};

} // namespace cartesi

#endif // HAVE_SLIRP

#endif
