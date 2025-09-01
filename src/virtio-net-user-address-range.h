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

#ifndef VIRTIO_NET_USER_ADDRESS_RANGE_H
#define VIRTIO_NET_USER_ADDRESS_RANGE_H

#include "os-features.h"

#ifdef HAVE_SLIRP

#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <unordered_map>

#include <slirp/libslirp.h>
#if SLIRP_CONFIG_VERSION_MAX < 3
#error "slirp version must be 3 or higher"
#endif

#include "i-device-state-access.h"
#include "machine-config.h"
#include "os.h"
#include "virtio-address-range.h"
#include "virtio-net-address-range.h"

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

namespace detail {

struct slirp_deleter {
    void operator()(Slirp *slirp) const noexcept {
        slirp_cleanup(slirp);
    }
};

} // namespace detail

struct slirp_context {
    SlirpConfig config{};
    SlirpCb callbacks{};
    std::unique_ptr<Slirp, detail::slirp_deleter> slirp;
    std::list<slirp_packet> send_packets;
    std::unordered_map<void *, std::unique_ptr<slirp_timer>> timers;
};

class virtio_net_user_address_range final : public virtio_net_address_range {
public:
    virtio_net_user_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx,
        const virtio_net_user_config &config);

    virtio_net_user_address_range(const virtio_net_user_address_range &other) = delete;
    virtio_net_user_address_range &operator=(const virtio_net_user_address_range &other) = delete;
    virtio_net_user_address_range &operator=(virtio_net_user_address_range &&other) = delete;

    virtio_net_user_address_range(virtio_net_user_address_range &&other) = default;
    ~virtio_net_user_address_range() override = default;

private:
    void do_net_reset() override;
    void do_net_prepare_select(select_fd_sets *fds, uint64_t *timeout_us) override;
    bool do_net_poll_selected(int select_ret, select_fd_sets *fds) override;
    bool do_net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t read_avail_len,
        uint32_t *pread_len) override;
    bool do_net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx, uint32_t write_avail_len,
        uint32_t *pwritten_len) override;

    std::unique_ptr<slirp_context> m_context;
};

static inline auto make_virtio_net_user_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx,
    const virtio_net_user_config &config) {
    return virtio_net_user_address_range{start, length, virtio_idx, config};
}

} // namespace cartesi

#endif // HAVE_SLIRP

#endif
