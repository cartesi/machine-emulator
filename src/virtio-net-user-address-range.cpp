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

/// \file
/// \brief VirtIO network carrier Slirp implementation.
/// \details \{
///
/// This is a user-mode network carrier, so it should work in host's userspace,
/// meaning you don't need root privilege or any configuration in the host to use it,
/// in most case it should work out of the box.
///
/// While being of use, the slirp network carrier has some limitations:
///   - There is an additional an emulation layer of the TCP/IP stack, so it's slower than TUN network carrier.
///   - Not all IP protocols are emulated, but TCP and UDP should work.
///   - Host cannot access guest TCP services (this can be improved in the future with slirp's hostfwd).
///
/// The implementation uses libslirp TCP/IP emulator library.
///
/// To have guest networking using a slirp network carrier,
/// execute the following commands in the guest with root privilege:
///
///   ip link set dev eth0 up
///   ip addr add 10.0.2.15/24 dev eth0
///   ip route add default via 10.0.2.2 dev eth0
///   echo 'nameserver 10.0.2.3' > /etc/resolv.conf
///
/// To test if everything works, try ping:
///
///   ping cartesi.io
///
/// The slirp network settings configuration is fixed to the following:
///
///   Network:      10.0.2.0
///   Netmask:      255.255.255.0
///   Host/Gateway: 10.0.2.2
///   DHCP Start:   10.0.2.15
///   Nameserver:   10.0.2.3
///
/// \}

// #define DEBUG_VIRTIO_ERRORS

#include "virtio-net-user-address-range.h"

#ifdef HAVE_SLIRP

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

#include <arpa/inet.h>
#include <slirp/libslirp.h>
#include <sys/select.h>

#include "i-device-state-access.h"
#include "machine-config.h"
#include "os.h"

using namespace std::string_literals;

namespace cartesi {

//??D why ssize_t?
static ssize_t slirp_send_packet(const void *buf, size_t len, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *carrier = reinterpret_cast<virtio_net_user_address_range *>(opaque);
    if (carrier->send_packets.size() >= SLIRP_MAX_PENDING_PACKETS) {
        // Too many send_packets in the write queue, we can just drop it.
        // Network re-transmission can recover from this.
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "slirp: dropped packet sent by the host because the write queue is full\n");
#endif
        return 0;
    }
    if (len > VIRTIO_NET_ETHERNET_MAX_LENGTH) {
        // This is unexpected, slirp is trying to send an a jumbo Ethernet frames? Drop it.
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "slirp: dropped large packet with length %u sent by the host\n",
            static_cast<unsigned int>(len));
#endif
        return 0;
    }
    // Add packet to the send packet queue,
    // the packet will actually be sent only the next time the device calls read_packet()
    slirp_packet packet{.len = len};
    memcpy(packet.buf.data(), buf, len);
    try {
        carrier->send_packets.emplace_back(packet);
        return static_cast<ssize_t>(len);
    } catch (...) {
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "slirp: exception thrown while adding a send packet\n");
#endif
        return 0;
    }
}

static void slirp_guest_error([[maybe_unused]] const char *msg, void * /*opaque*/) {
#ifdef DEBUG_VIRTIO_ERRORS
    std::ignore = fprintf(stderr, "slirp: %s\n", msg);
#endif
}

static int64_t slirp_clock_get_ns(void * /*opaque*/) {
    const auto now = std::chrono::steady_clock::now();
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
    return static_cast<int64_t>(ns.count());
}

static void *slirp_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *carrier = reinterpret_cast<virtio_net_user_address_range *>(opaque);
    try {
        auto *timer = new slirp_timer;
        timer->cb = cb;
        timer->cb_opaque = cb_opaque;
        timer->expire_timer_msec = -1;
        carrier->timers.insert(timer);
        return timer;
    } catch (...) {
        return nullptr;
    }
}

static void slirp_timer_free(void *timer_ptr, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *carrier = reinterpret_cast<virtio_net_user_address_range *>(opaque);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *timer = reinterpret_cast<slirp_timer *>(timer_ptr);
    if (timer != nullptr) {
        auto it = carrier->timers.find(timer);
        if (it != carrier->timers.end()) {
            carrier->timers.erase(it);
            delete timer;
        }
    }
}

static void slirp_timer_mod(void *timer_ptr, int64_t expire_timer_msec, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *carrier = reinterpret_cast<virtio_net_user_address_range *>(opaque);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *timer = reinterpret_cast<slirp_timer *>(timer_ptr);
    if ((timer != nullptr) && carrier->timers.find(timer) != carrier->timers.end()) {
        timer->expire_timer_msec = expire_timer_msec;
    }
}

static void slirp_register_poll_fd(int /*fd*/, void * /*opaque*/) {
    // Nothing to do, this callback is only useful on implementations using poll() instead of select().
}

static void slirp_unregister_poll_fd(int /*fd*/, void * /*opaque*/) {
    // Nothing to do, this callback is only useful on implementations using poll() instead of select().
}

static void slirp_notify(void * /*opaque*/) {
    // Nothing to do
}

virtio_net_user_address_range::virtio_net_user_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx,
    const cartesi::virtio_net_user_config &config) :
    virtio_net_address_range("VirtIO Net User", start, length, virtio_idx) {

    // Configure slirp
    slirp_cfg.version = std::min<int>(SLIRP_CONFIG_VERSION_MAX, SLIRP_VERSION);
    slirp_cfg.restricted = 0;                                             // Don't isolate the guest from the host
    slirp_cfg.in_enabled = true;                                          // IPv4 is enabled
    slirp_cfg.vnetwork.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNETWORK);       // Network
    slirp_cfg.vnetmask.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNETMASK);       // Netmask
    slirp_cfg.vhost.s_addr = htonl(SLIRP_DEFAULT_IPV4_VHOST);             // Host address/gateway
    slirp_cfg.vdhcp_start.s_addr = htonl(SLIRP_DEFAULT_IPV4_VDHCP_START); // DHCP start address
    slirp_cfg.vnameserver.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNAMESERVER); // DNS server address
    // ??(edubart): Should all the above settings be configurable by the user?
    // ??(edubart): Should we add support for IPv6? It is disabled by default.
    // Configure required slirp callbacks
    slirp_cbs.send_packet = slirp_send_packet;
    slirp_cbs.guest_error = slirp_guest_error;
    slirp_cbs.clock_get_ns = slirp_clock_get_ns;
    slirp_cbs.timer_new = slirp_timer_new;
    slirp_cbs.timer_free = slirp_timer_free;
    slirp_cbs.timer_mod = slirp_timer_mod;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    slirp_cbs.register_poll_fd = slirp_register_poll_fd;
    slirp_cbs.unregister_poll_fd = slirp_unregister_poll_fd;
#pragma GCC diagnostic pop
    slirp_cbs.notify = slirp_notify;

    // Initialize slirp
    slirp = slirp_new(&slirp_cfg, &slirp_cbs, this);
    if (slirp == nullptr) {
        throw std::runtime_error("could not configure slirp network device");
    }

    // Setup host forward ports
    for (const auto &hostfwd : config.hostfwd) {
        struct in_addr host_addr{};
        struct in_addr guest_addr{};
        host_addr.s_addr = htonl(hostfwd.host_ip);
        guest_addr.s_addr = htonl(hostfwd.guest_ip);
        if (slirp_add_hostfwd(slirp, static_cast<int>(hostfwd.is_udp), host_addr, hostfwd.host_port, guest_addr,
                hostfwd.guest_port) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "failed to forward "s + (hostfwd.is_udp ? "UDP" : "TCP") + " host port " +
                    std::to_string(hostfwd.host_port) + " to guest port " + std::to_string(hostfwd.guest_port)};
        }
    }
}

virtio_net_user_address_range::~virtio_net_user_address_range() {
    // Cleanup slirp
    if (slirp != nullptr) {
        slirp_cleanup(slirp);
        slirp = nullptr;
    }
    // Delete remaining timers created by slirp
    for (slirp_timer *timer : timers) {
        delete timer;
    }
    timers.clear();
}

void virtio_net_user_address_range::do_net_reset() {
    // Nothing to do, we don't want to reset slirp to not lose network state.
}

struct slirp_select_fds {
    int *pmaxfd;
    fd_set *readfds;
    fd_set *writefds;
    fd_set *exceptfds;
};

static int slirp_add_poll_cb(int fd, int events, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *fds = reinterpret_cast<slirp_select_fds *>(opaque);
    if ((events & SLIRP_POLL_IN) != 0) {
        FD_SET(fd, fds->readfds);
    }
    if ((events & SLIRP_POLL_OUT) != 0) {
        FD_SET(fd, fds->writefds);
    }
    if ((events & SLIRP_POLL_PRI) != 0) {
        FD_SET(fd, fds->exceptfds);
    }
    *fds->pmaxfd = std::max(fd, *fds->pmaxfd);
    return fd;
}

static int slirp_get_revents_cb(int fd, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *fds = reinterpret_cast<slirp_select_fds *>(opaque);
    int event = 0;
    if (FD_ISSET(fd, fds->readfds)) {
        event |= SLIRP_POLL_IN;
    }
    if (FD_ISSET(fd, fds->writefds)) {
        event |= SLIRP_POLL_OUT;
    }
    if (FD_ISSET(fd, fds->exceptfds)) {
        event |= SLIRP_POLL_PRI;
    }
    return event;
}

void virtio_net_user_address_range::do_net_prepare_select(select_fd_sets *fds, uint64_t *timeout_us) {
    // Did device reset and slirp failed to reinitialize?
    if (slirp == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *writefds = reinterpret_cast<fd_set *>(fds->writefds);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *exceptfds = reinterpret_cast<fd_set *>(fds->exceptfds);
    slirp_select_fds slirp_fds{.pmaxfd = &fds->maxfd, .readfds = readfds, .writefds = writefds, .exceptfds = exceptfds};
    const uint32_t initial_timeout_ms = *timeout_us / 1000;
    uint32_t timeout_ms = initial_timeout_ms;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    slirp_pollfds_fill(slirp, &timeout_ms, slirp_add_poll_cb, &slirp_fds);
#pragma GCC diagnostic pop
    if (initial_timeout_ms != timeout_ms) {
        *timeout_us = static_cast<uint64_t>(timeout_ms) * 1000;
    }
}

bool virtio_net_user_address_range::do_net_poll_selected(int select_ret, select_fd_sets *fds) {
    // Did device reset and slirp failed to reinitialize?
    if (slirp == nullptr) {
        return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *writefds = reinterpret_cast<fd_set *>(fds->writefds);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *exceptfds = reinterpret_cast<fd_set *>(fds->exceptfds);
    slirp_select_fds slirp_fds{.pmaxfd = nullptr, .readfds = readfds, .writefds = writefds, .exceptfds = exceptfds};
    slirp_pollfds_poll(slirp, static_cast<int>(select_ret < 0), slirp_get_revents_cb, &slirp_fds);
    // Fire expired timers
    const int64_t now_ms = slirp_clock_get_ns(nullptr) / 1000000;
    for (slirp_timer *timer : timers) {
        if (timer->expire_timer_msec != -1 && now_ms >= timer->expire_timer_msec) {
            if (timer->cb != nullptr) {
                timer->cb(timer->cb_opaque);
            }
            // The timer should not fire again until expire_timer_msec is modified by Slirp
            timer->expire_timer_msec = -1;
        }
    }
    return !send_packets.empty();
}

bool virtio_net_user_address_range::do_net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t read_avail_len, uint32_t *pread_len) {
    // Did device reset and slirp failed to reinitialize?
    if (slirp == nullptr) {
        // Just drop it.
        *pread_len = 0;
        return true;
    }
    const uint32_t packet_len = read_avail_len - VIRTIO_NET_ETHERNET_FRAME_OFFSET;
    if (packet_len > VIRTIO_NET_ETHERNET_MAX_LENGTH) {
        // This is unexpected, guest is trying to send jumbo Ethernet frames? Just drop it.
        *pread_len = 0;
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "slirp: dropped large packet with length %u sent by the guest\n",
            static_cast<unsigned int>(packet_len));
#endif
        return true;
    }
    slirp_packet packet{.len = packet_len};
    if (!vq.read_desc_mem(a, desc_idx, VIRTIO_NET_ETHERNET_FRAME_OFFSET, packet.buf.data(), packet.len)) {
        // Failure while accessing guest memory, the driver or guest messed up, return false to reset the device.
        return false;
    }
    slirp_input(slirp, packet.buf.data(), static_cast<int>(packet.len));
    // Packet was read and the queue is ready to be consumed.
    *pread_len = read_avail_len;
    return true;
}

bool virtio_net_user_address_range::do_net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t write_avail_len, uint32_t *pwritten_len) {
    // If no packet was send by slirp, we can just ignore.
    if (send_packets.empty()) {
        *pwritten_len = 0;
        return true;
    }
    // Retrieve the next packet sent by slirp.
    slirp_packet packet = send_packets.front();
    send_packets.pop_front();
    // Is there enough space in the write buffer to write this packet?
    if (VIRTIO_NET_ETHERNET_FRAME_OFFSET + packet.len > write_avail_len) {
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "slirp: dropped large packet with length %u sent by the host\n",
            static_cast<unsigned int>(packet.len));
#endif
        // Despite being a failure, return true to only drop the packet, we don't want to reset the device.
        *pwritten_len = 0;
        return true;
    }
    if (!vq.write_desc_mem(a, desc_idx, VIRTIO_NET_ETHERNET_FRAME_OFFSET, packet.buf.data(), packet.len)) {
        // Failure while accessing guest memory, the driver or guest messed up, return false to reset the device.
        return false;
    }
    // Packet was written and the queue is ready to be consumed.
    *pwritten_len = VIRTIO_NET_ETHERNET_FRAME_OFFSET + packet.len;
    return true;
}

} // namespace cartesi

#endif // HAVE_SLIRP
