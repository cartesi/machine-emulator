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
///   ip addr add 10.0.2.1/24 dev eth0
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

#include "virtio-net-carrier-slirp.h"

#include <cstring>
#include <ctime>

namespace cartesi {

static ssize_t slirp_send_packet(const void *buf, size_t len, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    virtio_net_carrier_slirp *carrier = reinterpret_cast<virtio_net_carrier_slirp *>(opaque);
    if (carrier->send_packets.size() >= SLIRP_MAX_PENDING_PACKETS) {
        // Too many send_packets in the write queue, we can just drop it.
        // Network re-transmission can recover from this.
#ifdef DEBUG_VIRTIO_ERRORS
        (void) fprintf(stderr, "slirp: dropped packet sent by the host because the write queue is full\n");
#endif
        return 0;
    }
    if (len > VIRTIO_NET_ETHERNET_MAX_LENGTH) {
        // This is unexpected, slirp is trying to send an a jumbo Ethernet frames? Drop it.
#ifdef DEBUG_VIRTIO_ERRORS
        (void) fprintf(stderr, "slirp: dropped large packet with length %u sent by the host\n",
            static_cast<unsigned int>(len));
#endif
        return 0;
    }
    // Add packet to the send packet queue,
    // the packet will actually be sent only the next time the device calls read_packet()
    slirp_packet packet{len};
    memcpy(packet.buf.data(), buf, len);
    try {
        carrier->send_packets.emplace_back(std::move(packet));
        return static_cast<ssize_t>(len);
    } catch (...) {
#ifdef DEBUG_VIRTIO_ERRORS
        (void) fprintf(stderr, "slirp: exception thrown while adding a send packet\n");
#endif
        return 0;
    }
}

static void slirp_guest_error(const char *msg, void *opaque) {
    (void) msg;
    (void) opaque;
#ifdef DEBUG_VIRTIO_ERRORS
    (void) fprintf(stderr, "slirp: %s\n", msg);
#endif
}

static int64_t slirp_clock_get_ns(void *opaque) {
    (void) opaque;
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void *slirp_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    virtio_net_carrier_slirp *carrier = reinterpret_cast<virtio_net_carrier_slirp *>(opaque);
    try {
        slirp_timer *timer = new slirp_timer;
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
    virtio_net_carrier_slirp *carrier = reinterpret_cast<virtio_net_carrier_slirp *>(opaque);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    slirp_timer *timer = reinterpret_cast<slirp_timer *>(timer_ptr);
    if (timer) {
        auto it = carrier->timers.find(timer);
        if (it != carrier->timers.end()) {
            carrier->timers.erase(it);
            delete timer;
        }
    }
}

static void slirp_timer_mod(void *timer_ptr, int64_t expire_timer_msec, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    virtio_net_carrier_slirp *carrier = reinterpret_cast<virtio_net_carrier_slirp *>(opaque);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    slirp_timer *timer = reinterpret_cast<slirp_timer *>(timer_ptr);
    if (timer && carrier->timers.find(timer) != carrier->timers.end()) {
        timer->expire_timer_msec = expire_timer_msec;
    }
}

static void slirp_register_poll_fd(int fd, void *opaque) {
    (void) fd;
    (void) opaque;
    // Nothing to do, this callback is only useful on implementations using poll() instead of select().
}

static void slirp_unregister_poll_fd(int fd, void *opaque) {
    (void) fd;
    (void) opaque;
    // Nothing to do, this callback is only useful on implementations using poll() instead of select().
}

static void slirp_notify(void *opaque) {
    (void) opaque;
    // Nothing to do
}

virtio_net_carrier_slirp::virtio_net_carrier_slirp() {
    // Configure slirp
    slirp_cfg.version = std::min<int>(SLIRP_CONFIG_VERSION_MAX, SLIRP_VERSION);
    slirp_cfg.restricted = false;                                         // Don't isolate the guest from the host
    slirp_cfg.in_enabled = true;                                          // IPv4 is enabled
    slirp_cfg.vnetwork.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNETWORK);       // Network
    slirp_cfg.vnetmask.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNETMASK);       // Netmask
    slirp_cfg.vhost.s_addr = htonl(SLIRP_DEFAULT_IPV4_VHOST);             // Host address/gateway
    slirp_cfg.vdhcp_start.s_addr = htonl(SLIRP_DEFAULT_IPV4_VDHCP_START); // DHCP start address
    slirp_cfg.vnameserver.s_addr = htonl(SLIRP_DEFAULT_IPV4_VNAMESERVER); // DNS server address
    // TODO(edubart): Should all the above settings be configurable by the user?
    // TODO(edubart): Should we add support for IPv6? It is disabled by default.
    // Configure required slirp callbacks
    slirp_cbs.send_packet = slirp_send_packet;
    slirp_cbs.guest_error = slirp_guest_error;
    slirp_cbs.clock_get_ns = slirp_clock_get_ns;
    slirp_cbs.timer_new = slirp_timer_new;
    slirp_cbs.timer_free = slirp_timer_free;
    slirp_cbs.timer_mod = slirp_timer_mod;
    slirp_cbs.register_poll_fd = slirp_register_poll_fd;
    slirp_cbs.unregister_poll_fd = slirp_unregister_poll_fd;
    slirp_cbs.notify = slirp_notify;
    // Initialize slirp
    slirp = slirp_new(&slirp_cfg, &slirp_cbs, this);
    if (!slirp) {
        throw std::runtime_error("could not configure slirp network device");
    }
}

virtio_net_carrier_slirp::~virtio_net_carrier_slirp() {
    // Cleanup slirp
    if (slirp) {
        slirp_cleanup(slirp);
        slirp = nullptr;
    }
    // Delete remaining timers created by slirp
    for (slirp_timer *timer : timers) {
        delete timer;
    }
    timers.clear();
}

void virtio_net_carrier_slirp::reset() {
    // Cleanup slirp
    if (slirp) {
        slirp_cleanup(slirp);
        slirp = nullptr;
    }
    send_packets.clear();
    // Delete remaining timers created by slirp
    for (slirp_timer *timer : timers) {
        delete timer;
    }
    timers.clear();
    // Initialize slirp again
    slirp = slirp_new(&slirp_cfg, &slirp_cbs, this);
#ifdef DEBUG_VIRTIO_ERRORS
    if (!slirp) {
        (void) fprintf(stderr, "slirp: failed to reinitialize\n");
    }
#endif
}

struct slirp_select_fds {
    int *pmaxfd;
    fd_set *readfds;
    fd_set *writefds;
    fd_set *exceptfds;
};

static int slirp_add_poll_cb(int fd, int events, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    slirp_select_fds *fds = reinterpret_cast<slirp_select_fds *>(opaque);
    if (events & SLIRP_POLL_IN) {
        FD_SET(fd, fds->readfds);
    }
    if (events & SLIRP_POLL_OUT) {
        FD_SET(fd, fds->writefds);
    }
    if (events & SLIRP_POLL_PRI) {
        FD_SET(fd, fds->exceptfds);
    }
    if (fd > *fds->pmaxfd) {
        *fds->pmaxfd = fd;
    }
    return fd;
}

static int slirp_get_revents_cb(int fd, void *opaque) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    slirp_select_fds *fds = reinterpret_cast<slirp_select_fds *>(opaque);
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

void virtio_net_carrier_slirp::do_poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    timeval *timeout) {
    // Did device reset and slirp failed to reinitialize?
    if (!slirp) {
        return;
    }
    slirp_select_fds fds{pmaxfd, readfds, writefds, exceptfds};
    uint32_t timeout_ms =
        static_cast<uint32_t>(timeout->tv_sec * 1000) + static_cast<uint32_t>(timeout->tv_usec / 1000);
    slirp_pollfds_fill(slirp, &timeout_ms, slirp_add_poll_cb, &fds);
    timeout->tv_sec = std::min(timeout->tv_sec, static_cast<time_t>(timeout_ms / 1000));
    timeout->tv_usec = std::min(timeout->tv_usec, static_cast<suseconds_t>(timeout_ms % 1000) * 1000);
}

bool virtio_net_carrier_slirp::do_poll_after_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    int select_ret) {
    // Did device reset and slirp failed to reinitialize?
    if (!slirp) {
        return false;
    }
    slirp_select_fds fds{nullptr, readfds, writefds, exceptfds};
    slirp_pollfds_poll(slirp, select_ret < 0, slirp_get_revents_cb, &fds);
    // Fire expired timers
    const int64_t now_ms = slirp_clock_get_ns(nullptr) / 1000000;
    for (slirp_timer *timer : timers) {
        if (timer->expire_timer_msec != -1 && now_ms >= timer->expire_timer_msec) {
            if (timer->cb) {
                timer->cb(timer->cb_opaque);
            }
            // The timer should not fire again until expire_timer_msec is modified by Slirp
            timer->expire_timer_msec = -1;
        }
    }
    return !send_packets.empty();
}

bool virtio_net_carrier_slirp::write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t read_avail_len, uint32_t *pread_len) {
    // Did device reset and slirp failed to reinitialize?
    if (!slirp) {
        // Just drop it.
        *pread_len = 0;
        return true;
    }
    const uint32_t packet_len = read_avail_len - VIRTIO_NET_ETHERNET_FRAME_OFFSET;
    if (packet_len > VIRTIO_NET_ETHERNET_MAX_LENGTH) {
        // This is unexpected, guest is trying to send jumbo Ethernet frames? Just drop it.
        *pread_len = 0;
#ifdef DEBUG_VIRTIO_ERRORS
        (void) fprintf(stderr, "slirp: dropped large packet with length %u sent by the guest\n",
            static_cast<unsigned int>(packet_len));
#endif
        return true;
    }
    slirp_packet packet{packet_len};
    if (!vq.read_desc_mem(a, desc_idx, VIRTIO_NET_ETHERNET_FRAME_OFFSET, packet.buf.data(), packet.len)) {
        // Failure while accessing guest memory, the driver or guest messed up, return false to reset the device.
        return false;
    }
    slirp_input(slirp, packet.buf.data(), static_cast<int>(packet.len));
    // Packet was read and the queue is ready to be consumed.
    *pread_len = read_avail_len;
    return true;
}

bool virtio_net_carrier_slirp::read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t write_avail_len, uint32_t *pwritten_len) {
    // If no packet was send by slirp, we can just ignore.
    if (send_packets.empty()) {
        *pwritten_len = 0;
        return true;
    }
    // Retrieve the next packet sent by slirp.
    slirp_packet packet = std::move(send_packets.front());
    send_packets.pop_front();
    // Is there enough space in the write buffer to write this packet?
    if (VIRTIO_NET_ETHERNET_FRAME_OFFSET + packet.len > write_avail_len) {
#ifdef DEBUG_VIRTIO_ERRORS
        (void) fprintf(stderr, "slirp: dropped large packet with length %u sent by the host\n",
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
