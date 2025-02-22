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
/// \brief VirtIO network carrier TUN/TAP implementation.
/// \details \{
///
/// To have guest networking host's tap0 network interface,
/// execute the following commands in the host with root privilege
/// before starting the machine:
///
///   modprobe tun
///   ip link add br0 type bridge
///   ip tuntap add dev tap0 mode tap user $USER
///   ip link set dev tap0 master br0
///   ip link set dev br0 up
///   ip link set dev tap0 up
///   ip addr add 192.168.3.1/24 dev br0
///
/// Then to share the host's internet access with the guest:
///   sysctl -w net.ipv4.ip_forward=1
///   iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
///
/// In the example above the host public internet interface is eth0, but this depends in the host.
///
/// Finally start the machine with using tap0 network carrier and
/// execute the following commands in the guest with root privilege:
///
///   ip link set dev eth0 up
///   ip addr add 192.168.3.2/24 dev eth0
///   ip route add default via 192.168.3.1 dev eth0
///   echo "nameserver 8.8.8.8" > /etc/resolv.conf
///
/// To test if everything works, try ping:
///
///   ping cartesi.io
///
/// \}

// #define DEBUG_VIRTIO_ERRORS

#include "virtio-net-tuntap-address-range.h"

#ifdef HAVE_TUNTAP

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#include "i-device-state-access.h"
#include "os.h"

// Include TUN/TAP headers
#ifdef __linux__
#include <linux/if_tun.h>
constexpr const char NET_TUN_DEV[] = "/dev/net/tun";
#else // Other platform, most likely MacOS or FreeBSD
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000 // Don't provide packet info
#define TUNSETIFF _IOW('T', 202, int)
constexpr const char NET_TUN_DEV[] = "/dev/tun";
#endif

namespace cartesi {

virtio_net_tuntap_address_range::virtio_net_tuntap_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx,
    const std::string &tap_name) :
    virtio_net_address_range("VirtIO Net TUN/TAP", start, length, virtio_idx) {
    // Open the tun device
    const int flags = O_RDWR | // Read/write
        O_NONBLOCK |           // Read/write should never block
        O_DSYNC;               // Flush packets right-away upon write
    const int fd = open(NET_TUN_DEV, flags);
    if (fd < 0) {
        throw std::runtime_error(
            std::string("could not open tun network device '") + NET_TUN_DEV + "': " + strerror(errno));
    }
    // Set the tap network interface
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | // TAP device
        IFF_NO_PI;            // Do not provide packet information
    strncpy(ifr.ifr_name, tap_name.c_str(), sizeof(ifr.ifr_name));
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        close(fd);
        throw std::runtime_error(
            std::string("could not configure tap network device '") + tap_name + "': " + strerror(errno));
    }
    m_tapfd = fd;
}

virtio_net_tuntap_address_range::~virtio_net_tuntap_address_range() {
    if (m_tapfd != -1) {
        close(m_tapfd);
    }
}

void virtio_net_tuntap_address_range::net_reset() {
    // Nothing to do.
}

void virtio_net_tuntap_address_range::net_prepare_select(select_fd_sets *fds, uint64_t * /*timeout_us*/) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    FD_SET(m_tapfd, readfds);
    fds->maxfd = std::max(m_tapfd, fds->maxfd);
}

bool virtio_net_tuntap_address_range::net_poll_selected(int select_ret, select_fd_sets *fds) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *readfds = reinterpret_cast<fd_set *>(fds->readfds);
    return select_ret > 0 && FD_ISSET(m_tapfd, readfds);
}

bool virtio_net_tuntap_address_range::net_write_packet_to_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t read_avail_len, uint32_t *pread_len) {
    // Determinate packet size
    const uint32_t packet_len = read_avail_len - VIRTIO_NET_ETHERNET_FRAME_OFFSET;
    if (packet_len > VIRTIO_NET_ETHERNET_MAX_LENGTH) {
        // This is unexpected, guest is trying to send jumbo Ethernet frames? Just drop it.
        *pread_len = 0;
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "tun: dropped large packet with length %u sent by the guest\n",
            static_cast<unsigned int>(packet_len));
#endif
        return true;
    }
    // Read packet from queue buffer
    std::array<uint8_t, VIRTIO_NET_ETHERNET_MAX_LENGTH> packet_buf{};
    if (!vq.read_desc_mem(a, desc_idx, VIRTIO_NET_ETHERNET_FRAME_OFFSET, packet_buf.data(), packet_len)) {
        // Failure while accessing guest memory, the driver or guest messed up, return false to reset the device.
        return false;
    }
    // Keep writing until all packet bytes are written
    uint32_t written_packet_len = 0;
    while (written_packet_len < packet_len) {
        // Set errno to zero because write() may not set it when its return is zero
        errno = 0;
        // Write to the network interface
        const ssize_t written_len =
            write(m_tapfd, packet_buf.data() + written_packet_len, packet_len - written_packet_len);
        if (written_len <= 0) {
            // Retry again when the operation would block or was interrupted
            if (errno == EAGAIN || errno == EINTR) {
                // sched_yield() lets the host CPU scheduler switch to other processes,
                // so we avoid consuming host CPU resources in this infinite loop,
                // ??E: We could also use a usleep() here when sched_yield() is not supported.
                sched_yield();
            } else {
                // Unexpected error, return false to reset the device.
                return false;
            }
        }
        written_packet_len += static_cast<uint32_t>(written_len);
    }
    // Packet was read and the queue is ready to be consumed.
    *pread_len = read_avail_len;
    return true;
}

bool virtio_net_tuntap_address_range::net_read_packet_from_host(i_device_state_access *a, virtq &vq, uint16_t desc_idx,
    uint32_t write_avail_len, uint32_t *pwritten_len) {
    // Write network to queue buffer in chunks
    std::array<uint8_t, VIRTIO_NET_ETHERNET_MAX_LENGTH> packet_buf{};
    // Set errno to zero because read() will not set it when it returns zero (end of file)
    errno = 0;
    // Read the next packet from the network interface
    const ssize_t read_len = read(m_tapfd, packet_buf.data(), VIRTIO_NET_ETHERNET_MAX_LENGTH);
    if (read_len <= 0) {
        // Stop when the operation would block or was interrupted,
        // the next poll will read any pending packet.
        if (errno == EAGAIN || errno == EINTR) {
            // There is no packet available.
            *pwritten_len = 0;
            return true;
        } // Unexpected error, return false to reset the device.
        return false;
    }
    const auto packet_len = static_cast<uint32_t>(read_len);
    // Is there enough space in the write buffer to write this packet?
    if (VIRTIO_NET_ETHERNET_FRAME_OFFSET + packet_len > write_avail_len ||
        packet_len == VIRTIO_NET_ETHERNET_MAX_LENGTH) {
#ifdef DEBUG_VIRTIO_ERRORS
        std::ignore = fprintf(stderr, "tun: dropped large packet with length %u sent by the host\n",
            static_cast<unsigned int>(packet_len));
#endif
        // Despite being a failure, return true to only drop the packet, we don't want to reset the device.
        *pwritten_len = 0;
        return true;
    }
    // Write to queue buffer
    if (!vq.write_desc_mem(a, desc_idx, VIRTIO_NET_ETHERNET_FRAME_OFFSET, packet_buf.data(), packet_len)) {
        // Failure while accessing guest memory, the driver or guest messed up, return false to reset the device.
        return false;
    }
    // Packet was written and the queue is ready to be consumed.
    *pwritten_len = VIRTIO_NET_ETHERNET_FRAME_OFFSET + packet_len;
    return true;
}

} // namespace cartesi

#endif // HAVE_TUNTAP
