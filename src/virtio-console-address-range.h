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

#ifndef VIRTIO_CONSOLE_ADDRESS_RANGE_H
#define VIRTIO_CONSOLE_ADDRESS_RANGE_H

#include <cstdint>

#include "i-device-state-access.h"
#include "os.h"
#include "virtio-address-range.h"

namespace cartesi {

/// \brief VirtIO console features
enum virtio_console_features : uint64_t {
    VIRTIO_CONSOLE_F_SIZE = (UINT64_C(1) << 0),        ///< Console configuration cols and rows are valid.
    VIRTIO_CONSOLE_F_MULTIPORT = (UINT64_C(1) << 1),   ///< Device has support for multiple ports
    VIRTIO_CONSOLE_F_EMERG_WRITE = (UINT64_C(1) << 2), ///< Device has support for emergency write.
};

/// \brief VirtIO console virtqueue indexes
enum virtio_console_virtq : uint32_t {
    VIRTIO_CONSOLE_RECEIVEQ = 0,  ///< Queue transmitting characters from host to guest
    VIRTIO_CONSOLE_TRANSMITQ = 1, ///< Queue transmitting characters from guest to host
};

/// \brief VirtIO console config space
struct virtio_console_config_space {
    uint16_t cols;         ///< Console width
    uint16_t rows;         ///< Console height
    uint32_t max_nr_ports; ///< Maximum number of ports supported
    uint32_t emerg_wr;     ///< Whether emergency write is supported
};

/// \brief VirtIO console device
class virtio_console_address_range final : public virtio_address_range {
    bool m_stdin_ready = false;

public:
    explicit virtio_console_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx);

    virtio_console_address_range(const virtio_console_address_range &other) = delete;
    virtio_console_address_range &operator=(const virtio_console_address_range &other) = delete;
    virtio_console_address_range &operator=(virtio_console_address_range &&other) = delete;

    virtio_console_address_range(virtio_console_address_range &&other) = default;
    ~virtio_console_address_range() override = default;

    bool write_next_chars_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len);
    bool write_next_chars_to_guest(i_device_state_access *a);
    bool notify_console_size_to_guest(i_device_state_access *a);

    virtio_console_config_space *get_config() {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<virtio_console_config_space *>(config_space.data());
    }

private:
    void do_prepare_select(select_fd_sets *fds, uint64_t *timeout_us) override;
    bool do_poll_selected(int select_ret, select_fd_sets *fds, i_device_state_access *da) override;
    void do_on_device_reset() override;
    void do_on_device_ok(i_device_state_access *a) override;
    bool do_on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len) override;
};

static inline auto make_virtio_console_address_range(uint64_t start, uint64_t length, uint32_t virtio_idx) {
    return virtio_console_address_range{start, length, virtio_idx};
}

} // namespace cartesi

#endif
