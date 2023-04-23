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

#ifndef VIRTIO_CONSOLE_H
#define VIRTIO_CONSOLE_H

#include "virtio-device.h"

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
class virtio_console final : public virtio_device {
    bool m_stdin_ready = false;

public:
    virtio_console(uint32_t virtio_idx);

    void on_device_reset() override;
    void on_device_ok(i_device_state_access *a) override;
    bool on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len) override;

    bool write_next_chars_to_host(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len);
    bool write_next_chars_to_guest(i_device_state_access *a);
    bool notify_console_size_to_guest(i_device_state_access *a);

    void poll_before_select(int *pmaxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        timeval *timeout) override;
    bool poll_after_select(i_device_state_access *a, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        int select_ret) override;

    virtio_console_config_space *get_config() {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<virtio_console_config_space *>(config_space.data());
    }
};

} // namespace cartesi

#endif
