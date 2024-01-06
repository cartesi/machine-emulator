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

#ifndef VIRTIO_SERIALIZER_H
#define VIRTIO_SERIALIZER_H

#include "virtio-device.h"

namespace cartesi {

/// \brief Utility for unpacking formatted bytes from a Virtqueue buffer
struct virtq_unserializer {
    i_device_state_access *a;
    virtq &vq; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    uint32_t queue_idx;
    uint32_t desc_idx;
    uint32_t offset;

    explicit virtq_unserializer(i_device_state_access *a, virtq &vq, uint32_t queue_idx, uint32_t desc_idx,
        uint32_t offset = 0) :
        a(a),
        vq(vq),
        queue_idx(queue_idx),
        desc_idx(desc_idx),
        offset(offset) {}
    virtq_unserializer() = delete;
    ~virtq_unserializer() = default;
    virtq_unserializer(const virtq_unserializer &other) = delete;
    virtq_unserializer(virtq_unserializer &&other) = delete;
    virtq_unserializer &operator=(const virtq_unserializer &other) = delete;
    virtq_unserializer &operator=(virtq_unserializer &&other) = delete;

    bool read_bytes(unsigned char *data, uint32_t data_len) {
        if (!vq.read_desc_mem(a, desc_idx, offset, data, data_len)) {
            return false;
        }
        // Advance
        offset += data_len;
        return true;
    }

    template <typename T>
    bool read_value(T *pval) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (!vq.read_desc_mem(a, desc_idx, offset, reinterpret_cast<unsigned char *>(pval), sizeof(T))) {
            return false;
        }
        // Advance
        offset += sizeof(T);
        return true;
    }

    template <int N>
    bool read_value(char (*pval)[N]) {
        return read_u16_string(&pval[0], N);
    }

    bool read_u16_string(void *data, uint16_t data_max_len) {
        // Read the string size
        uint16_t len = 0;
        if (!read_value(&len)) {
            return false;
        }
        // Check if data has enough space for string size plus the NULL termination character
        if (len + 1 > data_max_len) {
            return false;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto *data_uchar = reinterpret_cast<unsigned char *>(data);
        // Read the string
        if (!vq.read_desc_mem(a, desc_idx, offset, data_uchar, len)) {
            return false;
        }
        data_uchar[len] = 0;
        // Advance
        offset += len;
        return true;
    }

    template <typename... Args>
    bool unpack(Args... args) {
        return (read_value(args) && ...);
    }
};

/// \brief Utility for packing formatted bytes into a Virtqueue buffer
struct virtq_serializer {
    i_device_state_access *a;
    virtq &vq; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    uint32_t queue_idx;
    uint32_t desc_idx;
    uint32_t offset;
    uint32_t length;

    explicit virtq_serializer(i_device_state_access *a, virtq &vq, uint32_t queue_idx, uint32_t desc_idx,
        uint32_t offset = 0) :
        a(a),
        vq(vq),
        queue_idx(queue_idx),
        desc_idx(desc_idx),
        offset(offset),
        length(offset) {}
    virtq_serializer() = delete;
    ~virtq_serializer() = default;
    virtq_serializer(const virtq_serializer &other) = delete;
    virtq_serializer(virtq_serializer &&other) = delete;
    virtq_serializer &operator=(const virtq_serializer &other) = delete;
    virtq_serializer &operator=(virtq_serializer &&other) = delete;

    bool write_bytes(const unsigned char *data, uint32_t data_len) {
        if (!vq.write_desc_mem(a, desc_idx, offset, data, data_len)) {
            return false;
        }
        // Advance
        offset += data_len;
        length = std::max(length, offset);
        return true;
    }

    bool write_u16_string(const void *data, uint16_t data_len) {
        // Write the string size
        if (!write_value(&data_len)) {
            return false;
        }
        // Write the string
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (!vq.write_desc_mem(a, desc_idx, offset, reinterpret_cast<const unsigned char *>(data), data_len)) {
            return false;
        }
        // Advance
        offset += data_len;
        length = std::max(length, offset);
        return true;
    }

    template <typename T>
    bool write_value(const T *pval) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (!vq.write_desc_mem(a, desc_idx, offset, reinterpret_cast<const unsigned char *>(pval), sizeof(T))) {
            return false;
        }
        // Advance
        offset += sizeof(T);
        length = std::max(length, offset);
        return true;
    }

    bool write_value(const char *pval) {
        return write_u16_string(pval, strlen(pval));
    }

    template <int N>
    bool write_value(const char pval[N]) {
        return write_u16_string(pval, strnlen(pval, N));
    }

    template <typename... Args>
    bool pack(Args... args) {
        return (write_value(args) && ...);
    }
};

} // namespace cartesi

#endif
