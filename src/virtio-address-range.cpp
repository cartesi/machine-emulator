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

// Enable these defines to debug VirtIO
// #define DEBUG_VIRTIO
// #define DEBUG_VIRTIO_MMIO
// #define DEBUG_VIRTIO_ERRORS

#include "virtio-address-range.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>

#include "i-device-state-access.h"
#include "interpret.h"
#include "os.h"
#include "plic-address-range.h"
#include "strict-aliasing.h"

namespace cartesi {

static inline bool is_power_of_2(uint32_t val) {
    return (val & (val - 1)) == 0;
}

static inline void set_low32(uint64_t *paddr, uint32_t val) {
    *paddr = (*paddr & ~UINT64_C(0xffffffff)) | static_cast<uint64_t>(val);
}

static inline void set_high32(uint64_t *paddr, uint32_t val) {
    *paddr = (*paddr & UINT64_C(0xffffffff)) | (static_cast<uint64_t>(val) << 32);
}

static bool virtq_get_avail_header(const virtq &vq, i_device_state_access *a, virtq_header *pavail_header) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return a->read_memory(vq.avail_addr, reinterpret_cast<unsigned char *>(pavail_header), sizeof(virtq_header));
}

static bool virtq_set_used_header(const virtq &vq, i_device_state_access *a, const virtq_header *pused_header) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return a->write_memory(vq.used_addr, reinterpret_cast<const unsigned char *>(pused_header), sizeof(virtq_header));
}

static bool virtq_set_ring_used_elem(const virtq &vq, i_device_state_access *a, uint16_t ring_idx,
    const virtq_used_elem *pused_elem) {
    const uint64_t addr = vq.used_addr + sizeof(virtq_header) + ((ring_idx & (vq.num - 1)) * sizeof(virtq_used_elem));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return a->write_memory(addr, reinterpret_cast<const unsigned char *>(pused_elem), sizeof(virtq_used_elem));
}

static bool virtq_get_ring_avail_elem_desc_idx(const virtq &vq, i_device_state_access *a, uint16_t ring_idx,
    uint16_t *pdesc_idx) {
    const uint64_t addr = vq.avail_addr + sizeof(virtq_header) + ((ring_idx & (vq.num - 1)) * sizeof(uint16_t));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return a->read_memory(addr, reinterpret_cast<unsigned char *>(pdesc_idx), sizeof(uint16_t));
}

static bool virtq_get_desc(const virtq &vq, i_device_state_access *a, uint16_t desc_idx, virtq_desc *pdesc) {
    const uint64_t addr = vq.desc_addr + ((desc_idx & (vq.num - 1)) * sizeof(virtq_desc));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return a->read_memory(addr, reinterpret_cast<unsigned char *>(pdesc), sizeof(virtq_desc));
}

#if defined(DEBUG_VIRTIO_MMIO) || defined(DEBUG_VIRTIO_ERRORS)
static const char *get_virtio_mmio_offset_name(uint64_t offset) {
    if (offset >= VIRTIO_MMIO_CONFIG) {
        return "VIRTIO_MMIO_CONFIG";
    }
    switch (offset) {
        case VIRTIO_MMIO_MAGIC_VALUE:
            return "VIRTIO_MMIO_MAGIC_VALUE";
        case VIRTIO_MMIO_VERSION:
            return "VIRTIO_MMIO_VERSION";
        case VIRTIO_MMIO_DEVICE_ID:
            return "VIRTIO_MMIO_DEVICE_ID";
        case VIRTIO_MMIO_VENDOR_ID:
            return "VIRTIO_MMIO_VENDOR_ID";
        case VIRTIO_MMIO_DEVICE_FEATURES:
            return "VIRTIO_MMIO_DEVICE_FEATURES";
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            return "VIRTIO_MMIO_DEVICE_FEATURES_SEL";
        case VIRTIO_MMIO_DRIVER_FEATURES:
            return "VIRTIO_MMIO_DRIVER_FEATURES";
        case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
            return "VIRTIO_MMIO_DRIVER_FEATURES_SEL";
        case VIRTIO_MMIO_QUEUE_SEL:
            return "VIRTIO_MMIO_QUEUE_SEL";
        case VIRTIO_MMIO_QUEUE_NUM_MAX:
            return "VIRTIO_MMIO_QUEUE_NUM_MAX";
        case VIRTIO_MMIO_QUEUE_NUM:
            return "VIRTIO_MMIO_QUEUE_NUM";
        case VIRTIO_MMIO_QUEUE_READY:
            return "VIRTIO_MMIO_QUEUE_READY";
        case VIRTIO_MMIO_QUEUE_NOTIFY:
            return "VIRTIO_MMIO_QUEUE_NOTIFY";
        case VIRTIO_MMIO_INTERRUPT_STATUS:
            return "VIRTIO_MMIO_INTERRUPT_STATUS";
        case VIRTIO_MMIO_INTERRUPT_ACK:
            return "VIRTIO_MMIO_INTERRUPT_ACK";
        case VIRTIO_MMIO_STATUS:
            return "VIRTIO_MMIO_STATUS";
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            return "VIRTIO_MMIO_QUEUE_DESC_LOW";
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            return "VIRTIO_MMIO_QUEUE_DESC_HIGH";
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            return "VIRTIO_MMIO_QUEUE_AVAIL_LOW";
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            return "VIRTIO_MMIO_QUEUE_AVAIL_HIGH";
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            return "VIRTIO_MMIO_QUEUE_USED_LOW";
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            return "VIRTIO_MMIO_QUEUE_USED_HIGH";
        case VIRTIO_MMIO_SHM_SEL:
            return "VIRTIO_MMIO_SHM_SEL";
        case VIRTIO_MMIO_SHM_LEN_LOW:
            return "VIRTIO_MMIO_SHM_LEN_LOW";
        case VIRTIO_MMIO_SHM_LEN_HIGH:
            return "VIRTIO_MMIO_SHM_LEN_HIGH";
        case VIRTIO_MMIO_SHM_BASE_LOW:
            return "VIRTIO_MMIO_SHM_BASE_LOW";
        case VIRTIO_MMIO_SHM_BASE_HIGH:
            return "VIRTIO_MMIO_SHM_BASE_HIGH";
        case VIRTIO_MMIO_CONFIG_GENERATION:
            return "VIRTIO_MMIO_CONFIG_GENERATION";
        case VIRTIO_MMIO_CONFIG:
            return "VIRTIO_MMIO_CONFIG";
        default:
            return "UNKNOWN";
    }
}
#endif

bool virtq::get_desc_rw_avail_len(i_device_state_access *a, uint16_t desc_idx, uint32_t *pread_avail_len,
    uint32_t *pwrite_avail_len) const {
    // Traverse all buffers in queue
    uint32_t read_len = 0;
    uint32_t write_len = 0;
    bool write_part = false;
    bool ret = false;
    while (true) {
        virtq_desc desc{};
        // Retrieve queue buffer description
        if (!virtq_get_desc(*this, a, desc_idx, &desc)) {
            break;
        }
        // We are only interested in read-only buffers
        if ((desc.flags & VIRTQ_DESC_F_WRITE) != 0) {
            write_len += desc.len;
            write_part = true;
        } else {
            // The driver must never place a read buffer after a write buffer
            if (write_part) {
                break;
            }
            read_len += desc.len;
        }
        // Stop when there are no more buffers in queue
        if ((desc.flags & VIRTQ_DESC_F_NEXT) == 0) {
            ret = true;
            break;
        }
        // Move to the next buffer description
        desc_idx = desc.next;
    }
    if (pread_avail_len != nullptr) {
        *pread_avail_len = read_len;
    }
    if (pwrite_avail_len != nullptr) {
        *pwrite_avail_len = write_len;
    }
    return ret;
}

bool virtq::read_desc_mem(i_device_state_access *a, uint16_t desc_idx, uint32_t start_off, unsigned char *data,
    uint32_t len) const {
    // Really do nothing when length is 0
    if (len == 0) {
        return true;
    }
    const uint32_t end_off = start_off + len;
    uint32_t buf_start_off = 0;
    // Traverse all buffers in queue
    while (true) {
        virtq_desc desc{};
        // Retrieve queue buffer description
        if (!virtq_get_desc(*this, a, desc_idx, &desc)) {
            return false;
        }
        // We are only interested in read-only buffers
        if ((desc.flags & VIRTQ_DESC_F_WRITE) == 0) {
            // Read from target physical memory in chunks
            const uint32_t buf_end_off = buf_start_off + desc.len;
            const uint32_t chunk_start_off = std::max(buf_start_off, start_off);
            const uint32_t chunk_end_off = std::min(buf_end_off, end_off);
            // Copy chunk when it intersects with the desired interval
            if (chunk_end_off > chunk_start_off) {
                const uint32_t paddr_off = chunk_start_off - buf_start_off;
                const uint32_t data_off = chunk_start_off - start_off;
                const uint32_t chunk_len = chunk_end_off - chunk_start_off;
                // Read chunk from physical memory
                if (!a->read_memory(desc.paddr + paddr_off, data + data_off, chunk_len)) {
                    return false;
                }
            }
            buf_start_off += desc.len;
            // Stop when we reach the buffer end offset
            if (chunk_end_off >= end_off) {
                return true;
            }
        }
        // Stop when there are no more buffers in queue
        if ((desc.flags & VIRTQ_DESC_F_NEXT) == 0) {
            // Operation failed because more chunks were expected
            return false;
        }
        // Move to the next buffer description
        desc_idx = desc.next;
    }
}

bool virtq::write_desc_mem(i_device_state_access *a, uint16_t desc_idx, uint32_t start_off, const unsigned char *data,
    uint32_t len) const {
    // Really do nothing when length is 0
    if (len == 0) {
        return true;
    }
    const uint32_t end_off = start_off + len;
    uint32_t buf_start_off = 0;
    // Traverse all buffers in queue
    while (true) {
        virtq_desc desc{};
        // Retrieve queue buffer description
        if (!virtq_get_desc(*this, a, desc_idx, &desc)) {
            return false;
        }
        // We are only interested in write-only buffers
        if ((desc.flags & VIRTQ_DESC_F_WRITE) != 0) {
            // Read from target physical memory in chunks
            const uint32_t buf_end_off = buf_start_off + desc.len;
            const uint32_t chunk_start_off = std::max(buf_start_off, start_off);
            const uint32_t chunk_end_off = std::min(buf_end_off, end_off);
            // Copy chunk when it intersects with the desired interval
            if (chunk_end_off > chunk_start_off) {
                const uint32_t paddr_off = chunk_start_off - buf_start_off;
                const uint32_t data_off = chunk_start_off - start_off;
                const uint32_t chunk_len = chunk_end_off - chunk_start_off;
                // Read chunk from physical memory
                if (!a->write_memory(desc.paddr + paddr_off, data + data_off, chunk_len)) {
                    return false;
                }
            }
            buf_start_off += desc.len;
            // Stop when we reach the buffer end offset
            if (chunk_end_off >= end_off) {
                return true;
            }
        }
        // Stop when there are no more buffers in queue
        if ((desc.flags & VIRTQ_DESC_F_NEXT) == 0) {
            // Operation failed because more chunks were expected
            return false;
        }
        // Move to the next buffer description
        desc_idx = desc.next;
    }
}

bool virtq::consume_desc(i_device_state_access *a, uint16_t desc_idx, uint32_t written_len, uint16_t used_flags) {
    // Sets the used ring element desc index and written length
    virtq_used_elem used_elem{};
    used_elem.id = desc_idx;
    used_elem.len = written_len;
    if (!virtq_set_ring_used_elem(*this, a, last_used_idx, &used_elem)) {
        return false;
    }
    // Note that this increment will eventually wrap around after 65535,
    // in both driver and device.
    const uint16_t next_last_used_idx = last_used_idx + 1;
    // Advance the last used ring index
    virtq_header used_header{};
    used_header.flags = used_flags;
    used_header.idx = next_last_used_idx;
    if (!virtq_set_used_header(*this, a, &used_header)) {
        return false;
    }
    last_used_idx = next_last_used_idx;
    return true;
}

virtio_address_range::virtio_address_range(const char *description, uint64_t start, uint64_t length,
    uint32_t virtio_idx, uint32_t device_id, uint64_t device_features, uint32_t config_space_size) :
    pristine_address_range(description, start, length, m_virtio_flags,
        [](const char *err) { throw std::invalid_argument{err}; }),
    virtio_idx(virtio_idx),
    device_id(device_id),
    device_features(device_features | VIRTIO_F_VERSION_1),
    config_space_size(config_space_size) {}

void virtio_address_range::reset(i_device_state_access *a) {
    on_device_reset();
    // The device MUST initialize device status to 0 upon reset.
    device_status = 0;
    driver_ok = false;
    // The device MUST have all configuration change events cleared upon reset.
    driver_features = 0;
    queue_sel = 0;
    shm_sel = 0;
    device_features_sel = 0;
    driver_features_sel = 0;
    // The device MUST clear all bits in InterruptStatus upon reset.
    int_status = 0;
    // The device MUST clear ready bits in the QueueReady register for all queues in the device upon reset.
    for (auto &vq : queue) {
        vq.desc_addr = 0;
        vq.avail_addr = 0;
        vq.used_addr = 0;
        vq.num = 0;
        vq.last_used_idx = 0;
        vq.ready = 0;
    }
    // The device MUST have all queue and configuration change events unmapped upon reset.
    reset_irq(a, VIRTIO_INT_STATUS_USED_BUFFER | VIRTIO_INT_STATUS_CONFIG_CHANGE);
}

void virtio_address_range::set_irq(i_device_state_access *a, uint32_t add_int_status) {
    int_status |= add_int_status;
#ifdef DEBUG_VIRTIO
    std::ignore = fprintf(stderr, "virtio[%d]: set_irq int_status=%d\n", virtio_idx, int_status);
#endif
    // When interrupt status is non-zero, we should set pending IRQ to the PLIC device
    if (int_status != 0) {
        plic_set_pending_irq(a, get_irq_id());
    }
}

void virtio_address_range::reset_irq(i_device_state_access *a, uint32_t rem_int_status) {
    int_status &= ~rem_int_status;
#ifdef DEBUG_VIRTIO
    std::ignore = fprintf(stderr, "virtio[%d]: reset_irq int_status=%d\n", virtio_idx, int_status);
#endif
    // When interrupt status is zero, we should clear pending IRQ from the PLIC device
    if (int_status == 0) {
        plic_reset_pending_irq(a, get_irq_id());
    } else {
        // The IRQ may have to be restored again
        plic_set_pending_irq(a, get_irq_id());
    }
}

void virtio_address_range::notify_queue_used(i_device_state_access *a) {
#if defined(DEBUG_VIRTIO)
    std::ignore = fprintf(stderr, "virtio[%d]: notify_queue_used\n", virtio_idx);
#endif
    // A device MUST NOT consume buffers or send any used buffer notifications to the driver before DRIVER_OK.
    if (driver_ok) {
        set_irq(a, VIRTIO_INT_STATUS_USED_BUFFER);
    }
}

void virtio_address_range::notify_device_needs_reset(i_device_state_access *a) {
    // A fatal failure happened while processing a queue.
#if defined(DEBUG_VIRTIO) || defined(DEBUG_VIRTIO_ERRORS)
    std::ignore = fprintf(stderr, "virtio[%d]: notify_device_needs_reset\n", virtio_idx);
#endif
    // The device SHOULD set DEVICE_NEEDS_RESET when it enters an error state that a reset is needed.
    device_status |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
    // If DRIVER_OK is set, after it sets DEVICE_NEEDS_RESET,
    // the device MUST send a device configuration change notification to the driver.
    notify_config_change(a);
}

void virtio_address_range::notify_config_change(i_device_state_access *a) {
    // Whenever device changes the configuration, we MUST changed its config generation,
    // so the driver knows that it should re-read its configuration.
    config_generation++;
#if defined(DEBUG_VIRTIO)
    std::ignore =
        fprintf(stderr, "virtio[%d]: notify_config_change config_generation=%d\n", virtio_idx, config_generation);
#endif
    // A device MUST NOT send config notifications until the driver initializes the device.
    if (driver_ok) {
        set_irq(a, VIRTIO_INT_STATUS_CONFIG_CHANGE);
    }
}

bool virtio_address_range::prepare_queue_write(i_device_state_access *a, uint32_t queue_idx, uint16_t *pdesc_idx,
    uint32_t *pwrite_avail_len) const {
    *pdesc_idx = 0;
    *pwrite_avail_len = 0;
    // A device MUST NOT send notifications until the driver initializes the device.
    assert(driver_ok);
    assert(queue_idx < VIRTIO_QUEUE_COUNT);
    // Retrieve queue
    const virtq &vq = queue[queue_idx];
    // Silently ignore when the queue is not ready yet
    if (vq.ready == 0) {
        return true;
    }
    // Retrieve available buffer
    virtq_header avail_header{};
    if (!virtq_get_avail_header(vq, a, &avail_header)) {
        return false;
    }
    const uint16_t last_avail_idx = avail_header.idx;
    // Check if have an available index in the ring to write to.
    // We can only use equality operator for this check,
    // because the last available ring index may wraparound before the last used ring index,
    // but eventually the last used ring index will also wraparound.
    if (vq.last_used_idx == last_avail_idx) {
        // Queue is full, we have to wait the driver to free a queue
        return true;
    }
    // Retrieve descriptor index for the next available ring element
    uint16_t desc_idx{};
    if (!virtq_get_ring_avail_elem_desc_idx(vq, a, vq.last_used_idx, &desc_idx)) {
        return false;
    }
    *pdesc_idx = desc_idx;
    // Retrieve maximum amount of bytes we can write to queue buffer
    uint32_t write_avail_len{};
    if (!vq.get_desc_rw_avail_len(a, desc_idx, nullptr, &write_avail_len)) {
        return false;
    }
    *pwrite_avail_len = write_avail_len;
    return true;
}

bool virtio_address_range::consume_queue(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t written_len, uint16_t used_flags) {
    // A device MUST NOT consume buffers or send any used buffer notifications to the driver before DRIVER_OK.
    assert(driver_ok);
    assert(queue_idx < VIRTIO_QUEUE_COUNT);
#ifdef DEBUG_VIRTIO
    std::ignore = fprintf(stderr, "virtio[%d]: consume_queue queue_idx=%d desc_idx=%d written_len=%d\n", virtio_idx,
        queue_idx, desc_idx, written_len);
#endif
    // Retrieve queue
    virtq &vq = queue[queue_idx];
    // Consume the buffer, so the driver is free to reuse it again
    return vq.consume_desc(a, desc_idx, written_len, used_flags);
}

void virtio_address_range::on_device_queue_notify(i_device_state_access *a, uint32_t queue_idx) {
    // The device MUST NOT consume buffers or notify the driver before DRIVER_OK
    if (!driver_ok) {
        return;
    }
    // Retrieve queue
    const virtq &vq = queue[queue_idx];
    // The device MUST NOT access virtual queue contents when QueueReady is zero.
    if (vq.ready == 0) {
        return;
    }
    // When the driver wants to send a buffer to the device, it fills in a slot in the descriptor table
    // (or chains several together), and writes the descriptor index into the available ring.
    virtq_header avail_header{};
    if (!virtq_get_avail_header(vq, a, &avail_header)) {
        notify_device_needs_reset(a);
        return;
    }
    const uint16_t last_avail_idx = avail_header.idx;
    // Process all queues until we reach the last available index
    while (vq.last_used_idx != last_avail_idx) {
        // Retrieve description index for this ring element
        const uint32_t last_used_idx = vq.last_used_idx;
        uint16_t desc_idx{};
        if (!virtq_get_ring_avail_elem_desc_idx(vq, a, last_used_idx, &desc_idx)) {
            notify_device_needs_reset(a);
            return;
        }
        uint32_t read_avail_len{};
        uint32_t write_avail_len{};
        if (!vq.get_desc_rw_avail_len(a, desc_idx, &read_avail_len, &write_avail_len)) {
            notify_device_needs_reset(a);
            return;
        }
#if defined(DEBUG_VIRTIO)
        std::ignore = fprintf(stderr,
            "virtio[%d]: on_device_queue_available queue_idx=%d last_avail_idx=%d last_used_idx=%d desc_idx=%d "
            "read_avail_len=%d write_avail_len=%d\n",
            virtio_idx, queue_idx, last_avail_idx, last_used_idx, desc_idx, read_avail_len, write_avail_len);
#endif
        // Process the queue
        if (!on_device_queue_available(a, queue_idx, desc_idx, read_avail_len, write_avail_len)) {
            // The device doesn't want to continue consuming this queue
            break;
        }
        // We expect the device receive to always consume queue before continuing
        assert(last_used_idx != vq.last_used_idx);
    }
}

void virtio_address_range::prepare_select(select_fd_sets * /*fds*/, uint64_t * /*timeout_us*/) {}

bool virtio_address_range::poll_selected(int /*select_ret*/, select_fd_sets * /*fds*/, i_device_state_access * /*da*/) {
    return false;
};

bool virtio_address_range::poll_nowait(i_device_state_access *da) {
    uint64_t timeout_us = 0;
    return os_select_fds(
        [&](select_fd_sets *fds, uint64_t *timeout_us) -> void { this->prepare_select(fds, timeout_us); },
        [&](int select_ret, select_fd_sets *fds) -> bool { return this->poll_selected(select_ret, fds, da); },
        &timeout_us);
}

uint64_t virtio_address_range::read_shm_base(uint32_t /*shm_sel*/) const {
    // Reading from a non-existent region results in a base of 0xffffffffffffffff.
    return UINT64_C(-1);
}

uint64_t virtio_address_range::read_shm_length(uint32_t /*shm_sel*/) const {
    // Reading from a non-existent region results in a length of 0xffffffffffffffff.
    return UINT64_C(-1);
}

bool virtio_address_range::mmio_read_config(i_device_state_access * /*a*/, uint64_t offset, uint32_t *pval,
    int log2_size) const {
    const int size = 1 << log2_size;
    // Only accept aligned reads
    if ((offset & (size - 1)) != 0) {
        return false;
    }
    // Only accept reads inside config space
    if (offset + size > config_space_size) {
        return false;
    }
    // Only accept 1,2,4 byte config reads
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *config_space_buf = reinterpret_cast<const unsigned char *>(config_space.data());
    switch (log2_size) {
        case 0:
            *pval = aliased_aligned_read<uint8_t>(&config_space_buf[offset]);
            return true;
        case 1:
            *pval = aliased_aligned_read<uint16_t>(&config_space_buf[offset]);
            return true;
        case 2:
            *pval = aliased_aligned_read<uint32_t>(&config_space_buf[offset]);
            return true;
        default:
            return false;
    }
}

execute_status virtio_address_range::mmio_write_config(i_device_state_access * /*a*/, uint64_t offset, uint32_t val,
    int log2_size) {
    const int size = 1 << log2_size;
    // Only accept aligned writes
    if ((offset & (size - 1)) != 0) {
        return execute_status::failure;
    }
    // Only accept writes inside config space
    if (offset + size > config_space_size) {
        return execute_status::failure;
    }
    // Only accept 1,2,4 byte config writes
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *config_space_buf = reinterpret_cast<unsigned char *>(config_space.data());
    switch (log2_size) {
        case 0:
            aliased_aligned_write<uint8_t>(&config_space_buf[offset], val);
            return execute_status::success;
        case 1:
            aliased_aligned_write<uint16_t>(&config_space_buf[offset], val);
            return execute_status::success;
        case 2:
            aliased_aligned_write<uint32_t>(&config_space_buf[offset], val);
            return execute_status::success;
        default:
            return execute_status::failure;
    }
}

bool virtio_address_range::mmio_read(i_device_state_access *a, uint64_t offset, uint32_t *pval, int log2_size) const {
    // If offset is equal or greater than VIRTIO_MMIO_CONFIG, the driver is actually reading a device config
    if (offset >= VIRTIO_MMIO_CONFIG) {
        return mmio_read_config(a, offset - VIRTIO_MMIO_CONFIG, pval, log2_size);
    }
    // The driver MUST only use 32 bit wide and aligned reads to access the control registers
    if (((offset & 3) != 0) || log2_size != 2) {
        return false;
    }
    // Support only MMIO readable offsets according to the VirtIO spec
    switch (offset) {
        case VIRTIO_MMIO_MAGIC_VALUE:
            *pval = VIRTIO_MAGIC_VALUE;
            return true;
        case VIRTIO_MMIO_VERSION:
            *pval = VIRTIO_VERSION;
            return true;
        case VIRTIO_MMIO_DEVICE_ID:
            *pval = device_id;
            return true;
        case VIRTIO_MMIO_VENDOR_ID:
            *pval = VIRTIO_VENDOR_ID;
            return true;
        case VIRTIO_MMIO_DEVICE_FEATURES:
            // Reading from this register returns 32 consecutive flag bits,
            // the least significant bit depending on the last value written to DeviceFeaturesSel.
            switch (device_features_sel) {
                case 0:
                    *pval = static_cast<uint32_t>(device_features);
                    return true;
                case 1:
                    *pval = static_cast<uint32_t>(device_features >> 32);
                    return true;
                default:
                    *pval = 0;
                    return true;
            }
        case VIRTIO_MMIO_QUEUE_NUM_MAX:
            // Reading from this register returns the maximum size (number of elements) of the queue the device is ready
            // to process or zero if the queue is not available.
            *pval = (queue_sel < VIRTIO_QUEUE_COUNT) ? static_cast<uint32_t>(VIRTIO_QUEUE_NUM_MAX) : 0;
            return true;
        case VIRTIO_MMIO_QUEUE_READY:
            // Reading from this register returns the last value written to it.
            *pval = queue_sel < VIRTIO_QUEUE_COUNT ? queue[queue_sel].ready : 0;
            return true;
        case VIRTIO_MMIO_INTERRUPT_STATUS:
            // Reading from this register returns a bit mask of events that caused the device interrupt to be asserted.
            *pval = int_status;
            return true;
        case VIRTIO_MMIO_STATUS:
            // Reading from this register returns the current device status flags.
            *pval = device_status;
            return true;
        case VIRTIO_MMIO_CONFIG_GENERATION:
            // Reading from this register returns a value describing a version of the device-specific configuration
            // space.
            *pval = config_generation;
            return true;
        case VIRTIO_MMIO_SHM_LEN_LOW:
            *pval = static_cast<uint32_t>(read_shm_length(shm_sel));
            return true;
        case VIRTIO_MMIO_SHM_LEN_HIGH:
            *pval = static_cast<uint32_t>(read_shm_length(shm_sel) >> 32);
            return true;
        case VIRTIO_MMIO_SHM_BASE_LOW:
            *pval = static_cast<uint32_t>(read_shm_base(shm_sel));
            return true;
        case VIRTIO_MMIO_SHM_BASE_HIGH:
            *pval = static_cast<uint32_t>(read_shm_base(shm_sel) >> 32);
            return true;
        default:
            // Unsupported offset
            return false;
    }
}

execute_status virtio_address_range::mmio_write(i_device_state_access *a, uint64_t offset, uint32_t val,
    int log2_size) {
    // If offset is equal or greater than VIRTIO_MMIO_CONFIG, the driver is actually writing a device config
    if (offset >= VIRTIO_MMIO_CONFIG) {
        return mmio_write_config(a, offset - VIRTIO_MMIO_CONFIG, val, log2_size);
    }
    // The driver MUST only use 32 bit wide and aligned writes to access the control registers
    if (((offset & 3) != 0) || log2_size != 2) {
        return execute_status::failure;
    }
    // Support only MMIO writable offsets according to the VirtIO spec
    switch (offset) {
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            // Writing to this register selects a set of 32 device feature bits accessible by reading from
            // DeviceFeatures.
            device_features_sel = val;
            return execute_status::success;
        case VIRTIO_MMIO_DRIVER_FEATURES:
            // Writing to this register sets 32 consecutive flag bits, the least significant bit depending on the last
            // value written to DriverFeaturesSel.
            switch (driver_features_sel) {
                case 0:
                    set_low32(&driver_features, val);
                    break;
                case 1:
                    set_high32(&driver_features, val);
                    break;
                default:
                    // Silently ignore it.
                    break;
            }
            return execute_status::success;
        case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
            // Writing to this register selects a set of 32 activated feature bits accessible by writing to
            // DriverFeatures.
            driver_features_sel = val;
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_SEL:
            // Writing to this register selects the virtual queue that the following operations on
            // QueueNumMax, QueueNum, QueueReady, QueueDescLow, QueueDescHigh, QueueAvailLow, QueueAvailHigh,
            // QueueUsedLow and QueueUsedHigh apply to.
            queue_sel = val;
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_NUM:
            // Writing to this register notifies the device what size of the queue the driver will use.
            // QueueSize value must always be less than QueueMax and a power of 2.
            if (queue_sel < VIRTIO_QUEUE_COUNT && val <= VIRTIO_QUEUE_NUM_MAX && is_power_of_2(val)) {
                queue[queue_sel].num = val;
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_READY:
            // Writing one to this register notifies the device that it can execute requests from this virtual queue.
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                queue[queue_sel].ready = (val == 1) ? 1 : 0;
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_NOTIFY:
            // Writing a value to this register notifies the device that there are new buffers to process in a queue.
            // The value written should be the queue index.
            if (val < VIRTIO_QUEUE_COUNT) {
                on_device_queue_notify(a, val);
            }
            // Most of times we will need to serve interrupts due to either used buffer or config change
            // notification
            return (int_status != 0) ? execute_status::success_and_serve_interrupts : execute_status::success;
        case VIRTIO_MMIO_INTERRUPT_ACK:
            // Writing a value with bits set as defined in InterruptStatus to this register notifies the device that
            // events causing the interrupt have been handled.
            reset_irq(a, val);
            return (int_status != 0) ? execute_status::success_and_serve_interrupts : execute_status::success;
        case VIRTIO_MMIO_STATUS:
            if (val == 0) {
                // Writing zero to this registers triggers a device reset.
                reset(a);
            } else {
                const uint32_t old_status = device_status;
                const uint64_t enabling_status = (device_status ^ val) & val;
                if ((enabling_status & VIRTIO_STATUS_FEATURES_OK) != 0) {
                    // The driver will re-read device status to ensure the FEATURES_OK bit is really set.
                    // We allow the device initialization to succeed only if the driver supports our device
                    // features.
                    if (driver_features != device_features) {
                        return execute_status::success;
                    }
                }
                // Writing non-zero values to this register sets the status flags, indicating the driver progress.
                device_status = val;
                if ((enabling_status & VIRTIO_STATUS_DRIVER_OK) != 0) {
                    // If DRIVER_OK is set, after it sets DEVICE_NEEDS_RESET, the device MUST send a device
                    // configuration change notification to the driver.
                    if ((old_status & VIRTIO_STATUS_DEVICE_NEEDS_RESET) != 0) {
                        set_irq(a, VIRTIO_INT_STATUS_CONFIG_CHANGE);
                    } else {
                        driver_ok = true;
                        on_device_ok(a);
                    }
                }
            }
            // We may have triggered an interrupt request
            return (int_status != 0) ? execute_status::success_and_serve_interrupts : execute_status::success;
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_low32(&queue[queue_sel].desc_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_low32(&queue[queue_sel].avail_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_low32(&queue[queue_sel].used_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_high32(&queue[queue_sel].desc_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_high32(&queue[queue_sel].avail_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            if (queue_sel < VIRTIO_QUEUE_COUNT) {
                set_high32(&queue[queue_sel].used_addr, val);
            }
            return execute_status::success;
        case VIRTIO_MMIO_SHM_SEL:
            // Writing to this register selects the shared memory region
            // following operations on SHMLenLow, SHMLenHigh, SHMBaseLow and SHMBaseHigh apply to.
            shm_sel = val;
            return execute_status::success;
        default:
            // Unsupported offset
            return execute_status::failure;
    }
}

bool virtio_address_range::do_read_device(i_device_state_access *a, uint64_t offset, int log2_size,
    uint64_t *pval) const noexcept {
    uint32_t val32 = 0;
    const bool status = mmio_read(a, offset, &val32, log2_size);
    if (status) {
        *pval = val32;
    }
#ifdef DEBUG_VIRTIO_MMIO
    std::ignore = fprintf(stderr, "virtio[%d]: mmio_read  offset=0x%03lx (%s) value=%d size=%d\n", get_virtio_index(),
        offset, get_virtio_mmio_offset_name(offset), val32, 1 << log2_size);
#endif
#if defined(DEBUG_VIRTIO_MMIO) || defined(DEBUG_VIRTIO_ERRORS)
    if (!status) {
        std::ignore = fprintf(stderr, "virtio[%d]: mmio_read FAILED!  offset=0x%03lx(%s) size=%d\n", get_virtio_index(),
            offset, get_virtio_mmio_offset_name(offset), 1 << log2_size);
    }
#endif
    return status;
}

/// \brief VirtIO device read callback. See ::pma_write.
execute_status virtio_address_range::do_write_device(i_device_state_access *a, uint64_t offset, int log2_size,
    uint64_t val) noexcept {
#ifdef DEBUG_VIRTIO_MMIO
    std::ignore = fprintf(stderr, "virtio[%d]: mmio_write offset=0x%03lx (%s) value=%ld size=%d\n", get_virtio_index(),
        offset, get_virtio_mmio_offset_name(offset), val, 1 << log2_size);
#endif
    const execute_status status = mmio_write(a, offset, val, log2_size);
#if defined(DEBUG_VIRTIO_MMIO) || defined(DEBUG_VIRTIO_ERRORS)
    if (status == execute_status::failure) {
        std::ignore = fprintf(stderr, "virtio[%d]: mmio_write FAILED! offset=0x%03lx (%s) value=%ld size=%d\n",
            get_virtio_index(), offset, get_virtio_mmio_offset_name(offset), val, 1 << log2_size);
    }
#endif
    return status;
}

} // namespace cartesi
