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

#ifndef VIRTIO_DEVICE_H
#define VIRTIO_DEVICE_H

#include <array>
#include <cstdint>
#include <cstring>

#include <sys/select.h>

#include "i-device-state-access.h"
#include "os.h"
#include "pma.h"

namespace cartesi {

/// \brief VirtIO constants
enum virtio_constants : uint32_t {
    VIRTIO_MAGIC_VALUE = 0x74726976, // Little-endian equivalent of the "virt" string
    VIRTIO_VERSION = 0x2,            ///< Compliance with VirtIO v1.2 specification for non-legacy devices
    VIRTIO_VENDOR_ID = 0xffff,       ///< Dummy vendor ID
    VIRTIO_QUEUE_COUNT = 2,          ///< All devices we implement so far just need 2 queues
    VIRTIO_QUEUE_NUM_MAX = 128,      ///< Number of elements in queue ring, it should be at least 128 for most drivers
    VIRTIO_MAX_CONFIG_SPACE_SIZE = 256, ///< Maximum size of config space
    VIRTIO_MAX = 31,                    ///< Maximum number of virtio devices
};

/// \brief VirtIO features flags
enum virtio_features : uint64_t {
    VIRTIO_F_INDIRECT_DESC =
        (UINT64_C(1) << 28),                  ///< The driver can use descriptors with the VIRTQ_DESC_F_INDIRECT flag.
    VIRTIO_F_EVENT_IDX = (UINT64_C(1) << 29), ///< Enables the used_event and the avail_event fields.
    VIRTIO_F_VERSION_1 = (UINT64_C(1) << 32), ///< Compliance with VirtIO v1.2 specification
    VIRTIO_F_ACCESS_PLATFORM = (UINT64_C(1) << 33), ///< The device can be used on a platform where device access to
                                                    ///< data in memory is limited and/or translated.
    VIRTIO_F_RING_PACKED = (UINT64_C(1) << 34),     ///< Support for the packed virtqueue layout.
    VIRTIO_F_IN_ORDER = (UINT64_C(1)
        << 35), ///< All buffers are used by the device in the same order in which they have been made available.
    VIRTIO_F_ORDER_PLATFORM = (UINT64_C(1)
        << 36), ///< Memory accesses by the driver and the device are ordered in a way described by the platform.
    VIRTIO_F_SR_IOV = (UINT64_C(1) << 37),            ///< Supports Single Root I/O Virtualization (PCI only).
    VIRTIO_F_NOTIFICATION_DATA = (UINT64_C(1) << 38), ///< The driver passes extra data in its device notifications.
    VIRTIO_F_NOTIF_CONFIG_DATA = (UINT64_C(1) << 39), ///< The driver uses the data provided by the device as a
                                                      ///< virtqueue identifier in available buffer notifications.
    VIRTIO_F_RING_RESET = (UINT64_C(1) << 40),        ///< The driver can reset a queue individually.
};

/// \brief VirtIO device types as defined in VirtIO v1.2 specification
enum virtio_devices : uint32_t {
    VIRTIO_DEVICE_INVALID = 0,
    VIRTIO_DEVICE_NETWORK = 1,
    VIRTIO_DEVICE_BLOCK = 2,
    VIRTIO_DEVICE_CONSOLE = 3,
    VIRTIO_DEVICE_ENTROPY = 4,
    VIRTIO_DEVICE_MEMORY_BALLOONING = 5,
    VIRTIO_DEVICE_IOMEM = 6,
    VIRTIO_DEVICE_RPMSG = 7,
    VIRTIO_DEVICE_SCSI = 8,
    VIRTIO_DEVICE_9P = 9,
    VIRTIO_DEVICE_WLAN = 10,
    VIRTIO_DEVICE_RPROC = 11,
    VIRTIO_DEVICE_CAIF = 12,
    VIRTIO_DEVICE_MEMORY_BALLOON = 13,
    VIRTIO_DEVICE_GPU = 16,
    VIRTIO_DEVICE_CLOCK = 17,
    VIRTIO_DEVICE_INPUT = 18,
    VIRTIO_DEVICE_SOCKET = 19,
    VIRTIO_DEVICE_CRYPTO = 20,
    VIRTIO_DEVICE_SIGNAL_DISTRIBUTION = 21,
    VIRTIO_DEVICE_PSTORE = 22,
    VIRTIO_DEVICE_IOMMU = 23,
    VIRTIO_DEVICE_MEMORY = 24,
    VIRTIO_DEVICE_AUDIO = 25,
    VIRTIO_DEVICE_FILE_SYSTEM = 26,
    VIRTIO_DEVICE_PMEM = 27,
    VIRTIO_DEVICE_RPMB = 28,
    VIRTIO_DEVICE_MAC80211_HWSIM = 29,
    VIRTIO_DEVICE_VIDEO_ENCODER = 30,
    VIRTIO_DEVICE_VIDEO_DECODER = 31,
    VIRTIO_DEVICE_SCMI = 32,
    VIRTIO_DEVICE_NITROSECURE = 33,
    VIRTIO_DEVICE_I2C = 34,
    VIRTIO_DEVICE_WATCHDOG = 35,
    VIRTIO_DEVICE_CAN = 36,
    VIRTIO_DEVICE_PARAMETER_SERVER = 38,
    VIRTIO_DEVICE_AUDIO_POLICY = 39,
    VIRTIO_DEVICE_BLUETOOTH = 40,
    VIRTIO_DEVICE_GPIO = 41,
    VIRTIO_DEVICE_RDMA = 42,
};

/// \brief VirtIO device status bits
enum virtio_status : uint32_t {
    VIRTIO_STATUS_ACKNOWLEDGE = (1 << 0), ///< Guest OS has found the device and recognized it as a valid virtio device.
    VIRTIO_STATUS_DRIVER = (1 << 1),      ///< Guest OS knows how to drive the device.
    VIRTIO_STATUS_DRIVER_OK = (1 << 2),   ///< The driver is set up and ready to drive the device.
    VIRTIO_STATUS_FEATURES_OK =
        (1 << 3), ///< The driver has acknowledged all the features it understands, and feature negotiation is complete.
    VIRTIO_STATUS_DEVICE_NEEDS_RESET = (1 << 4), ///< Device has experienced an error from which it can't recover.
    VIRTIO_STATUS_FAILED = (1 << 5), ///< Something went wrong in the guest, and it has given up on the device. This
                                     ///< could be an internal error, or the driver didn't like the device for some
                                     ///< reason, or even a fatal error during device operation.
};

/// \brief VirtIO memory mapped IO offsets
enum virtio_mmio_offsets : uint64_t {
    VIRTIO_MMIO_MAGIC_VALUE = 0x000,         ///< Magic value
    VIRTIO_MMIO_VERSION = 0x004,             ///< Device version number
    VIRTIO_MMIO_DEVICE_ID = 0x008,           ///< Virtio Subsystem Device ID
    VIRTIO_MMIO_VENDOR_ID = 0x00c,           ///< Virtio Subsystem Vendor ID
    VIRTIO_MMIO_DEVICE_FEATURES = 0x010,     ///< Flags representing features the device supports
    VIRTIO_MMIO_DEVICE_FEATURES_SEL = 0x014, ///< Device (host) features word selection.
    VIRTIO_MMIO_DRIVER_FEATURES = 0x020, ///< Flags representing device features understood and activated by the driver
    VIRTIO_MMIO_DRIVER_FEATURES_SEL = 0x024, ///< Driver (guest) features word selection
    VIRTIO_MMIO_QUEUE_SEL = 0x030,           ///< Virtual queue index
    VIRTIO_MMIO_QUEUE_NUM_MAX = 0x034,       ///< Maximum virtual queue size
    VIRTIO_MMIO_QUEUE_NUM = 0x038,           ///< Virtual queue size
    VIRTIO_MMIO_QUEUE_READY = 0x044,         ///< Virtual queue ready bit
    VIRTIO_MMIO_QUEUE_NOTIFY = 0x050,        ///< Queue notifier
    VIRTIO_MMIO_INTERRUPT_STATUS = 0x060,    ///< Interrupt status
    VIRTIO_MMIO_INTERRUPT_ACK = 0x064,       ///< Interrupt acknowledge
    VIRTIO_MMIO_STATUS = 0x070,              ///< Device status
    VIRTIO_MMIO_QUEUE_DESC_LOW = 0x080,      ///< Virtual queue descriptor area - 64 bit long physical address
    VIRTIO_MMIO_QUEUE_DESC_HIGH = 0x084,     ///< Virtual queue descriptor area - 64 bit long physical address
    VIRTIO_MMIO_QUEUE_AVAIL_LOW = 0x090,     ///< Virtual queue driver area - 64 bit long physical address
    VIRTIO_MMIO_QUEUE_AVAIL_HIGH = 0x094,    ///< Virtual queue driver area - 64 bit long physical address
    VIRTIO_MMIO_QUEUE_USED_LOW = 0x0a0,      ///< Virtual queue device area - 64 bit long physical address
    VIRTIO_MMIO_QUEUE_USED_HIGH = 0x0a4,     ///< Virtual queue device area - 64 bit long physical address
    VIRTIO_MMIO_SHM_SEL = 0x0ac,             ///< Shared memory id
    VIRTIO_MMIO_SHM_LEN_LOW = 0x0b0,         ///< Shared memory region - 64 bit long length
    VIRTIO_MMIO_SHM_LEN_HIGH = 0x0b4,        ///< Shared memory region - 64 bit long length
    VIRTIO_MMIO_SHM_BASE_LOW = 0x0b8,        ///< Shared memory region - 64 bit long physical address
    VIRTIO_MMIO_SHM_BASE_HIGH = 0x0bc,       ///< Shared memory region - 64 bit long physical address
    VIRTIO_MMIO_CONFIG_GENERATION = 0x0fc,   ///< Configuration atomicity value
    VIRTIO_MMIO_CONFIG = 0x100,              ///< Configuration space
};

/// \brief VirtIO interrupt status
enum virtio_int_status : uint32_t {
    VIRTIO_INT_STATUS_USED_BUFFER = 1 << 0,
    VIRTIO_INT_STATUS_CONFIG_CHANGE = 1 << 1,
};

/// \brief Virtqueue descriptor flags
enum virtq_desc_flags : uint16_t {
    VIRTQ_DESC_F_NEXT = 1,     ///< This marks a buffer as continuing via the next field.
    VIRTQ_DESC_F_WRITE = 2,    ///< This marks a buffer as device write-only (otherwise device read-only).
    VIRTQ_DESC_F_INDIRECT = 4, ///< This means the buffer contains a list of buffer descriptors.
};

/// \brief Virtqueue used flags
enum virtq_used_flags : uint16_t {
    VIRTQ_USED_F_NO_NOTIFY =
        1, ///< The device uses this in used flags to advise the driver: don't kick me when you add a buffer.
};

/// \brief Virtqueue avail flags
enum virtq_avail_flags : uint16_t {
    VIRTQ_AVAIL_F_NO_INTERRUPT =
        1, ///< The driver uses this in avail flags to advise the device: don't interrupt me when you consume a buffer.
};

/// \brief Virtqueue buffer descriptor
struct virtq_desc {
    uint64_t paddr; ///< Guest physical address
    uint32_t len;   ///< Guest physical length
    uint16_t flags; ///< Descriptor flags
    uint16_t next;  ///< Next field if flags & VIRTQ_DESC_F_NEXT
};

/// \brief Virtqueue used/avail header
struct virtq_header {
    uint16_t flags; ///< Used or avail flags (see virtq_used_flags or virtq_avail_flags)
    uint16_t idx;   ///< Where the driver would put the next descriptor entry in the ring (modulo the queue size)
};

/// \brief Virtqueue used element
struct virtq_used_elem {
    uint32_t id;  ///< Index of start of used descriptor chain
    uint32_t len; ///< Total length of the descriptor chain which was written to.
};

/// \brief VirtIO's split Virtqueue implementation
struct virtq {
    uint64_t desc_addr;     ///< Used for describing buffers
    uint64_t avail_addr;    ///< Data supplied by driver to the device (available ring)
    uint64_t used_addr;     ///< Data supplied by device to driver (used ring)
    uint32_t num;           ///< Maximum number of elements in the queue ring
    uint16_t last_used_idx; ///< Last used ring index, this always increment
    uint16_t ready;         ///< Whether the queue is ready

    /// \brief Gets how many bytes are available in queue read/write buffers.
    /// \param a The state accessor for the current device.
    /// \param desc_idx Index of queue's descriptor be traversed.
    /// \param pread_avail_len Receives the available length of the read buffer.
    /// \param pwrite_avail_len Receives the available length of the write buffer.
    /// \returns True if successful, false if an error happened while parsing the queue buffer.
    bool get_desc_rw_avail_len(i_device_state_access *a, uint16_t desc_idx, uint32_t *pread_avail_len,
        uint32_t *pwrite_avail_len) const;

    /// \brief Reads bytes from a queue buffer descriptor.
    /// \param a The state accessor for the current device.
    /// \param desc_idx Index of queue's descriptor be traversed.
    /// \param start_off Starting offset in the queue read buffer to be read.
    /// \param data Receives the data.
    /// \param len Amount of bytes to be read.
    /// \returns True if successful, false if an error happened while reading the queue buffer.
    bool read_desc_mem(i_device_state_access *a, uint16_t desc_idx, uint32_t start_off, unsigned char *data,
        uint32_t len) const;

    /// \brief Writes bytes to a queue buffer descriptor.
    /// \param a The state accessor for the current device.
    /// \param desc_idx Index of queue's descriptor be traversed.
    /// \param start_off Starting offset in the queue write buffer to be written.
    /// \param data Data to be written.
    /// \param len Amount of bytes to be written.
    /// \returns True if successful, false if an error happened while writing the queue buffer.
    bool write_desc_mem(i_device_state_access *a, uint16_t desc_idx, uint32_t start_off, const unsigned char *data,
        uint32_t len) const;

    /// \brief Consumes a queue buffer, marking it a used to the driver.
    /// \brief The driver will notify later when the buffer becomes available again,
    /// after it finishes processing the buffer.
    /// \param a The state accessor for the current device.
    /// \param desc_idx Index of queue's header descriptor to be consumed.
    /// \param written_len Amount of bytes written in case of write-only queues,
    /// should be 0 for read-only queues.
    /// \param flags Used flags to passed to the driver.
    /// \returns True if successful, false if an error happened.
    bool consume_desc(i_device_state_access *a, uint16_t desc_idx, uint32_t written_len, uint16_t flags);
};

/// \brief VirtIO device common interface
class virtio_device {
protected:
    uint32_t virtio_idx = 0;          ///< VirtIO device index
    uint32_t int_status = 0;          ///< Interrupt status mask (see virtio_status)
    uint32_t device_id = 0;           ///< Device id (see virtio_devices)
    uint64_t device_features = 0;     ///< Features supported by the device
    uint64_t driver_features = 0;     ///< Features supported by the driver
    uint32_t device_features_sel = 0; ///< Device features selector (high/low bits)
    uint32_t driver_features_sel = 0; ///< Driver features selector (high/low bits)
    uint32_t queue_sel = 0;           ///< Queue selector
    uint32_t shm_sel = 0;             ///< Shared memory selector
    uint32_t device_status = 0;       ///< Device status mask (see virtio_status)
    uint32_t config_generation = 0;   ///< Configuration generation counter
    uint32_t config_space_size = 0;   ///< Configuration size
    bool driver_ok = false;           ///< True when the device was successfully initialized by the driver

    // Use an array of uint32 instead of uint8, to make sure we can perform 4-byte aligned reads on config space
    std::array<uint32_t, VIRTIO_MAX_CONFIG_SPACE_SIZE / sizeof(uint32_t)> config_space{}; ///< Configuration space
    std::array<virtq, VIRTIO_QUEUE_COUNT> queue{};                                        ///< Virtqueues

public:
    explicit virtio_device(uint32_t virtio_idx, uint32_t device_id, uint64_t device_features,
        uint32_t config_space_size);
    virtio_device() = delete;
    virtual ~virtio_device() = default;
    virtio_device(const virtio_device &other) = delete;
    virtio_device(virtio_device &&other) = delete;
    virtio_device &operator=(const virtio_device &other) = delete;
    virtio_device &operator=(virtio_device &&other) = delete;

    /// \brief Reset device to uninitialize state, cleaning all its internal state.
    /// \details This is only requested by the driver when a fatal failure occurs
    /// and the driver is about to reinitialize the device.
    /// It's also request by the driver to de-initialize the device.
    void reset(i_device_state_access *a);

    /// \brief Set an interrupt request.
    /// \params add_int_status Interrupt status bits to be set.
    void set_irq(i_device_state_access *a, uint32_t add_int_status);

    /// \brief Clear interrupt requests.
    /// \params rem_int_status Interrupt status bits to be unset.
    void reset_irq(i_device_state_access *a, uint32_t rem_int_status);

    /// \brief Notify the driver that a fatal failure occurred and it should reset the device state.
    /// \details A good driver implementation will issue a reset and reinitialize the device this call.
    void notify_device_needs_reset(i_device_state_access *a);

    /// \brief Notify the driver that a queue buffer has just been used.
    void notify_queue_used(i_device_state_access *a);

    /// \brief Notify the driver that device has configuration changed.
    /// \details The driver will eventually re-read the configuration space to detect the change.
    void notify_config_change(i_device_state_access *a);

    /// \brief Prepare a queue descriptor for writing.
    /// \param queue_idx Queue index to write to.
    /// \param pdesc_idx Receives queue's available descriptor index that can be written to.
    /// \param pwrite_avail_len Receives maximum length that can be written to.
    /// \returns True if there are no errors, false otherwise.
    /// \details In case the queue is full or not ready yet, this function will still return true,
    /// however pwrite_avail_len will be set to 0.
    bool prepare_queue_write(i_device_state_access *a, uint32_t queue_idx, uint16_t *pdesc_idx,
        uint32_t *pwrite_avail_len) const;

    /// Consume an available queue's descriptor (sets it as used) and notify the driver.
    /// \param queue_idx Queue index to consume and notify.
    /// \param desc_idx Queue's available descriptor index to set as used.
    /// \param written_len Amount of bytes written to the descriptor buffer.
    /// \param used_flags Used flags, see virtq_used_flags.
    /// \returns True if there are no errors, false otherwise.
    bool consume_and_notify_queue(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t written_len = 0, uint16_t used_flags = 0);

    /// \brief Called when driver request a device reset, this function must clean-up all device internal state.
    virtual void on_device_reset() = 0;

    /// \brief Called when driver finish initializing the device.
    virtual void on_device_ok(i_device_state_access *a) = 0;

    /// \brief Process driver notification for pending available queue's descriptors.
    /// \params queue_idx Index for the queue that is has an available descriptor to be processed.
    void on_device_queue_notify(i_device_state_access *a, uint32_t queue_idx);

    /// \brief Called when driver notifies that a queue descriptor is available to be processed.
    /// \param queue_idx Queue index that has at least one available descriptor.
    /// \param desc_idx Queue's available descriptor index.
    /// \param read_avail_len Total readable length in the descriptor buffer.
    /// \param write_avail_len Total writable length in the descriptor buffer.
    virtual bool on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len) = 0;

    /// \brief Fill file descriptors to be polled by select().
    /// \param fds Pointer to sets of read, write and except file descriptors to be updated.
    /// \param timeout_us Maximum amount of time to wait, this may be updated (always to lower values).
    virtual void prepare_select(select_fd_sets *fds, uint64_t *timeout_us);

    /// \brief Poll file descriptors that were marked as ready by select().
    /// \param select_ret Return value from the most recent select() call.
    /// \param fds Pointer to sets of read, write and except file descriptors to be checked.
    /// \returns True if an interrupt was requested, false otherwise.
    /// \details This function process pending events and trigger interrupt requests (if any).
    virtual bool poll_selected(int select_ret, select_fd_sets *fds, i_device_state_access *da);

    /// \brief Poll pending events without waiting (non-blocking).
    /// \details Basically call prepare_select(), select() and poll_selected() with timeout set to 0.
    /// \returns True if an interrupt was requested, false otherwise.
    bool poll_nowait(i_device_state_access *da);

    /// \brief Reads device's shared memory base address.
    /// \returns Guest a valid physical address, or -1 in case shared memory is not supported by the device.
    virtual uint64_t read_shm_base(uint32_t shm_sel);

    /// \brief Reads device's shared memory length.
    /// \returns Length in bytes, or -1 in case shared memory is not supported by the device.
    virtual uint64_t read_shm_length(uint32_t shm_sel);

    /// \brief Reads a value from device's configuration space.
    /// \param offset Offset to be read.
    /// \param pval Receives the value.
    /// \param log2_size log2 of size of value to read.
    /// \returns True if there are no errors, false otherwise.
    bool mmio_read_config(i_device_state_access *a, uint64_t offset, uint32_t *pval, int log2_size);

    /// \brief Writes a value to device's configuration space.
    /// \param offset Offset to write to.
    /// \param val The value to write.
    /// \param log2_size log2 of size of value to write.
    /// \returns A status of the execution, execute_status::failure when there is an error.
    execute_status mmio_write_config(i_device_state_access *a, uint64_t offset, uint32_t val, int log2_size);

    /// \brief Reads a value from the device.
    /// \param offset Offset to be read.
    /// \param pval Receives the value.
    /// \param log2_size log2 of size of value to read.
    /// \returns True if there are no errors, false otherwise.
    bool mmio_read(i_device_state_access *a, uint64_t offset, uint32_t *pval, int log2_size);

    /// \brief Writes a value to the device.
    /// \param offset Offset to be written.
    /// \param val The value to be written.
    /// \param log2_size log2 of size of value to write.
    /// \returns execute::failure if operation failed, otherwise other success enumeration if operation succeeded.
    execute_status mmio_write(i_device_state_access *a, uint64_t offset, uint32_t val, int log2_size);

    /// \brief Returns the VirtIO device index for this VirtIO device.
    uint32_t get_virtio_index() const {
        return virtio_idx;
    }

    /// \brief Returns the PLIC's interrupt request number for this VirtIO device.
    uint32_t get_irq_id() const {
        return virtio_idx + 1;
    }

    /// \brief Returns the VirtIO device id.
    uint32_t get_device_id() const {
        return device_id;
    }
};

/// \brief Global VirtIO driver instance
extern const pma_driver virtio_driver;

} // namespace cartesi

#endif
