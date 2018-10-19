#ifndef PMA_H
#define PMA_H

#include <cstdint>
#include "merkle-tree.h"

// Forward definitions
class i_device_state_access;
struct machine_state;

/// \file
/// \brief Physical memory attributes

/// log<sub>2</sub> of physical memory page size.
#define PMA_PAGE_SIZE_LOG2 12
/// Physical memory page size.
#define PMA_PAGE_SIZE      (1 << PMA_PAGE_SIZE_LOG2)

/// \name PMA target flags
/// \{
#define PMA_FLAGS_M         (1u << 0) ///< Memory range
#define PMA_FLAGS_IO        (1u << 1) ///< IO mapped range
#define PMA_FLAGS_E         (1u << 2) ///< Empty range
#define PMA_FLAGS_R         (1u << 3) ///< Readable
#define PMA_FLAGS_W         (1u << 4) ///< Writable
#define PMA_FLAGS_X         (1u << 5) ///< Executable
#define PMA_FLAGS_IR        (1u << 6) ///< Idempotent reads
#define PMA_FLAGS_IW        (1u << 7) ///< Idempotent writes
/// \}

/// Mask for PMA flags
#define PMA_FLAGS_MASK      (0xff)

/// \name PMA host type
#define PMA_TYPE_MEMORY     (1u << 31) ///< Mapped to host memory
#define PMA_TYPE_DEVICE     (1u << 30) ///< Mapped to device
/// \}

/// RAM type-flags combination
#define PMA_TYPE_FLAGS_RAM  ( \
    PMA_TYPE_MEMORY | \
    PMA_FLAGS_M     | \
    PMA_FLAGS_X     | \
    PMA_FLAGS_W     | \
    PMA_FLAGS_R     | \
    PMA_FLAGS_IR    | \
    PMA_FLAGS_IW    \
)

/// Flash memory type-flags combination
#define PMA_TYPE_FLAGS_FLASH  ( \
    PMA_TYPE_MEMORY | \
    PMA_FLAGS_M     | \
    PMA_FLAGS_W     | \
    PMA_FLAGS_R     | \
    PMA_FLAGS_IR    | \
    PMA_FLAGS_IW    \
)

/// Memory mapped device type-flags combination
#define PMA_TYPE_FLAGS_MMIO       (PMA_TYPE_DEVICE | PMA_FLAGS_IO | PMA_FLAGS_W | PMA_FLAGS_R )

/// Shadow device type-flags combination
#define PMA_TYPE_FLAGS_SHADOW      (PMA_TYPE_DEVICE | PMA_FLAGS_E )

//??D Maybe change the callbacks to receive the pma_entry
//    instead of a context pointer?

/// \brief Prototype for callback invoked when machine wants
/// to read from a device.
/// \param da Object through which the machine state can be accessed by device.
/// \param context Device context (set during device initialization).
/// \param offset Offset of requested value from device base address.
/// \param val Pointer to word where value should be stored.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
typedef bool (*pma_device_read)(i_device_state_access *da, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief Prototype for callback invoked when machine wants
/// to write to a device.
/// \param da Object through which the machine state can be accessed by device.
/// \param context Device context (set during device initialization).
/// \param offset Offset of requested value from device base address.
/// \param val Word to be written at \p offset.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
typedef bool (*pma_device_write)(i_device_state_access *da, void *context, uint64_t offset, uint64_t val, int size_log2);

/// \brief Return status for device peek callback.
enum class device_peek_status {
    success, ///< Peek succeeded and returned data.
    invalid_page, ///< Page index is out of range or misaligned.
    pristine_page ///< Page is in range, but is always pristine.
};

/// \brief Prototype for callback invoked when machine wants
/// to peek into a device with no side-effects.
/// \param s Machine state for naked read-only access.
/// \param context Device context (set during device initialization).
/// \param page_index Index of page within device range. Must be aligned to PMA_PAGE_SIZE.
/// \param page_data Pointer to buffer that will receive page data. Must be able to hold PMA_PAGE_SIZE bytes.
/// \returns device_peek_status.
typedef device_peek_status (*pma_device_peek)(const machine_state *s, void *context, uint64_t page_index, uint8_t *page_data);

/// \brief Default device write callback issues error on write.
bool pma_device_write_error(i_device_state_access *, void *, uint64_t, uint64_t, int);

/// \brief Default device read callback issues error on reads.
bool pma_device_read_error(i_device_state_access *, void *, uint64_t, uint64_t *, int);

/// \brief Default device peek callback issues error on peeks.
device_peek_status pma_device_peek_error(const machine_state *, void *, uint64_t, uint8_t *);

/// \brief Data for memory ranges.
struct pma_memory {
    uint8_t *host_memory;      ///< Start of associated memory region in host.
    int backing_file;          ///< File descryptor for backed memory.
};

struct pma_device_driver {
    const char *name;         ///< Driver name.
    pma_device_read read;     ///< Callback for read operations.
    pma_device_write write;   ///< Callback for write operations.
    pma_device_peek peek;     ///< Callback for peek operations.
};

//??D change this to a class with a virtual interface.
/// \brief Data for device ranges.
struct pma_device {
    void *context;            ///< Device context set during initialization.
    const pma_device_driver *driver; ///< Device driver with callbacks.
};

/// \brief Physical Memory Attribute entry.
/// \details The target's physical memory layout is described by an
/// array of PMA entries.
struct pma_entry {
    uint64_t start;        ///< Start of physical memory range in target.
    uint64_t length;       ///< Length of physical memory range in target.
    uint32_t type_flags;   ///< Type and flags of range.
    union {
        pma_memory memory; ///< Memory-specific data.
        pma_device device; ///< Device-specific data.
    }; // anonymous union
};

/// \brief Checks if a PMA entry describes a memory range
/// \param pma Pointer to entry of interest.
static inline bool pma_is_memory(const pma_entry *pma) {
    return pma->type_flags & PMA_TYPE_MEMORY;
}

/// \brief Checks if a PMA entry describes a device range
/// \param pma Pointer to entry of interest.
static inline bool pma_is_device(const pma_entry *pma) {
    return pma->type_flags & PMA_TYPE_DEVICE;
}

/// \brief Checks if a PMA entry is RAM
/// \param pma Pointer to entry of interest.
static inline bool pma_is_ram(const pma_entry *pma) {
    return pma->type_flags == PMA_TYPE_FLAGS_RAM;
}

/// \brief Checks if a PMA entry is a flash drive
/// \param pma Pointer to entry of interest.
static inline bool pma_is_flash(const pma_entry *pma) {
    return pma->type_flags == PMA_TYPE_FLAGS_FLASH;
}

/// \brief Checks if a PMA entry is a memory-mapped IO device
/// \param pma Pointer to entry of interest.
static inline bool pma_is_mmio(const pma_entry *pma) {
    return pma->type_flags == PMA_TYPE_FLAGS_MMIO;
}

/// \brief Checks if a PMA entry is a shadow device.
/// \param pma Pointer to entry of interest.
static inline bool pma_is_shadow(const pma_entry *pma) {
    return pma->type_flags == PMA_TYPE_FLAGS_SHADOW;
}

/// \brief Encodes PMA istart as per whitepaper
static inline uint64_t pma_get_istart(const pma_entry *pma) {
    return pma->start | (pma->type_flags & PMA_FLAGS_MASK);
}

/// \brief Encodes PMA ilength as per whitepaper
static inline uint64_t pma_get_ilength(const pma_entry *pma) {
    return pma->length;
}

#endif
