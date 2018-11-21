#ifndef PMA_H
#define PMA_H

#include <cstdint>
#include <boost/container/static_vector.hpp>

#include "merkle-tree.h"

// Forward definitions
class i_virtual_state_access;
struct pma_entry;

/// \file
/// \brief Physical memory attributes

/// log<sub>2</sub> of physical memory page size.
#define PMA_PAGE_SIZE_LOG2 12
/// Physical memory page size.
#define PMA_PAGE_SIZE       (UINT64_C(1) << PMA_PAGE_SIZE_LOG2)
/// Physical memory word size.
#define PMA_WORD_SIZE       UINT64_C(8)

/// \name PMA target flags
/// \{
#define PMA_FLAGS_M         (UINT64_C(1) << 0) ///< Memory range
#define PMA_FLAGS_IO        (UINT64_C(1) << 1) ///< IO mapped range
#define PMA_FLAGS_E         (UINT64_C(1) << 2) ///< Empty range
#define PMA_FLAGS_R         (UINT64_C(1) << 3) ///< Readable
#define PMA_FLAGS_W         (UINT64_C(1) << 4) ///< Writable
#define PMA_FLAGS_X         (UINT64_C(1) << 5) ///< Executable
#define PMA_FLAGS_IR        (UINT64_C(1) << 6) ///< Idempotent reads
#define PMA_FLAGS_IW        (UINT64_C(1) << 7) ///< Idempotent writes
/// \}

/// Mask for PMA flags
#define PMA_FLAGS_MASK      UINT64_C(1)

/// \name PMA host type
#define PMA_TYPE_MEMORY     (UINT64_C(1) << 31) ///< Mapped to host memory
#define PMA_TYPE_DEVICE     (UINT64_C(1) << 30) ///< Mapped to device
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

/// \brief Prototype for callback invoked when machine wants to read from a range.
/// \param pma Pointer to corresponding PMA entry.
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Pointer to word where value will be stored.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_read)(const pma_entry *pma, i_virtual_state_access *da, uint64_t offset, uint64_t *val, int size_log2);

/// \brief Default read callback issues error on reads.
bool pma_read_error(const pma_entry *, i_virtual_state_access *, uint64_t, uint64_t *, int);

/// \brief Prototype for callback invoked when machine wants to write to a range.
/// \param pma Pointer to corresponding PMA entry.
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Word to be written at \p offset.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_write)(const pma_entry *pma, i_virtual_state_access *da, uint64_t offset, uint64_t val, int size_log2);

/// \brief Default write callback issues error on write.
bool pma_write_error(const pma_entry *, i_virtual_state_access *, uint64_t, uint64_t, int);

/// \brief Prototype for callback invoked when machine wants to peek into a range with no side-effects.
/// \param pma Pointer to corresponding PMA entry.
/// \param page_offset Offset of page start within range. Must be aligned to PMA_PAGE_SIZE.
/// \param page_data Receives pointer to start of page data, or nullptr if page is constant *and* pristine.
/// \param scratch Pointer to memory buffer that must be able to hold PMA_PAGE_SIZE bytes.
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_peek)(const pma_entry *, uint64_t page_offset, const uint8_t **page_data, uint8_t *scratch);

/// \brief Default peek callback issues error on peeks.
bool pma_peek_error(const pma_entry *, uint64_t, const uint8_t **, uint8_t *);

/// \brief Driver for range.
struct pma_driver {
    const char *name;         ///< Driver name.
    pma_read read;            ///< Callback for read operations.
    pma_write write;          ///< Callback for write operations.
    pma_peek peek;            ///< Callback for peek operations.
};

// For performance reasons, we can't possibly invoke a
// function every time we want to read from a memory
// range, so memory ranges do not use a driver like
// device ranges do.

/// \brief Data for memory ranges.
struct pma_memory {
    uint8_t *host_memory;      ///< Start of associated memory region in host.
    int backing_file;          ///< File descryptor for backed memory.
};

/// \brief Physical Memory Attribute entry.
/// \details The target's physical memory layout is described by an
/// array of PMA entries.
struct pma_entry {
    uint64_t start;           ///< Start of physical memory range in target.
    uint64_t length;          ///< Length of physical memory range in target.
    uint32_t type_flags;      ///< Type and flags of range.
    pma_memory memory;        ///< Memory-specific data (devices need no additional data).
    void *context;            ///< Context set during initialization.
    const pma_driver *driver; ///< Driver with callbacks for range.
};

#define PMA_SIZE 32 ///< Maximum number of PMAs
using pma_entries = boost::container::static_vector<pma_entry, PMA_SIZE>;

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

/// \brief Encodes PMA encoded start field as per whitepaper
static inline uint64_t pma_get_istart(const pma_entry &pma) {
    return (pma.start & ~PMA_FLAGS_MASK) | (pma.type_flags & PMA_FLAGS_MASK);
}

/// \brief Encodes PMA encoded length field as per whitepaper
static inline uint64_t pma_get_ilength(const pma_entry &pma) {
    return pma.length;
}

/// \brief Returns context associated to PMA entry
static inline void *pma_get_context(pma_entry *pma) {
    return pma->context;
}

static inline void *pma_get_context(const pma_entry *pma) {
    return const_cast<void *>(pma->context);
}

#endif
