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

/// \name PMA istart flags
/// \{
#define PMA_ISTART_M_SHIFT   (0) ///< Memory range
#define PMA_ISTART_IO_SHIFT  (1) ///< IO mapped range
#define PMA_ISTART_E_SHIFT   (2) ///< Empty range
#define PMA_ISTART_R_SHIFT   (3) ///< Readable
#define PMA_ISTART_W_SHIFT   (4) ///< Writable
#define PMA_ISTART_X_SHIFT   (5) ///< Executable
#define PMA_ISTART_IR_SHIFT  (6) ///< Idempotent reads
#define PMA_ISTART_IW_SHIFT  (7) ///< Idempotent writes
/// \}


/// \brief Prototype for callback invoked when machine wants to peek into a range with no side-effects.
/// \param pma Pointer to corresponding PMA entry.
/// \param page_offset Offset of page start within range. Must be aligned to PMA_PAGE_SIZE.
/// \param page_data Receives pointer to start of page data, or nullptr if page is constant *and* pristine.
/// \param scratch Pointer to memory buffer that must be able to hold PMA_PAGE_SIZE bytes.
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_peek)(const pma_entry &, uint64_t page_offset, const uint8_t **page_data, uint8_t *scratch);

/// \brief Default peek callback issues error on peeks.
bool pma_peek_error(const pma_entry &, uint64_t, const uint8_t **, uint8_t *);

/// \brief Prototype for callback invoked when machine wants to read from a range.
/// \param pma Pointer to corresponding PMA entry.
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Pointer to word where value will be stored.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_read)(const pma_entry &pma, i_virtual_state_access *da, uint64_t offset, uint64_t *val, int size_log2);

/// \brief Default read callback issues error on reads.
bool pma_read_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t *, int);

/// \brief Prototype for callback invoked when machine wants to write to a range.
/// \param pma Pointer to corresponding PMA entry.
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Word to be written at \p offset.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns True if operation succeeded, false otherwise.
typedef bool (*pma_write)(const pma_entry &pma, i_virtual_state_access *da, uint64_t offset, uint64_t val, int size_log2);

/// \brief Default write callback issues error on write.
bool pma_write_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t, int);

/// \brief Driver for range.
struct pma_driver {
    const char *name;         ///< Driver name.
    pma_read read;            ///< Callback for read operations.
    pma_write write;          ///< Callback for write operations.
};

/// \brief Data for IO ranges.
struct pma_device {
    void *context;             ///< Context set during initialization.
    const pma_driver *driver;  ///< Driver with callbacks.
};

// For performance reasons, we can't possibly invoke a
// function every time we want to read from a memory
// range, so memory ranges do not use a driver like
// IO ranges do. So we use naked pointers to host memory.

/// \brief Data for memory ranges.
struct pma_memory {
    uint8_t *host_memory;      ///< Start of associated memory region in host.
    int backing_file;          ///< File descryptor for backed memory.
    uint64_t length;           ///< Copy of PMA length field
};

/// \brief Data for empty memory ranges
struct pma_empty {
};

/// \brief Physical Memory Attribute entry.
/// \details The target's physical memory layout is described by an
/// array of PMA entries.
struct pma_entry {
    uint64_t start;           ///< Start of physical memory range in target.
    uint64_t length;          ///< Length of physical memory range in target.
    struct flags {
        bool M;
        bool IO;
        bool E;
        bool R;
        bool W;
        bool X;
        bool IR;
        bool IW;
    } istart;                  ///< Exploded flags for PMA entry.
    pma_peek peek;             ///< Callback for peek operations.
    union {
        pma_memory M;          ///< Data specific to M ranges
        pma_device IO;         ///< Data specific to IO ranges
        pma_empty E;           ///< Data specific to E ranges
    } data;
};

#define PMA_MAX 32 ///< Maximum number of PMAs
using pma_entries = boost::container::static_vector<pma_entry, PMA_MAX>;

/// \brief Encodes PMA encoded start field as per whitepaper
static inline uint64_t pma_get_istart(const pma_entry &pma) {
    uint64_t istart = pma.start;
    istart |= (static_cast<uint64_t>(pma.istart.M) << PMA_ISTART_M_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.IO) << PMA_ISTART_IO_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.E) << PMA_ISTART_E_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.R) << PMA_ISTART_R_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.W) << PMA_ISTART_W_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.X) << PMA_ISTART_X_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.IR) << PMA_ISTART_IR_SHIFT);
    istart |= (static_cast<uint64_t>(pma.istart.IW) << PMA_ISTART_IW_SHIFT);
    return istart;
}

/// \brief Encodes PMA encoded length field as per whitepaper
static inline uint64_t pma_get_ilength(const pma_entry &pma) {
    return pma.length;
}

/// \brief Returns context associated to PMA entry
static inline void *pma_get_context(pma_entry &pma) {
    return pma.data.IO.context;
}

static inline void *pma_get_context(const pma_entry &pma) {
    return const_cast<void *>(pma.data.IO.context);
}

#endif
