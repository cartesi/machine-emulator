#ifndef PMA_H
#define PMA_H

#include <cstdint>
#include <vector>
#include <variant>

namespace cartesi {

// Forward declarations
class pma_entry;
class i_virtual_state_access;

/// \file
/// \brief Physical memory attributes.

/// \brief Fixed PMA ranges.
enum PMA_ranges: uint64_t {
    PMA_SHADOW_START  = UINT64_C(0),           ///< Start of shadow range
    PMA_SHADOW_LENGTH = UINT64_C(0x1000),      ///< Length of shadow range
    PMA_ROM_START     = UINT64_C(0x1000),      ///< Start of ROM range
    PMA_ROM_LENGTH    = UINT64_C(0xF000),      ///< Length of ROM range
    PMA_CLINT_START   = UINT64_C(0x2000000),   ///< Start of CLINT range
    PMA_CLINT_LENGTH  = UINT64_C(0xC0000),     ///< Length of CLINT range
    PMA_HTIF_START    = UINT64_C(0x40008000),  ///< Start of HTIF range
    PMA_HTIF_LENGTH   = UINT64_C(0x1000),      ///< Length of HTIF range
    PMA_RAM_START     = UINT64_C(0x80000000),  ///< Start of RAM range
};

/// \brief PMA constants.
enum PMA_constants: uint64_t {
    PMA_PAGE_SIZE_LOG2 = 12, ///< log<sub>2</sub> of physical memory page size.
    PMA_PAGE_SIZE      = (UINT64_C(1) << PMA_PAGE_SIZE_LOG2), ///< Physical memory page size.
    PMA_WORD_SIZE      = UINT64_C(8), ///< Physical memory word size.
    PMA_MAX            = UINT64_C(32) ///< Maximum number of PMAs
};

/// \brief PMA istart shifts
enum PMA_ISTART_shifts {
    PMA_ISTART_M_SHIFT  = 0,
    PMA_ISTART_IO_SHIFT = 1,
    PMA_ISTART_E_SHIFT  = 2,
    PMA_ISTART_R_SHIFT  = 3,
    PMA_ISTART_W_SHIFT  = 4,
    PMA_ISTART_X_SHIFT  = 5,
    PMA_ISTART_IR_SHIFT = 6,
    PMA_ISTART_IW_SHIFT = 7,
    PMA_ISTART_DID_SHIFT = 8,
};

/// \brief PMA istart masks
enum PMA_ISTART_masks: uint64_t {
    PMA_ISTART_M_MASK   = UINT64_C(1)  << PMA_ISTART_M_SHIFT,  ///< Memory range
    PMA_ISTART_IO_MASK  = UINT64_C(1)  << PMA_ISTART_IO_SHIFT, ///< Device range
    PMA_ISTART_E_MASK   = UINT64_C(1)  << PMA_ISTART_E_SHIFT,  ///< Empty range
    PMA_ISTART_R_MASK   = UINT64_C(1)  << PMA_ISTART_R_SHIFT,  ///< Readable
    PMA_ISTART_W_MASK   = UINT64_C(1)  << PMA_ISTART_W_SHIFT,  ///< Writable
    PMA_ISTART_X_MASK   = UINT64_C(1)  << PMA_ISTART_X_SHIFT,  ///< Executable
    PMA_ISTART_IR_MASK  = UINT64_C(1)  << PMA_ISTART_IR_SHIFT, ///< Idempotent reads
    PMA_ISTART_IW_MASK  = UINT64_C(1)  << PMA_ISTART_IW_SHIFT, ///< Idempotent writes
    PMA_ISTART_DID_MASK = UINT64_C(15) << PMA_ISTART_DID_SHIFT ///< Device id
};

/// \brief PMA device ids
enum class PMA_ISTART_DID {
    memory = 0, ///< DID for memory
    shadow = 1, ///< DID for shadow device
    CLINT  = 2, ///< DID for CLINT device
    HTIF   = 3  ///< DID for HTIF device
};

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

/// \brief Driver for device ranges.
struct pma_driver final {
    const char *name{""};             ///< Driver name.
    pma_read read{pma_read_error};    ///< Callback for read operations.
    pma_write write{pma_write_error}; ///< Callback for write operations.
};

/// \brief Data for IO ranges.
class pma_device final {

    void *m_context;             ///< Context to pass to callbacks.
    const pma_driver *m_driver;  ///< Driver with callbacks.

public:
    /// \brief Constructor from entries.
    /// \param context Context to pass to callbacks.
    /// \param driver Driver with callbacks.
    pma_device(void *context, const pma_driver *driver):
        m_context{context},
        m_driver{driver} {
        ;
    }

    /// \brief Returns context to pass to callbacks.
    void *get_context(void) {
        return m_context;
    }

    /// \brief Returns context to pass to callbacks.
    void *get_context(void) const {
        // Discard qualifier on purpose because the context
        // is none of our business.
        return const_cast<void *>(m_context);
    }

    /// \brief Returns driver with callbacks
    const pma_driver *get_driver(void) const {
        return m_driver;
    }
};

// For performance reasons, we can't possibly invoke a
// function every time we want to read from a memory
// range, so memory ranges do not use a driver like
// IO ranges do. So we use naked pointers to host memory.

/// \brief Data for memory ranges.
class pma_memory final {

    uint64_t m_length;             ///< Length of memory range (copy of PMA length field).
    uint8_t *m_host_memory;        ///< Start of associated memory region in host.
    int m_backing_file;            ///< File descryptor for mmaped memory.

public:

    /// \brief Mmap'd range data (shared or not).
    struct mmapd {
        bool shared;
    };

    /// \brief Constructor for mmap'd ranges.
    /// \param length of range.
    /// \param path Path for backing file.
    /// \param m Mmap'd range data (shared or not).
    pma_memory(uint64_t length, const std::string &path, const mmapd &m);

    /// \brief Calloc'd range data (just a tag).
    struct callocd {
    };

    /// \brief Constructor for calloc'd ranges.
    /// \param length of range.
    /// \param path Path for backing file.
    /// \param c Calloc'd range data (just a tag).
    pma_memory(uint64_t length, const std::string &path, const callocd &c);

    /// \brief Constructor for calloc'd ranges.
    /// \param length of range.
    /// \param c Calloc'd range data (just a tag).
    pma_memory(uint64_t length, const callocd &c);

    /// \brief No copy constructor
    pma_memory(const pma_memory &) = delete;

    /// \brief No copy assignment
    pma_memory &operator=(const pma_memory &) = delete;

    /// \brief Move assignment
    pma_memory(pma_memory &&);

    /// \brief Move constructor
    pma_memory &operator=(pma_memory &&);

    /// \brief Destructor
    ~pma_memory(void);

    /// \brief Returns start of associated memory region in host
    uint8_t *get_host_memory(void) {
        return m_host_memory;
    }

    /// \brief Returns start of associated memory region in host
    const uint8_t *get_host_memory(void) const {
        return m_host_memory;
    }

    /// \brief Returns file descryptor for mmaped memory.
    int get_backing_file(void) const {
        return m_backing_file;
    }

    /// \brief Returns copy of PMA length field (needed for munmap).
    int get_length(void) const {
        return m_length;
    }

};

/// \brief Data for empty memory ranges (nothing, really)
struct pma_empty final {
};

/// \brief Physical Memory Attribute entry.
/// \details The target's physical memory layout is described by an
/// array of PMA entries.
class pma_entry final {
public:

    ///< Exploded flags for PMA entry.
    struct flags {
        // bool M = std::holds_alternative<pma_memory>(data);
        // bool IO = std::holds_alternative<pma_device>(data);
        // bool E = std::holds_alternative<pma_empty>(data);
        bool R;
        bool W;
        bool X;
        bool IR;
        bool IW;
        PMA_ISTART_DID DID;
    };

private:

    uint64_t m_start;   ///< Start of physical memory range in target.
    uint64_t m_length;  ///< Length of physical memory range in target.
    flags m_flags;      ///< PMA Flags

    pma_peek m_peek;    ///< Callback for peek operations.

    std::vector<uint8_t> m_dirty_page_map;  ///< Map of dirty pages.

    std::variant<
        pma_empty,      ///< Data specific to E ranges
        pma_device,     ///< Data specific to IO ranges
        pma_memory      ///< Data specific to M ranges
    > m_data;

public:
    /// \brief No copy constructor
    pma_entry(const pma_entry &) = delete;
    /// \brief No copy assignment
    pma_entry &operator=(const pma_entry &) = delete;
    /// \brief Default move constructor
    pma_entry(pma_entry &&) = default;
    /// \brief Default move assignment
    pma_entry &operator=(pma_entry &&) = default;

    /// \brief Constructor for empty entry
    pma_entry(uint64_t start, uint64_t length):
        m_start{start},
        m_length{length},
        m_flags{},
        m_peek{pma_peek_error},
        m_data{pma_empty{}} {
        ;
    }

    /// \brief Default constructor creates an empty entry
    /// spanning an empty range
    pma_entry(void): pma_entry(0, 0) { ; }

    /// \brief Constructor for memory entry
    explicit pma_entry(uint64_t start, uint64_t length, pma_memory &&memory,
        pma_peek peek = pma_peek_error):
        m_start{start},
        m_length{length},
        m_flags{},
        m_peek{peek},
        m_data{std::move(memory)} {
            // allocate dirty page map and mark all pages as dirty
            m_dirty_page_map.resize(length/(8*PMA_PAGE_SIZE)+1, 0xff);
        }

    /// \brief Constructor for device entry
    explicit pma_entry(uint64_t start, uint64_t length, pma_device &&device,
        pma_peek peek = pma_peek_error):
        m_start{start},
        m_length{length},
        m_flags{},
        m_peek{peek},
        m_data{std::move(device)} { ; }

    /// \brief Set flags for lvalue references
    /// \params f New flags.
    pma_entry &set_flags(flags f) & {
        m_flags = f;
        return *this;
    }

    /// \brief Set flags for rvalue references
    /// \params f New flags.
    pma_entry &&set_flags(flags f) && {
        m_flags = f;
        return std::move(*this);
    }

    /// \brief Returns the peek callback for the range.
    pma_peek get_peek(void) const {
        return m_peek;
    }

    /// \Returns data specific to E ranges
    const pma_empty &get_empty(void) const {
        return std::get<pma_empty>(m_data);
    }

    /// \Returns data specific to E ranges
    pma_empty &get_empty(void) {
        return std::get<pma_empty>(m_data);
    }

    /// \Returns data specific to M ranges
    const pma_memory &get_memory(void) const {
        return std::get<pma_memory>(m_data);
    }

    /// \Returns data specific to M ranges
    pma_memory &get_memory(void) {
        return std::get<pma_memory>(m_data);
    }

    /// \Returns data specific to IO ranges
    const pma_device &get_device(void) const {
        return std::get<pma_device>(m_data);
    }

    /// \Returns data specific to IO ranges
    pma_device &get_device(void) {
        return std::get<pma_device>(m_data);
    }

    /// \brief Returns packed PMA istart field as per whitepaper
    uint64_t get_istart(void) const;

    /// \brief Returns start of physical memory range in target.
    uint64_t get_start(void) const {
        return m_start;
    }
    /// \brief Returns length of physical memory range in target.
    uint64_t get_length(void) const {
        return m_length;
    }

    /// \brief Returns encoded PMA ilength field as per whitepaper
    uint64_t get_ilength(void) const;

    /// \brief Tells if PMA is a memory range
    bool get_istart_M(void) const {
        return std::holds_alternative<pma_memory>(m_data);
    }

    /// \brief Tells if PMA is a device range
    bool get_istart_IO(void) const {
        return std::holds_alternative<pma_device>(m_data);
    }

    /// \brief Tells if PMA is an empty range
    bool get_istart_E(void) const {
        return std::holds_alternative<pma_empty>(m_data);
    }

    /// \brief Tells if PMA range is readable
    bool get_istart_R(void) const {
        return m_flags.R;
    }

    /// \brief Tells if PMA range is writable
    bool get_istart_W(void) const {
        return m_flags.W;
    }

    /// \brief Tells if PMA range is executable
    bool get_istart_X(void) const {
        return m_flags.X;
    }

    /// \brief Tells if reads to PMA range are idempotent
    bool get_istart_IR(void) const {
        return m_flags.IR;
    }

    /// \brief Tells if writes to PMA range are idempotent
    bool get_istart_IW(void) const {
        return m_flags.IW;
    }

    /// \brief Returns the id of the device that owns the range
    PMA_ISTART_DID get_istart_DID(void) const {
        return m_flags.DID;
    }

    /// \brief Mark a given page as dirty
    /// \param address_in_range Any address within page in range
    void mark_dirty_page(uint64_t address_in_range) {
        if (!m_dirty_page_map.empty()) {
            auto page_number = address_in_range >> PMA_constants::PMA_PAGE_SIZE_LOG2;
            m_dirty_page_map.at(page_number >> 3) |= (1 << (page_number & 7));
        }
    }

    /// \brief Mark a given page as clean
    /// \param address_in_range Any address within page in range
    void mark_clean_page(uint64_t address_in_range) {
        if (!m_dirty_page_map.empty()) {
            auto page_number = address_in_range >> PMA_constants::PMA_PAGE_SIZE_LOG2;
            m_dirty_page_map.at(page_number >> 3) &= ~(1 << (page_number & 7));
        }
    }

    /// \brief Checks if a given page is marked dirty
    /// \param address_in_range Any address within page in range
    /// \regurns true if dirty, false if clean
    bool is_page_marked_dirty(uint64_t address_in_range) const {
        if (!m_dirty_page_map.empty()) {
            auto page_number = address_in_range >> PMA_constants::PMA_PAGE_SIZE_LOG2;
            return m_dirty_page_map.at(page_number >> 3) & (1 << (page_number & 7));
        } else return true;
    }

    /// \brief Marks all pages in range as clean
    void mark_pages_clean(void) {
        return std::fill(m_dirty_page_map.begin(), m_dirty_page_map.end(), 0);
    }

};

} // namespace

#endif
