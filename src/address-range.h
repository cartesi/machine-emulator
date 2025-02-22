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

#ifndef ADDRESS_RANGE_H
#define ADDRESS_RANGE_H

#include <array>
#include <bit>
#include <cinttypes>
#include <cstdint>
#include <tuple>

#include "assert-printf.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "pma.h"

namespace cartesi {

// Forward declarations
class machine;

/// \file
/// \brief Physical address range

/// \brief Physical Address Range.
/// \details The target's physical address layout is described by an array of specializations of such ranges.
class address_range {

    std::array<char, 32> m_description; ///< Description of address range for use in error messages.
    uint64_t m_start;                   ///< Target physical address where range starts.
    uint64_t m_length;                  ///< Length of range, in bytes.
    uint64_t m_length_bit_ceil;         ///< Smallest power of 2 that is not smaller than length, in bytes.
    pma_flags m_flags;                  ///< Physical memory attribute flags for range.

public:
    /// \brief Noexcept constexpr constructor for empty ranges with description
    /// \detail Can be used to initialize a constexpr empty range
    template <size_t N>
    explicit constexpr address_range(const char (&description)[N]) noexcept :
        m_description{},
        m_start{0},
        m_length{0},
        m_length_bit_ceil{0},
        m_flags{} {
        m_flags.E = true;
        for (unsigned i = 0; i < std::min<unsigned>(N, m_description.size() - 1); ++i) {
            m_description[i] = description[i];
        }
    }

    address_range(const address_range &other) = default;
    address_range &operator=(const address_range &other) = default;
    address_range(address_range &&other) = default;
    address_range &operator=(address_range &&other) = default;
    constexpr virtual ~address_range() {}; // = default; // doesn't work due to bug in gcc

    template <typename ABRT, size_t N, typename... ARGS>
    [[noreturn]] static void ABRTF(ABRT abrt, const char (&fmt)[N], ARGS... args) {
        char buf[256]{};
        std::ignore = snprintf(buf, std::size(buf), fmt, args...);
        abrt(buf);
        __builtin_trap();
    }

    /// \brief Constructor
    /// \tparam ABRT type of function used to abort and report errors
    /// \param description Description of address range for use in error messages (will be copied)
    /// \param start Target physical address where range starts
    /// \param length Length of range, in bytes
    /// \param f Phyical memory attribute flags for range
    template <typename ABRT>
    address_range(const char *description, uint64_t start, uint64_t length, const pma_flags &flags, ABRT abrt) :
        m_description{},
        m_start{start},
        m_length{length},
        m_length_bit_ceil{(length >> 63) == 0 ? std::bit_ceil(length) : 0},
        m_flags{flags} {
        // Non-empty description is mandatory
        if (description == nullptr || *description == '\0') {
            ABRTF(abrt, "address range 0x%" PRIx64 ":0x%" PRIx64 " has empty description", m_start, m_length);
        }
        for (unsigned i = 0; i < m_description.size() - 1 && description[i] != '\0'; ++i) {
            m_description[i] = description[i];
        }
        // All address ranges must be page-aligned
        if ((m_length & ~PMA_ISTART_START_MASK) != 0) {
            ABRTF(abrt, "length must be multiple of page size when initializing %s", m_description);
        }
        if ((m_start & ~PMA_ISTART_START_MASK) != 0) {
            ABRTF(abrt, "start of %s (0x%" PRIx64 ") must be aligned to page boundary of %d bytes", m_description,
                start, PMA_PAGE_SIZE);
        }
        // It must be possible to round length up to the next power of two
        if (m_length_bit_ceil == 0) {
            ABRTF(abrt, "range too long when initializing %s", m_description);
        }
        // Empty range must really be empty
        if (m_length == 0) {
            if (m_start != 0) {
                ABRTF(abrt, "range with length 0 must start at 0 when initializing %s", m_description);
            }
            if (!m_flags.E) {
                ABRTF(abrt, "range with length 0 must be flagged empty when initializing %s", m_description);
            }
            if (m_flags.M) {
                ABRTF(abrt, "memory range cannot be empty when initializing %s", m_description);
            }
            if (m_flags.IO) {
                ABRTF(abrt, "device range cannot be empty when initializing %s", m_description);
            }
        }
        // Non-empty range must either be memory or device
        if (static_cast<int>(m_flags.M) + static_cast<int>(m_flags.IO) + static_cast<int>(m_flags.E) != 1) {
            ABRTF(abrt, "range must be one of empty, memory, or device when initializing %s", m_description);
        }
    }

    /// \brief Checks if a range of addresses is entirely contained within this range
    /// \param offset Start of range of interest, relative to start of this range
    /// \param length Length of range of interest, in bytes
    /// \returns True if and only if range of interest is entirely contained within this range
    bool contains_relative(uint64_t offset, uint64_t length) const noexcept {
        return get_length() >= length && offset <= get_length() - length;
    }

    /// \brief Checks if a range of addresses is entirely contained within this range
    /// \param start Target phyisical address of start of range of interest
    /// \param length Length of range of interest, in bytes
    /// \returns True if and only if range of interest is entirely contained within this range
    bool contains_absolute(uint64_t start, uint64_t length) const noexcept {
        return start >= get_start() && contains_relative(start - get_start(), length);
    }

    /// \brief Returns PMA flags used during construction
    /// \returns Flags
    const pma_flags &get_flags() const noexcept {
        return m_flags;
    }

    /// \brief Returns description of address range for use in error messages.
    /// \returns Description
    const char *get_description() const noexcept {
        return m_description.data();
    }

    /// \brief Returns target physical address where range starts.
    /// \returns Start of range
    uint64_t get_start() const noexcept {
        return m_start;
    }

    /// \brief Returns length of range, in bytes.
    /// \returns Length of range
    uint64_t get_length() const noexcept {
        return m_length;
    }

    /// \brief Returns smallest power of 2 that is not smaller than range length, in bytes
    /// \returns Bit-ceil of length of range
    uint64_t get_length_bit_ceil() const noexcept {
        return m_length_bit_ceil;
    }

    /// \brief Test if address range is occupied by memory
    /// \returns True if and only if range is occupied by memory
    bool is_memory() const noexcept {
        return m_flags.M;
    }

    /// \brief Test if address range is occupied by a device
    /// \returns True if and only if range is occupied by a device
    bool is_device() const noexcept {
        return m_flags.IO;
    }

    /// \brief Test if address range is empty
    /// \returns True if and only if range is empty
    bool is_empty() const noexcept {
        return m_flags.E;
    }

    /// \brief Tests if range is readable
    /// \returns True if and only if range is readable
    bool is_readable() const noexcept {
        return m_flags.R;
    }

    /// \brief Tests if range is writeable
    /// \returns True if and only if range is writeable
    bool is_writeable() const noexcept {
        return m_flags.W;
    }

    /// \brief Tests if range is executable
    /// \returns True if and only if range is executable
    bool is_executable() const noexcept {
        return m_flags.X;
    }

    /// \brief Tests if range is read-idempotent
    /// \returns True if and only if what is read from range remains there until written to
    bool is_read_idempotent() const noexcept {
        return m_flags.IR;
    }

    /// \brief Tests if range is write-idempotent
    /// \returns True if and only if what is written to range remains there and can be read until written to again
    bool is_write_idempotent() const noexcept {
        return m_flags.IW;
    }

    /// \brief Returns driver ID associated to range
    /// \returns Teh driver ID
    PMA_ISTART_DID get_driver_id() const noexcept {
        return m_flags.DID;
    }

    /// \brief Returns packed address range istart field as per whitepaper
    /// \returns Packed address range istart
    uint64_t get_istart() const noexcept {
        return pack_pma_istart(m_flags, m_start);
    }

    /// \brief Returns encoded addres range ilength field as per whitepaper
    /// \returns Packed address range ilength
    /// \details This currently contains only the length itself
    uint64_t get_ilength() const noexcept {
        return get_length();
    }

    /// \brief Read contents from address range with, no side-effects.
    /// \param m Reference to machine.
    /// \param offset Offset within range to start reading.
    /// \param length Number of bytes to read.
    /// \param data Receives pointer to start of data, or nullptr if data is constant *and* pristine (filled with
    /// zeros).
    /// \param scratch Pointer to memory buffer that must be able to hold \p length bytes.
    /// \returns True if operation succeeded, false otherwise.
    bool peek(const machine &m, uint64_t offset, uint64_t length, const unsigned char **data,
        unsigned char *scratch) const noexcept {
        return do_peek(m, offset, length, data, scratch);
    };

    // -----
    // These are only for device ranges
    // -----

    /// \brief Reads a word from a device
    /// \param da State access object through which the machine state can be accessed.
    /// \param offset Where to start reading, relative to start of this range.
    /// \param log2_size Log<sub>2</sub> of size of value to read (0=uint8_t, 1=uint16_t, 2=uint32_t, 3=uint64_t).
    /// \param pval Pointer to word where value will be stored.
    /// \returns True if operation succeeded, false otherwise.
    bool read_device(i_device_state_access *da, uint64_t offset, int log2_size, uint64_t *pval) const noexcept {
        return do_read_device(da, offset, log2_size, pval);
    }

    /// \brief Writes a word to a device
    /// \param da State access object through which the machine state can be accessed.
    /// \param offset Where to start reading, relative to start of this range.
    /// \param log2_size Log<sub>2</sub> of size of value to write (0=uint8_t, 1=uint16_t, 2=uint32_t, 3=uint64_t).
    /// \param val Value to write.
    /// \returns execute::failure if operation failed, otherwise a success code if operation succeeded.
    execute_status write_device(i_device_state_access *da, uint64_t offset, int log2_size, uint64_t val) noexcept {
        return do_write_device(da, offset, log2_size, val);
    }

    // -----
    // These are only for memory ranges
    // -----

    /// \brief Returns start of associated memory region in host
    /// \returns Pointer to memory
    const unsigned char *get_host_memory() const noexcept {
        return do_get_host_memory();
    }

    /// \brief Returns start of associated memory region in host
    /// \returns Pointer to memory
    unsigned char *get_host_memory() noexcept {
        return do_get_host_memory();
    }

    /// \brief Mark a given page as dirty
    /// \param offset Any offset in range within desired page
    void mark_dirty_page(uint64_t offset) noexcept {
        do_mark_dirty_page(offset);
    }

    /// \brief Mark all pages in a range of interest as dirty
    /// \param offset Start of range of interest, relative to start of this range
    /// \param length Length of range of interest, in bytes
    void mark_dirty_pages(uint64_t offset, uint64_t length) noexcept {
        auto offset_aligned = offset &= ~(PMA_PAGE_SIZE - 1);
        const auto length_aligned = length + (offset - offset_aligned);
        for (; offset_aligned < length_aligned; offset_aligned += PMA_PAGE_SIZE) {
            mark_dirty_page(offset_aligned);
        }
    }

    /// \brief Mark a given page as clean
    /// \param offset Any offset in range within desired page
    void mark_clean_page(uint64_t offset) noexcept {
        do_mark_clean_page(offset);
    }

    /// \brief Marks all pages in range as clean
    void mark_pages_clean() noexcept {
        do_mark_pages_clean();
    }

    /// \brief Tests if a given page is dirty
    /// \param offset Any offset in range within desired page
    /// \returns True if and only if page is marked dirty
    bool is_page_marked_dirty(uint64_t offset) const noexcept {
        return do_is_page_marked_dirty(offset);
    }

private:
    // Default implementation of peek() always fails
    virtual bool do_peek(const machine & /*m*/, uint64_t /*offset*/, uint64_t /*length*/,
        const unsigned char ** /*data*/, unsigned char * /*scratch*/) const noexcept {
        return false;
    }

    // Default implementation of read_device() for non-device ranges always fails
    virtual bool do_read_device(i_device_state_access * /*a*/, uint64_t /*offset*/, int /*log2_size*/,
        uint64_t * /*val*/) const noexcept {
        return false;
    }

    // Default implementation of write_device() for non-device ranges always fails
    virtual execute_status do_write_device(i_device_state_access * /*a*/, uint64_t /*offset*/, int /* log2_size */,
        uint64_t /*val*/) noexcept {
        return execute_status::failure;
    }

    // Default implementation of get_host_memory() for non-memory ranges returns nullptr
    virtual const unsigned char *do_get_host_memory() const noexcept {
        return nullptr;
    }

    virtual unsigned char *do_get_host_memory() noexcept {
        return nullptr;
    }

    // Defaul implemenation always assumes every page is always dirty
    virtual void do_mark_dirty_page(uint64_t /*offset*/) noexcept {
        ;
    }

    virtual void do_mark_clean_page(uint64_t /*offset*/) noexcept {
        ;
    }

    virtual void do_mark_pages_clean() noexcept {
        ;
    }

    virtual bool do_is_page_marked_dirty(uint64_t /*offset*/) const noexcept {
        return true;
    }
};

template <size_t N>
constexpr static auto make_empty_address_range(const char (&description)[N]) {
    return address_range{description};
}

template <typename ABRT>
static inline auto make_address_range(const char *description, uint64_t start, uint64_t length, pma_flags f,
    ABRT abrt) {
    return address_range{description, start, length, f, abrt};
}

} // namespace cartesi

#endif // OCCUPIED_ADDRESS_RANGE_H
