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

#ifndef ADDRESS_RANGE_HPP
#define ADDRESS_RANGE_HPP

#include <algorithm>
#include <array>
#include <bit>
#include <cinttypes>
#include <cstdint>
#include <tuple>
#include <utility>

#include "address-range-constants.hpp"
#include "assert-printf.hpp"
#include "i-device-state-access-fwd.hpp"
#include "interpret.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"

#ifndef MICROARCHITECTURE
#ifndef ZKARCHITECTURE
#include "i-dense-hash-tree.hpp"
#include "i-dirty-page-tree.hpp"
#endif
#endif

namespace cartesi {

/// \file
/// \brief Physical address range

/// \brief Physical Address Range.
/// \details The target's physical address layout is described by an array of specializations of such ranges.
class address_range {

    uint64_t m_istart; ///< Start of range and attribute flags, as stored in the PMA entry.
    uint64_t m_length; ///< Length of range, in bytes.

public:
    /// \brief Noexcept constexpr constructor for empty ranges
    constexpr address_range() noexcept : m_istart{0}, m_length{0} {}

    // NOLINTNEXTLINE(hicpp-use-equals-default,modernize-use-equals-default)
    constexpr virtual ~address_range() {} // = default; // doesn't work due to bug in gcc

    template <typename ABRT, size_t N, typename... ARGS>
    [[noreturn]]
    static void ABRTF(ABRT abrt, const char (&fmt)[N], ARGS... args) {
#ifndef ZKARCHITECTURE
        char buf[256]{};
        std::ignore = snprintf(buf, std::size(buf), fmt, args...);
        abrt(buf);
#endif
        __builtin_trap();
    }

    /// \brief Constructor from a PMA entry
    /// \tparam ABRT type of function used to abort and report errors
    /// \param istart Start of range packed with its attribute flags
    /// \param ilength Length of range, in bytes
    template <typename ABRT>
    constexpr address_range(uint64_t istart, uint64_t ilength, ABRT abrt) : m_istart{istart}, m_length{ilength} {
        validate(nullptr, abrt);
    }

    /// \brief Constructor
    /// \tparam ABRT type of function used to abort and report errors
    /// \param description Description of address range for use in error messages
    /// \param start Target physical address where range starts
    /// \param length Length of range, in bytes
    /// \param f Physical memory attribute flags for range
    template <typename ABRT>
    constexpr address_range(const char *description, uint64_t start, uint64_t length, const pmas_flags &flags,
        ABRT abrt) :
        m_istart{pmas_pack_istart(flags, start & PMA_ISTART_START_MASK)},
        m_length{length} {
        // Non-empty description is mandatory
        if (description == nullptr || *description == '\0') {
            ABRTF(abrt, "address range 0x%" PRIx64 ":0x%" PRIx64 " has empty description", start, length);
        }
        if ((start & ~PMA_ISTART_START_MASK) != 0) {
            ABRTF(abrt, "start of %s (0x%" PRIx64 ") must be aligned to page boundary (every %" PRId64 " bytes)",
                description, start, AR_PAGE_SIZE);
        }
        validate(description, abrt);
    }

    address_range(const address_range &other) = default;
    address_range &operator=(const address_range &other) = default;
    address_range(address_range &&other) = default;
    address_range &operator=(address_range &&other) = default;

    /// \brief Checks if a range of addresses is entirely contained within this range
    /// \param offset Start of range of interest, relative to start of this range
    /// \param length Length of range of interest, in bytes
    /// \returns True if and only if range of interest is entirely contained within this range
    constexpr bool contains_relative(uint64_t offset, uint64_t length) const noexcept {
        return get_length() >= length && offset <= get_length() - length;
    }

    /// \brief Checks if a range of addresses is entirely contained within this range
    /// \param start Target phyisical address of start of range of interest
    /// \param length Length of range of interest, in bytes
    /// \returns True if and only if range of interest is entirely contained within this range
    constexpr bool contains_absolute(uint64_t start, uint64_t length) const noexcept {
        return start >= get_start() && contains_relative(start - get_start(), length);
    }

    /// \brief Returns PMA flags used during construction
    /// \returns Flags
    constexpr pmas_flags get_flags() const noexcept {
        uint64_t start{};
        return pmas_unpack_istart(m_istart, start);
    }

    /// \brief Returns description of address range for use in error messages.
    /// \returns Description
    const char *get_description() const noexcept {
        return do_get_description();
    }

    /// \brief Returns target physical address where range starts.
    /// \returns Start of range
    constexpr uint64_t get_start() const noexcept {
        return m_istart & PMA_ISTART_START_MASK;
    }

    /// \brief Returns target physical address right past end of range.
    /// \returns End of range
    constexpr uint64_t get_end() const noexcept {
        return get_start() + m_length;
    }

    /// \brief Returns length of range, in bytes.
    /// \returns Length of range
    constexpr uint64_t get_length() const noexcept {
        return m_length;
    }

    /// \brief Test if address range is occupied by memory
    /// \returns True if and only if range is occupied by memory
    /// \details In this case, get_host_memory() is guaranteed not to return nullptr.
    constexpr bool is_memory() const noexcept {
        return (m_istart & PMA_ISTART_M_MASK) != 0;
    }

    /// \brief Test if address range is occupied by a device
    /// \returns True if and only if range is occupied by a device
    /// \details In this case, read_device() and write_device() are operational.
    constexpr bool is_device() const noexcept {
        return (m_istart & PMA_ISTART_IO_MASK) != 0;
    }

    /// \brief Test if address range is empty
    /// \returns True if and only if range is empty
    /// \details Empty ranges should be used only for sentinels.
    constexpr bool is_empty() const noexcept {
        return m_length == 0;
    }

    /// \brief Tests if range is readable
    /// \returns True if and only if range is readable from within the machine.
    constexpr bool is_readable() const noexcept {
        return (m_istart & PMA_ISTART_R_MASK) != 0;
    }

    /// \brief Tests if range is writeable
    /// \returns True if and only if range is writeable from within the machine.
    constexpr bool is_writeable() const noexcept {
        return (m_istart & PMA_ISTART_W_MASK) != 0;
    }

    /// \brief Tests if range is executable
    /// \returns True if and only if range is executable from within the machine.
    constexpr bool is_executable() const noexcept {
        return (m_istart & PMA_ISTART_X_MASK) != 0;
    }

    /// \brief Tests if range is read-idempotent
    /// \returns True if and only if what is read from range remains there until written to
    constexpr bool is_read_idempotent() const noexcept {
        return (m_istart & PMA_ISTART_IR_MASK) != 0;
    }

    /// \brief Tests if range is write-idempotent
    /// \returns True if and only if what is written to range remains there and can be read until written to again
    constexpr bool is_write_idempotent() const noexcept {
        return (m_istart & PMA_ISTART_IW_MASK) != 0;
    }

    /// \brief Returns driver ID associated to range
    /// \returns The driver ID
    constexpr PMA_ISTART_DID get_driver_id() const noexcept {
        return static_cast<PMA_ISTART_DID>((m_istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
    }

    /// \brief Returns packed address range istart field as per whitepaper
    /// \returns Packed address range istart
    constexpr uint64_t get_istart() const noexcept {
        return m_istart;
    }

    /// \brief Returns encoded address range ilength field as per whitepaper
    /// \returns Packed address range ilength
    /// \details This currently contains only the length itself
    uint64_t get_ilength() const noexcept {
        return get_length();
    }

    /// \brief Returns number of levels in a tree where each leaf is a page
    int get_level_count() const noexcept {
        return get_level_count(get_length());
    }

#ifndef MICROARCHITECTURE
#ifndef ZKARCHITECTURE
    /// \brief Returns reference to dirty page tree.
    i_dirty_page_tree &get_dirty_page_tree() noexcept {
        return do_get_dirty_page_tree();
    }

    /// \brief Returns const reference to dirty page tree.
    const i_dirty_page_tree &get_dirty_page_tree() const noexcept {
        return do_get_dirty_page_tree();
    }

    /// \brief Returns reference to dense hash tree.
    i_dense_hash_tree &get_dense_hash_tree() noexcept {
        return do_get_dense_hash_tree();
    }

    /// \brief Returns const reference to dense hash tree tree.
    const i_dense_hash_tree &get_dense_hash_tree() const noexcept {
        return do_get_dense_hash_tree();
    }
#endif
#endif

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

    /// \brief Returns true if the mapped memory is read-only on the host
    /// \returns True if the memory is read-only in the host
    bool is_host_read_only() const noexcept {
        return do_is_host_read_only();
    }

    /// \brief Returns true if the mapped memory is shared with a backing store in the host
    /// \returns True if the memory is shared in the host
    bool has_shared_backing_store() const noexcept {
        return do_has_shared_backing_store();
    }

protected:
    /// \brief Returns number of levels in a tree where each leaf is a page
    /// \param length Length of range, in bytes
    static constexpr int get_level_count(uint64_t length) noexcept {
        auto page_count = length >> AR_LOG2_PAGE_SIZE;
        if (page_count == 0) {
            return 0;
        }
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        return std::bit_width(std::bit_ceil(page_count));
    }

private:
    /// \brief Checks the range, aborting with a message that names it
    /// \param description Description of range, or nullptr to name it after its driver
    template <typename ABRT>
    constexpr void validate(const char *description, ABRT abrt) const {
        const auto name = [this, description] {
            return description != nullptr ? description : pmas_get_DID_name(get_driver_id());
        };
        const uint64_t start = get_start();
        // End = start + length cannot overflow
        if (start >= UINT64_MAX - m_length) {
            ABRTF(abrt, "0x%" PRIx64 ":0x%" PRIx64 " is out of bounds when initializing %s", start, m_length, name());
        }
        // All address ranges must be page-aligned
        if ((m_length & ~PMA_ISTART_START_MASK) != 0) {
            ABRTF(abrt, "length of %s (0x% " PRIx64 ") must be multiple of page length (%" PRId64 " bytes)", name(),
                m_length, AR_PAGE_SIZE);
        }
        // Empty range must really be empty
        if (m_length == 0 && m_istart != 0) {
            if (start != 0) {
                ABRTF(abrt, "empty range with length 0 must start at 0 when initializing %s", name());
            }
            ABRTF(abrt, "empty range must have clear flags when initializing %s", name());
        }
    }

    // Ranges that carry no description of their own are described by their driver
    virtual const char *do_get_description() const noexcept {
        return is_empty() ? "empty" : pmas_get_DID_name(get_driver_id());
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

    virtual bool do_is_host_read_only() const noexcept {
        return false;
    }

    virtual bool do_has_shared_backing_store() const noexcept {
        return false;
    }

#ifndef MICROARCHITECTURE
#ifndef ZKARCHITECTURE
    // Default implemenationt returns always dirty tree
    virtual const i_dirty_page_tree &do_get_dirty_page_tree() const noexcept {
        const static empty_dirty_page_tree no_dirty{};
        return no_dirty;
    }

    virtual i_dirty_page_tree &do_get_dirty_page_tree() noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<i_dirty_page_tree &>(std::as_const(*this).do_get_dirty_page_tree());
    }

    // Default implemenationt returns no hashes
    virtual const i_dense_hash_tree &do_get_dense_hash_tree() const noexcept {
        const static empty_dense_hash_tree no_hashes{};
        return no_hashes;
    }

    virtual i_dense_hash_tree &do_get_dense_hash_tree() noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<i_dense_hash_tree &>(std::as_const(*this).do_get_dense_hash_tree());
    }
#endif
#endif
};

} // namespace cartesi

#endif // ADDRESS_RANGE_HPP
