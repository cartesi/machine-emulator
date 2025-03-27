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

#ifndef MEMORY_ADDRESS_RANGE_H
#define MEMORY_ADDRESS_RANGE_H

#include <cassert>
#include <variant>

#include "address-range.h"
#include "machine-config.h"
#include "os-mmap.h"
#include "unique-c-ptr.h"

namespace cartesi {

// Forward declarations
class machine;

/// \file
/// \brief An address range occupied by memory

struct memory_address_range_flags final {
    bool read_only{false};        ///< Whether the memory is read-only on the host
    bool page_uncleanable{false}; //< Whether the memory page dirty state can be cleaned
};

class memory_address_range : public address_range {
    unique_mmap_ptr<unsigned char> m_ptr;  ///< Pointer to mapped memory
    unsigned char *m_host_memory;          ///< Start of associated memory region in host.
    memory_address_range_flags m_ar_flags; ///< Memory address range specific flags.
    std::vector<uint8_t> m_dirty_page_map; ///< Map of dirty pages.

public:
    using ptr_type = std::unique_ptr<memory_address_range>;

    /// \brief Constructor for mmap'd ranges.
    /// \param description Description of address range for use in error messages
    /// \param start Start of address range
    /// \param length Length of address range
    /// \param flags Range flags
    /// \param image_filename Path to backing file.
    /// \param host_length Length of host memory to be mapped.
    /// This value can exceed the specified length, effectively creating an additional region
    /// of memory that is not associated with the backing files.
    memory_address_range(const std::string &description, uint64_t start, uint64_t length, const pmas_flags &flags,
        const backing_store_config &backing_store = {}, const memory_address_range_flags &ar_flags = {},
        uint64_t host_length = 0);

    memory_address_range(const memory_address_range &) = delete;
    memory_address_range &operator=(const memory_address_range &) = delete;
    memory_address_range &operator=(memory_address_range &&) noexcept = delete;

    ~memory_address_range() override = default;
    memory_address_range(memory_address_range &&) noexcept = default;

private:
    unsigned char *do_get_host_memory() noexcept override {
        return m_host_memory;
    }

    const unsigned char *do_get_host_memory() const noexcept override {
        return m_host_memory;
    }

    void do_mark_dirty_page(uint64_t offset) noexcept override {
        auto page_index = offset >> AR_constants::AR_PAGE_SIZE_LOG2;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        m_dirty_page_map[map_index] |= (1 << (page_index & 7));
    }

    void do_mark_clean_page(uint64_t offset) noexcept override {
        if (m_ar_flags.page_uncleanable) {
            // Dirty pages on this address range are permanently dirty and cannot be cleaned.
            return;
        }
        auto page_index = offset >> AR_constants::AR_PAGE_SIZE_LOG2;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        m_dirty_page_map[map_index] &= ~(1 << (page_index & 7));
    }

    void do_mark_pages_clean() noexcept override {
        if (m_ar_flags.page_uncleanable) {
            // Dirty pages on this address range are permanently dirty and cannot be cleaned.
            return;
        }
        std::fill(m_dirty_page_map.begin(), m_dirty_page_map.end(), 0);
    }

    bool do_is_page_marked_dirty(uint64_t offset) const noexcept override {
        auto page_index = offset >> AR_constants::AR_PAGE_SIZE_LOG2;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        return (m_dirty_page_map[map_index] & (1 << (page_index & 7))) != 0;
    }

    bool do_is_host_read_only() const noexcept override {
        return m_ar_flags.read_only;
    }

    bool do_is_page_uncleanable() const noexcept override {
        return m_ar_flags.page_uncleanable;
    }

    bool do_peek(const machine & /*m*/, uint64_t offset, uint64_t length, const unsigned char **data,
        unsigned char * /*scratch*/) const noexcept override {
        if (contains_relative(offset, length)) {
            *data = get_host_memory() + offset;
            return true;
        }
        *data = nullptr;
        return false;
    }
};

} // namespace cartesi

#endif
