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
#include "unique-c-ptr.h"

namespace cartesi {

// Forward declarations
class machine;

/// \file
/// \brief An address range occupied by memory

class memory_address_range : public address_range {

    using callocd_ptr = unique_calloc_ptr<unsigned char>;
    using mmapd_ptr = unique_mmap_ptr<unsigned char>;

    std::variant<std::monostate, ///< Before initialization
        callocd_ptr,             ///< Automatic pointer for calloced memory
        mmapd_ptr                ///< Automatic pointer for mmapped memory
        >
        m_ptr;

    unsigned char *m_host_memory;          ///< Start of associated memory region in host.
    std::vector<uint8_t> m_dirty_page_map; ///< Map of dirty pages.

public:
    using ptr_type = std::unique_ptr<memory_address_range>;

    /// \brief Mmap'd range data (shared or not).
    struct mmapd {
        bool shared;
    };

    /// \brief Constructor for mmap'd ranges.
    /// \param description Description of address range for use in error messages
    /// \param start Start of address range
    /// \param length Length of address range
    /// \param flags Range flags
    /// \param image_filename Path to backing file.
    /// \param m Mmap'd range data (shared or not).
    memory_address_range(const std::string &description, uint64_t start, uint64_t length, const pmas_flags &flags,
        const std::string &image_filename, const mmapd &m);

    /// \brief Calloc'd range data (just a tag).
    struct callocd {};

    /// \brief Constructor for calloc'd ranges.
    /// \param description Description of address range for use in error messages
    /// \param start Start of address range
    /// \param length Length of address range
    /// \param flags Range flags
    /// \param image_filename Path to backing file.
    /// \param c Calloc'd range data (just a tag).
    memory_address_range(const std::string &description, uint64_t start, uint64_t length, const pmas_flags &flags,
        const std::string &image_filename, const callocd & /*c*/);

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
        auto page_index = offset >> AR_constants::AR_LOG2_PAGE_SIZE;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        m_dirty_page_map[map_index] |= (1 << (page_index & 7));
    }

    void do_mark_clean_page(uint64_t offset) noexcept override {
        auto page_index = offset >> AR_constants::AR_LOG2_PAGE_SIZE;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        m_dirty_page_map[map_index] &= ~(1 << (page_index & 7));
    }

    void do_mark_pages_clean() noexcept override {
        std::fill(m_dirty_page_map.begin(), m_dirty_page_map.end(), 0);
    }

    bool do_is_page_marked_dirty(uint64_t offset) const noexcept override {
        auto page_index = offset >> AR_constants::AR_LOG2_PAGE_SIZE;
        auto map_index = page_index >> 3;
        assert(map_index < m_dirty_page_map.size());
        return (m_dirty_page_map[map_index] & (1 << (page_index & 7))) != 0;
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

static inline auto make_callocd_memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    pmas_flags flags, const std::string &image_filename = {}) {
    return memory_address_range{description, start, length, flags, image_filename, memory_address_range::callocd{}};
}

static inline auto make_mmapd_memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    pmas_flags flags, const std::string &image_filename, bool shared) {
    return memory_address_range{description, start, length, flags, image_filename, memory_address_range::mmapd{shared}};
}

} // namespace cartesi

#endif
