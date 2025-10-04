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

#include <cstdint>
#include <string>

#include "address-range.h"
#include "dense-hash-tree.h"
#include "dirty-page-tree.h"
#include "machine-config.h"
#include "os-mapped-memory.h"
#include "pmas.h"

namespace cartesi {

// Forward declarations
class machine;

/// \brief Configuration for memory address range
struct memory_address_range_config {
    ///< Whether memory is read-only on host. (If set, must be read-only on target as well)
    bool host_read_only{false};
    ///< Whether host should not reserve memory when mapping the memory.
    /// Only useful to create or load machines with large unused address space on host without enough memory or swap.
    /// (Use with caution as the process may crash when running out of host memory)/
    bool host_no_reserve{false};
    ///< Total amount of memory allocated by host. (Must be larger than what is needed by target)
    uint64_t host_length{0};
};

/// \file
/// \brief An address range occupied by memory

class memory_address_range final : public address_range {
    os::mapped_memory m_mapped;           ///< Pointer to mapped memory
    memory_address_range_config m_config; ///< Memory configuration passed to constructor.
    backing_store_config m_backing_store; ///< Backing store configuration passed to constructor.
    dirty_page_tree m_dpt;                ///< Tree of dirty pages.
    dense_hash_tree m_dht;                ///< Dense hash tree of pages.

public:
    /// \brief Constructor
    /// \param description Description of address range for use in error messages
    /// \param start Start of address range
    /// \param length Length of address range
    /// \param flags Address range flags
    /// \param backing_store Configuration for underlying file backing.
    /// \param config Additional configuration for memory address range.
    /// \p config.host_length Length of host memory to be mapped.
    /// If set to 0, use \p length.
    /// Otherwise, \p host_length cannot be smaller than \p length.
    /// The effect is to allocate additional memory past \p length that is not visible by the address range,
    /// and is not part of the backing storage, but can be used for other purposes.
    /// \p config.host_read_only Marks memory as read-only on host itself. Requires \p flags.W to be cleared as well.
    memory_address_range(const std::string &description, uint64_t start, uint64_t length, const pmas_flags &flags,
        const backing_store_config &backing_store = {}, const memory_address_range_config &memory_config = {});

    ~memory_address_range() override = default;

    // No copy or move constructors or assignments
    memory_address_range(const memory_address_range &) = delete;
    memory_address_range(memory_address_range &&) = delete;
    memory_address_range &operator=(const memory_address_range &) = delete;
    memory_address_range &operator=(memory_address_range &&) = delete;

private:
    unsigned char *do_get_host_memory() noexcept override {
        return m_mapped.get_ptr();
    }

    const unsigned char *do_get_host_memory() const noexcept override {
        return m_mapped.get_ptr();
    }

    bool do_is_host_read_only() const noexcept override {
        return m_config.host_read_only;
    }

    bool do_is_backing_store_shared() const noexcept override {
        return m_backing_store.shared;
    }

    dirty_page_tree &do_get_dirty_page_tree() noexcept override {
        return m_dpt;
    }

    const dirty_page_tree &do_get_dirty_page_tree() const noexcept override {
        return m_dpt;
    }

    dense_hash_tree &do_get_dense_hash_tree() noexcept override {
        return m_dht;
    }

    const dense_hash_tree &do_get_dense_hash_tree() const noexcept override {
        return m_dht;
    }
};

} // namespace cartesi

#endif
