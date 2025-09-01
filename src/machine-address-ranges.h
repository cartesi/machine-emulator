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

#ifndef MACHINE_ADDRESS_RANGES_H
#define MACHINE_ADDRESS_RANGES_H

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

/// \file
/// \brief Cartesi machine address ranges.

#include "address-range-description.h"
#include "address-range.h"
#include "machine-config.h"
#include "machine-runtime-config.h"
#include "scope-remove.h"
#include "virtio-address-range.h"

namespace cartesi {

/// \brief Machine address ranges.
/// \details Class holding all address ranges in the machine
class machine_address_ranges {

    std::vector<std::unique_ptr<address_range>> m_all; ///< Owner of all address ranges
    std::vector<uint64_t> m_hash_tree;                 ///< Indices of address ranges registered with hash tree
    std::vector<uint64_t> m_pmas;                      ///< Indices of address ranges registered as PMAs
    std::vector<virtio_address_range *> m_virtio;      ///< Pointers to all VirtIO address ranges
    address_range_descriptions m_descrs;               ///< Address range descriptions for users
    int m_shadow_state_index;                          ///< Index of shadow state address range
    int m_shadow_uarch_state_index;                    ///< Index of shadow uarch state address range
    address_range m_sentinel{make_empty_address_range("sentinel")};

public:
    /// \brief Constructor
    /// \param config Machine configuration
    /// \param runtime_config Runtime configuration
    /// \param dir Directory for backing store files (can be empty)
    /// \param remover Scope remove object to remove created files on failure
    explicit machine_address_ranges(const machine_config &config, const machine_runtime_config &runtime_config,
        const std::string &dir, scope_remove &remover);

    /// \brief Const view of all address ranges
    auto all() const {
        return std::views::transform(m_all, [](const auto &p) -> const address_range & { return *p; });
    }

    /// \brief Const view of address ranges registered with hash tree
    auto hash_tree_view() const {
        return std::views::transform(m_hash_tree, [this](auto i) -> const address_range & { return *m_all[i]; });
    }

    /// \brief View of address ranges registered with hash tree
    auto hash_tree_view() {
        return std::views::transform(m_hash_tree, [this](auto i) -> address_range & { return *m_all[i]; });
    }

    /// \brief Const view of address ranges registered as PMAs
    auto pmas_view() const {
        return std::views::transform(m_pmas, [this](auto i) -> const address_range & { return *m_all[i]; });
    }

    /// \brief Const view of address ranges registered as PMAs
    auto pmas_view() {
        return std::views::transform(m_pmas, [this](auto i) -> address_range & { return *m_all[i]; });
    }

    /// \brief View of all VirtIO address ranges
    auto virtio_view() {
        return std::views::transform(m_virtio, [](auto *p) -> virtio_address_range & { return *p; });
    }

    /// \brief View of all VirtIO address ranges
    auto virtio_view() const {
        return std::views::transform(m_virtio, [](auto *p) -> const virtio_address_range & { return *p; });
    }

    /// \brief Returns the address range corresponding to the ith PMA
    const address_range &read_pma(uint64_t index) const noexcept {
        if (index >= m_pmas.size()) [[unlikely]] {
            return m_sentinel;
        }
        return *m_all[static_cast<size_t>(m_pmas[static_cast<size_t>(index)])];
    }

    /// \brief Returns const address range that covers a given physical memory region
    /// \param paddr Target physical address of start of region.
    /// \param length Length of region, in bytes.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    const address_range &find(uint64_t paddr, uint64_t length) const noexcept {
        for (const auto &ar : m_all) {
            if (ar->contains_absolute(paddr, length)) {
                return *ar;
            }
        }
        return m_sentinel;
    }

    /// \brief Returns address range that covers a given physical memory region
    /// \param paddr Target physical address of start of region.
    /// \param length Length of region, in bytes.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    address_range &find(uint64_t paddr, uint64_t length) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<address_range &>(std::as_const(*this).find(paddr, length));
    }

    /// \brief Returns a const address range that covers a given word in physical memory
    /// \tparam T Type of word.
    /// \param paddr Target physical address of start of region.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    template <typename T>
    const address_range &find(uint64_t paddr) const {
        return find(paddr, sizeof(T));
    }

    /// \brief Returns a const address range that covers a given word in physical memory
    /// \tparam T Type of word.
    /// \param paddr Target physical address of start of region.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    template <typename T>
    address_range &find(uint64_t paddr) {
        return find(paddr, sizeof(T));
    }

    /// \brief Replaces a memory address range.
    /// \param config Configuration of the new memory address range.
    /// \details A memory address range matching the start and length specified in the config must exist.
    void replace(const memory_range_config &config);

    /// \brief Returns descriptions of all address ranges.
    const address_range_descriptions &descriptions_view() const {
        return m_descrs;
    }

    /// \brief Marks as dirty the pages of address ranges assumed dirty
    void mark_always_dirty_pages();

private:
    ///< Where to register an address range
    struct register_where {
        bool hash_tree; //< Register with hash tree, so it appears in the root hash
        bool pmas;      //< Register as a PMA, so the interpreter can see it
    };

    /// \brief Checks if address range can be registered.
    /// \param ar Address range object to register.
    /// \param where Where to register the address range.
    void check(const address_range &ar, register_where where);

    /// \brief Registers a new address range.
    /// \tparam AR An address range or derived type.
    /// \param ar The address range object to register (as an r-value).
    /// \param where Where to register the address range.
    /// \returns Reference to address range object after it is moved inside the machine.
    /// \details The r-value address range is moved to the heap, and a smart pointer holding it is added to a container.
    /// Once the address range is moved to the heap, its address will remain valid until it is replaced by
    /// a call to replace(), or until this object is destroyed.
    /// This means pointers to address ranges remain valid even after subsequent calls to push_back(),
    /// but may be invalidated by calls to replace().
    /// For a stronger guarantee, when an address range is replaced, the smart pointer holding the new address range
    /// overwrites the smart pointer holding the old address range at the same index in the container.
    /// This means the index into the container that owns all address ranges will always refer to same address range
    /// after subsequent calls to register() and  calls to replace() as well.
    /// \details Besides the container that stores the address ranges, the machine maintains three subsets.
    /// The "hash_tree" subset lists the indices of the address ranges that will be considered by the hash tree
    /// during the computation of the state hash.
    /// The "pmas" subset lists the indices of the address ranges registered as PMAs, and therefore visible
    /// from within the interpreter.
    /// The \p where parameter tells whether to register the address range with the hash tree and/or as a PMA.
    /// Finally, the "virtio" subset lists every VirtIO address range that has been registered.
    template <typename AR>
        requires std::is_rvalue_reference_v<AR &&> && std::derived_from<AR, address_range>
    AR &push_back(AR &&ar, register_where where);

    /// \brief Adds uarch RAM address range
    /// \param c uarch RAM configuration
    void push_back_uarch_ram(const uarch_ram_config &uram);

    /// \brief Adds RAM address range
    /// \param ram RAM configuration
    void push_back_ram(const ram_config &ram);

    /// \brief Adds flash drive address ranges
    /// \param flash_drive Flash drive configurations
    /// \param runtime_config Runtime configuration
    /// \detail This modifies the flash drive configuration with automatic start/length from backing storage, if needed
    void push_back_flash_drives(const flash_drive_configs &flash_drive, const machine_runtime_config &runtime_config);

    /// \brief Adds virtio address ranges
    /// \param virtio VirtIO configurations
    /// \param iunrep Initial value of iunrep CSR
    void push_back_virtio(const virtio_configs &virtio, uint64_t iunrep);

    /// \brief Adds CMIO address ranges
    /// \param c CMIO configuration
    void push_back_cmio(const cmio_config &c);
};

} // namespace cartesi

#endif
