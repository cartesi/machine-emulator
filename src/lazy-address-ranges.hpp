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

#ifndef LAZY_ADDRESS_RANGES_HPP
#define LAZY_ADDRESS_RANGES_HPP

#include <array>
#include <cstdint>

#include "address-range.hpp"
#include "clint-address-range.hpp"
#include "compiler-defines.hpp"
#include "htif-address-range.hpp"
#include "plic-address-range.hpp"
#include "pmas-constants.hpp"

namespace cartesi {

/// \brief Address ranges built from PMA entries, where there is no machine to own them.
/// \details Replaying a step log, and running inside the microarchitecture or a zkVM, only the two
/// words of each PMA entry are available. A range is built and validated the first time its entry is
/// created, and never changes afterwards. Memory ranges are built in place from the entry. Device
/// ranges are members, and the entry must match them.
class lazy_address_ranges {
    // The device members are constant-initialized: constants that fail validation reach the trap in
    // the address_range constructor during constant evaluation and do not compile.
    static constexpr void never_called(const char * /*err*/) {}

    std::array<address_range, PMA_MAX> m_memory{};
    std::array<address_range *, PMA_MAX> m_created{};
    address_range m_sentinel;
    clint_address_range m_clint{never_called};
    plic_address_range m_plic{never_called};
    htif_address_range m_htif{never_called};

    static constexpr bool is_memory_or_empty(uint64_t istart, uint64_t ilength) noexcept {
        return (istart & PMA_ISTART_M_MASK) != 0 || ilength == 0;
    }

    static constexpr PMA_ISTART_DID get_driver_id(uint64_t istart) noexcept {
        return static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
    }

    /// \brief Creates the range for an entry
    /// \details A memory or empty range is built from the entry. A device range is built in, and the
    /// entry must match it.
    template <typename ABRT>
    FORCE_INLINE address_range &create(uint64_t index, uint64_t istart, uint64_t ilength, ABRT abrt) {
        if (is_memory_or_empty(istart, ilength)) {
            m_memory[index] = address_range{istart, ilength, abrt};
            return m_memory[index];
        }
        address_range *device = nullptr;
        switch (get_driver_id(istart)) {
            case PMA_ISTART_DID::CLINT:
                device = &m_clint;
                break;
            case PMA_ISTART_DID::PLIC:
                device = &m_plic;
                break;
            case PMA_ISTART_DID::HTIF:
                device = &m_htif;
                break;
            default:
                abrt("unhandled device address range");
                __builtin_trap();
        }
        if (device->get_istart() != istart || device->get_length() != ilength) {
            abrt("incompatible device address range");
            __builtin_trap();
        }
        return *device;
    }

public:
    constexpr lazy_address_ranges() = default;
    // Created entries point into this object
    lazy_address_ranges(const lazy_address_ranges &) = delete;
    lazy_address_ranges &operator=(const lazy_address_ranges &) = delete;
    lazy_address_ranges(lazy_address_ranges &&) = delete;
    lazy_address_ranges &operator=(lazy_address_ranges &&) = delete;
    constexpr ~lazy_address_ranges() = default;

    /// \brief Returns the range already created for an entry, or nullptr
    address_range *get(uint64_t index) const noexcept {
        return m_created[index];
    }

    /// \brief Returns the range for an entry, creating it on first use
    template <typename ABRT>
    address_range &get_or_create(uint64_t index, uint64_t istart, uint64_t ilength, ABRT abrt) {
        auto *&created = m_created[index];
        if (created == nullptr) {
            created = &create(index, istart, ilength, abrt);
        }
        return *created;
    }

    /// \brief Returns the empty range that stands for no PMA entry
    address_range &get_sentinel() noexcept {
        return m_sentinel;
    }
};

} // namespace cartesi

#endif
