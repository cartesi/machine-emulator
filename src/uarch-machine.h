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

#ifndef UARCH_MACHINE_H
#define UARCH_MACHINE_H

/// \file
/// \brief Cartesi microarchitecture machine
#include <cstdint>

#include "pma.h"
#include "uarch-config.h"
#include "uarch-state.h"

namespace cartesi {

/// \class uarch_machine
/// \brief Cartesi Machine Microarchitecture implementation
class uarch_machine final {
    uarch_state m_s;  ///< Opaque microarchitecture machine state
    uarch_config m_c; ///< Copy of initialization config

public:
    /// \brief Constructor from machine configuration
    // I will deal with clang-tidy later.
    explicit uarch_machine(uarch_config c);
    /// \brief Destructor.
    ~uarch_machine() = default;

    /// \brief No default constructor
    uarch_machine() = delete;
    /// \brief No copy constructor
    uarch_machine(const uarch_machine &other) = delete;
    /// \brief No move constructor
    uarch_machine(uarch_machine &&other) = delete;
    /// \brief No copy assignment
    uarch_machine &operator=(const uarch_machine &other) = delete;
    /// \brief No move assignment
    uarch_machine &operator=(uarch_machine &&other) = delete;

    /// \brief Returns machine state for direct access.
    uarch_state &get_state() {
        return m_s;
    }

    /// \brief Returns machine state for direct read-only access.
    const uarch_state &get_state() const {
        return m_s;
    }

    /// \brief Obtain PMA entry that covers a given physical memory region
    /// \param s Pointer to machine state.
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    pma_entry &find_pma_entry(uint64_t paddr, uint64_t length);

    /// \brief Obtain PMA entry that covers a given physical memory region
    const pma_entry &find_pma_entry(uint64_t paddr, uint64_t length) const;

    /// \brief Returns copy of initialization config.
    const uarch_config &get_initial_config() const {
        return m_c;
    }
};

} // namespace cartesi

#endif
