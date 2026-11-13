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

#ifndef SELECTED_ADDRESS_RANGES_HPP
#define SELECTED_ADDRESS_RANGES_HPP

#include <array>
#include <cstdint>

#include "address-range.hpp"
#include "clint-address-range.hpp"
#include "htif-address-range.hpp"
#include "plic-address-range.hpp"
#include "pmas-constants.hpp"

namespace cartesi {

/// \brief Address ranges built from PMA entries, where there is no machine to own them.
/// \details Replaying a step log, and running inside the microarchitecture or a zkVM, only the two
/// words of each PMA entry are available. A range is built and validated the first time its entry is
/// selected, and never changes afterwards. Memory ranges are built in place from the entry. Device
/// ranges are members, and the entry must match them.
class selected_address_ranges {
    // The device members are constant-initialized: constants that fail validation reach the trap in
    // the address_range constructor during constant evaluation and do not compile.
    static constexpr void mismatch(const char * /*err*/) {}

    std::array<address_range, PMA_MAX> m_memory{};
    std::array<address_range *, PMA_MAX> m_selected{};
    clint_address_range m_clint{mismatch};
    plic_address_range m_plic{mismatch};
    htif_address_range m_htif{mismatch};

public:
    constexpr selected_address_ranges() = default;
    // Selected entries point into this object
    selected_address_ranges(const selected_address_ranges &) = delete;
    selected_address_ranges &operator=(const selected_address_ranges &) = delete;
    selected_address_ranges(selected_address_ranges &&) = delete;
    selected_address_ranges &operator=(selected_address_ranges &&) = delete;
    constexpr ~selected_address_ranges() = default;

    /// \brief Returns the range selected earlier for an entry, or nullptr
    address_range *find(uint64_t index) const noexcept {
        return m_selected[index];
    }

    /// \brief Returns the range for an entry, building it on first use
    template <typename ABRT>
    address_range &select(uint64_t index, uint64_t istart, uint64_t ilength, ABRT abrt) {
        auto *&selected = m_selected[index];
        if (selected != nullptr) {
            return *selected;
        }
        if ((istart & PMA_ISTART_M_MASK) != 0 || ilength == 0) {
            m_memory[index] = address_range{istart, ilength, abrt};
            selected = &m_memory[index];
            return *selected;
        }
        address_range *ar = nullptr;
        switch (static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT)) {
            case PMA_ISTART_DID::CLINT:
                ar = &m_clint;
                break;
            case PMA_ISTART_DID::PLIC:
                ar = &m_plic;
                break;
            case PMA_ISTART_DID::HTIF:
                ar = &m_htif;
                break;
            default:
                abrt("unhandled device address range");
                __builtin_trap();
        }
        if (ar->get_istart() != istart || ar->get_length() != ilength) {
            abrt("incompatible device address range");
            __builtin_trap();
        }
        selected = ar;
        return *selected;
    }
};

} // namespace cartesi

#endif
