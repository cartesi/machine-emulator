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

#ifndef SHADOW_UARCH_STATE_ADDRESS_RANGE_H
#define SHADOW_UARCH_STATE_ADDRESS_RANGE_H

#include <cstddef>
#include <cstdint>

#include "address-range.h"
#include "shadow-uarch-state.h"

/// \file
/// \brief Shadow uarch state address range.

namespace cartesi {

class shadow_uarch_state_address_range final : public address_range {

    static constexpr pmas_flags m_shadow_uarch_state_flags{
        .M = false,
        .IO = true,
        .E = false,
        .R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_uarch_state,
    };

public:
    template <typename ABRT>
    shadow_uarch_state_address_range(uint64_t start, uint64_t length, ABRT abrt) :
        address_range("shadow uarch state", start, length, m_shadow_uarch_state_flags, abrt) {
        ;
    }

    shadow_uarch_state_address_range(const shadow_uarch_state_address_range &) = delete;
    shadow_uarch_state_address_range &operator=(const shadow_uarch_state_address_range &) = delete;
    shadow_uarch_state_address_range &operator=(shadow_uarch_state_address_range &&) noexcept = delete;

    shadow_uarch_state_address_range(shadow_uarch_state_address_range &&) noexcept = default;
    ~shadow_uarch_state_address_range() override = default;

private:
#ifndef MICROARCHITECTURE
    bool do_peek(const machine &m, uint64_t offset, uint64_t length, const unsigned char **data,
        unsigned char *scratch) const noexcept override;
#endif
};

template <typename ABRT>
static inline shadow_uarch_state_address_range make_shadow_uarch_state_address_range(uint64_t start, uint64_t length,
    ABRT abrt) {
    return shadow_uarch_state_address_range{start, length, abrt};
}

} // namespace cartesi

#endif
