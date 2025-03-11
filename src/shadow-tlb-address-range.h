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

#ifndef SHADOW_TLB_ADDRESS_RANGE_H
#define SHADOW_TLB_ADDRESS_RANGE_H

#include <cstddef>
#include <cstdint>

#include "address-range-constants.h"
#include "address-range.h"
#include "shadow-state.h"

/// \file
/// \brief Shadow state address range.

namespace cartesi {

class shadow_tlb_address_range final : public address_range {

    static constexpr pmas_flags m_shadow_tlb_flags{
        .M = false,
        .IO = false,
        .R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_TLB,
    };

public:
    template <typename ABRT>
    explicit shadow_tlb_address_range(ABRT abrt) :
        address_range("shadow TLB", AR_SHADOW_TLB_START, AR_SHADOW_TLB_LENGTH, m_shadow_tlb_flags, abrt) {
        ;
    }

    shadow_tlb_address_range(const shadow_tlb_address_range &) = default;
    shadow_tlb_address_range &operator=(const shadow_tlb_address_range &) = default;
    shadow_tlb_address_range(shadow_tlb_address_range &&) noexcept = default;
    shadow_tlb_address_range &operator=(shadow_tlb_address_range &&) noexcept = default;
    ~shadow_tlb_address_range() override = default;

private:
#ifndef MICROARCHITECTURE
    bool do_peek(const machine &m, uint64_t offset, uint64_t length, const unsigned char **data,
        unsigned char *scratch) const noexcept override;
#endif
};

template <typename ABRT>
static inline shadow_tlb_address_range make_shadow_tlb_address_range(ABRT abrt) {
    return shadow_tlb_address_range{abrt};
}

} // namespace cartesi

#endif
