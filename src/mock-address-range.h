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

#ifndef MOCK_ADDRESS_RANGE_H
#define MOCK_ADDRESS_RANGE_H

#include <array>
#include <utility>
#include <variant>

#include "address-range.h"
#include "clint-address-range.h"
#include "htif-address-range.h"
#include "plic-address-range.h"
#include "pma.h"
#include "shadow-state-address-range.h"
#include "shadow-tlb-address-range.h"

namespace cartesi {

using mock_address_range = std::variant<std::monostate, address_range, clint_address_range, htif_address_range,
    plic_address_range, shadow_state_address_range, shadow_tlb_address_range>;

using mock_address_ranges = std::array<mock_address_range, PMA_MAX>;

template <typename AR, typename ABRT>
static inline mock_address_range check_mock_flags(AR &&ar, const pma_flags &flags, ABRT abrt)
    requires std::is_rvalue_reference_v<AR &&> && std::derived_from<AR, address_range>
{
    if (ar.get_flags() != flags) {
        abrt("incompatible flags in mock address range");
        __builtin_trap();
        return std::monostate{};
    }
    return std::forward<AR>(ar);
}

template <typename ABRT>
static inline mock_address_range make_mock_address_range(uint64_t istart, uint64_t ilength, ABRT abrt) {
    uint64_t start{};
    auto flags = pma_unpack_istart(istart, start);
    if (flags.M) {
        return make_address_range(pma_get_DID_name(flags.DID), start, ilength, flags, abrt);
    }
    if (flags.E) {
        return make_address_range("empty", start, ilength, flags, abrt);
    }
    switch (flags.DID) {
        case PMA_ISTART_DID::shadow_state:
            return check_mock_flags(make_shadow_state_address_range(start, ilength, abrt), flags, abrt);
        case PMA_ISTART_DID::shadow_TLB:
            return check_mock_flags(make_shadow_tlb_address_range(start, ilength, abrt), flags, abrt);
        case PMA_ISTART_DID::CLINT:
            return check_mock_flags(make_clint_address_range(start, ilength, abrt), flags, abrt);
        case PMA_ISTART_DID::PLIC:
            return check_mock_flags(make_plic_address_range(start, ilength, abrt), flags, abrt);
        case PMA_ISTART_DID::HTIF:
            return check_mock_flags(make_htif_address_range(start, ilength, abrt), flags, abrt);
        default:
            abrt("unhandled mock address range");
            __builtin_trap();
            return std::monostate{};
    }
};

template <typename ABRT>
address_range &get_mock_address_range(mock_address_range &mock, ABRT abrt) {
    //??D I'm hoping the compiler optimizes this to what amounts to an if and a cast
    static_assert(std::is_same_v<std::variant_alternative_t<0, mock_address_range>, std::monostate>);
    switch (mock.index()) {
        case 1:
            return std::get<1>(mock);
        case 2:
            return std::get<2>(mock);
        case 3:
            return std::get<3>(mock);
        case 4:
            return std::get<4>(mock);
        case 5:
            return std::get<5>(mock);
        case 6:
            return std::get<6>(mock);
        default: {
            static auto unhandled = make_empty_address_range("unhandled mock address range");
            abrt("unhandled mock address range");
            __builtin_trap();
            return unhandled;
        }
    }
    static_assert(std::variant_size_v<mock_address_range> == 7);
}

} // namespace cartesi

#endif
