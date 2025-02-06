
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

#ifndef I_PREFER_SHADOW_UARCH_STATE_H
#define I_PREFER_SHADOW_UARCH_STATE_H

/// \file
/// \brief Interface for state access that prefers to go through shadow uarch state

#include <cinttypes>
#include <cstdint>
#include <type_traits>

#include "dump-uarch-state-access.h"
#include "meta.h"
#include "shadow-uarch-state.h"
#include "tlb.h"

namespace cartesi {

/// \class i_prefer_shadow_uarch_state
/// \brief Interface for multiplexed access to shadow uarch state.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \detail This is for state access methods that do not need individualized access to uarch registers
template <typename DERIVED>
class i_prefer_shadow_uarch_state { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    uint64_t read_shadow_uarch_state(shadow_uarch_state_what what) {
        const auto val = derived().do_read_shadow_uarch_state(what);
        [[maybe_unused]] const auto *const what_name = shadow_uarch_state_get_what_name(what);
        DUSA_PRINTF("%s::read_shadow_uarch_state(%s) = %" PRIu64 "(0x%" PRIx64 ")\n", derived().get_name(), what_name,
            val, val);
        return val;
    }

    void write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) {
        derived().do_write_shadow_uarch_state(what, val);
        [[maybe_unused]] const auto *const what_name = shadow_uarch_state_get_what_name(what);
        DUSA_PRINTF("%s::write_shadow_uarch_state(%s, %" PRIu64 "(0x%" PRIx64 "))\n", derived().get_name(), what_name,
            val, val);
    }
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_prefer_shadow_uarch_state =
    std::integral_constant<bool, is_template_base_of_v<i_prefer_shadow_uarch_state, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_prefer_shadow_uarch_state_v = is_an_i_prefer_shadow_uarch_state<DERIVED>::value;

} // namespace cartesi

#endif
