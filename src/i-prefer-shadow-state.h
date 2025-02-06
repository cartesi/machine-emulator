
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

#ifndef I_PREFER_SHADOW_STATE_H
#define I_PREFER_SHADOW_STATE_H

/// \file
/// \brief Interface for state access that prefers to go through shadow state

#include <cstdint>
#include <type_traits>

#include "meta.h"
#include "shadow-state.h"
#include "tlb.h"

namespace cartesi {

/// \class i_prefer_shadow_state
/// \brief Interface for multiplexed access to shadow state.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \detail This is for state access methods that do not need individualized access to machine registers
template <typename DERIVED>
class i_prefer_shadow_state { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    uint64_t read_shadow_state(shadow_state_what what) {
        return derived().do_read_shadow_state(what);
    }

    void write_shadow_state(shadow_state_what what, uint64_t val) {
        derived().do_write_shadow_state(what, val);
    }
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_prefer_shadow_state =
    std::integral_constant<bool, is_template_base_of_v<i_prefer_shadow_state, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_prefer_shadow_state_v = is_an_i_prefer_shadow_state<DERIVED>::value;

} // namespace cartesi

#endif
