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

#ifndef I_INTERACTIVE_STATE_ACCESS_H
#define I_INTERACTIVE_STATE_ACCESS_H

/// \file
/// \brief Interactive state access interface

#include <cstdint>
#include <type_traits>

#include "meta.h"

namespace cartesi {

/// \class i_interactive_state_access
/// \brief Interface for interactive machine state access.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_interactive_state_access { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Wait for external interrupts requests.
    /// \param mcycle Current value of mcycle.
    /// \param mcycle_max Maximum mcycle after wait.
    auto poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) const {
        return derived().do_poll_external_interrupts(mcycle, mcycle_max);
    }

    /// \brief Returns true if soft yield HINT instruction is enabled at runtime
    bool get_soft_yield() const {
        return derived().do_get_soft_yield();
    }

    /// \brief Reads a character from the console
    /// \returns Character read if any, -1 otherwise
    int getchar() const {
        return derived().do_getchar();
    }
};

/// \brief SFINAE test implementation of the i_interactive_state_access interface
template <typename DERIVED>
using is_an_i_interactive_state_access =
    std::integral_constant<bool, is_template_base_of_v<i_interactive_state_access, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_interactive_state_access_v = is_an_i_interactive_state_access<DERIVED>::value;

} // namespace cartesi

#endif
