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

#ifndef REJECTED_MANUAL_YIELD_HPP
#define REJECTED_MANUAL_YIELD_HPP

/// \file
/// \brief Predicate for the manual-yield rejected machine state

#include <cstdint>

#include "htif-constants.hpp"

namespace cartesi {

/// \brief Tells if the machine is paused on a manual yield whose reason is rx-rejected.
/// \tparam STATE_ACCESS State access class.
/// \param a State accessor.
/// \returns True when a manual yield with reason rx-rejected is pending.
/// \details This is the state from which verifiers substitute the recorded revert root
/// hash for the machine root hash. The uarch-dialect equivalent lives in
/// uarch-reset-state.cpp, where it is translated to Solidity.
template <typename STATE_ACCESS>
bool is_rejected_manual_yield(const STATE_ACCESS &a) {
    if (a.read_iflags_Y() == 0) {
        return false;
    }
    const uint64_t tohost = a.read_htif_tohost();
    return HTIF_DEV_FIELD(tohost) == HTIF_DEV_YIELD && HTIF_CMD_FIELD(tohost) == HTIF_YIELD_CMD_MANUAL &&
        HTIF_REASON_FIELD(tohost) == HTIF_YIELD_MANUAL_REASON_RX_REJECTED;
}

} // namespace cartesi

#endif
