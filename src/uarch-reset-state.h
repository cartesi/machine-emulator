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

#ifndef UARCH_RESET_STATE_H
#define UARCH_RESET_STATE_H

namespace cartesi {

/// \brief  Reset uarch to pristine state
/// \tparam STATE_ACCESS state accessor type
/// \param a state accessor instance
template <typename STATE_ACCESS>
void uarch_reset_state(STATE_ACCESS &a);

class uarch_state_access;
class uarch_record_state_access;
class uarch_replay_state_access;

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void uarch_reset_state(uarch_state_access &a);

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void uarch_reset_state(uarch_state_access &a);

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void uarch_reset_state(uarch_record_state_access &a);

// Declaration of explicit instantiation in module uarch-reset-state.cpp
extern template void uarch_reset_state(uarch_replay_state_access &a);

} // namespace cartesi

#endif
