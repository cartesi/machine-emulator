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

// NOLINTBEGIN(google-readability-casting, misc-const-correctness)

#include <stdexcept>

#include "riscv-constants.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-reset-state.h"
#include "uarch-solidity-compat.h"
#include "uarch-state-access.h"

namespace cartesi {

template <typename UarchState>
void uarch_reset_state(UarchState &a) {
    resetState(a);
}

// Explicit instantiation for uarch_state_access
template void uarch_reset_state(uarch_state_access &a);

// Explicit instantiation for uarch_record_state_access
template void uarch_reset_state(uarch_record_state_access &a);

// Explicit instantiation for uarch_replay_state_access
template void uarch_reset_state(uarch_replay_state_access &a);

} // namespace cartesi
// NOLINTEND(google-readability-casting, misc-const-correctness)
