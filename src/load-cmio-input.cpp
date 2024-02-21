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

#include "record-state-access.h"
#include "replay-state-access.h"
#include "state-access.h"

#include "load-cmio-input.h"
#include "uarch-solidity-compat.h"

namespace cartesi {

template <typename STATE_ACCESS>
void load_cmio_input(STATE_ACCESS &a, uint16_t reason, const unsigned char *data, uint32 length) {
    if (!a.read_iflags_Y()) {
        throw std::runtime_error("iflags.Y is not set");
    }

    a.replace_cmio_rx_buffer(data, length);

    // Write data length and reason to fromhost
    const uint64 mask16 = uint64ShiftLeft(1, 16) - 1;
    const uint64 mask32 = uint64ShiftLeft(1, 32) - 1;
    uint64 yieldData = uint64ShiftLeft((uint64(reason) & mask16), 32) | (uint64(length) & mask32);
    a.write_htif_fromhost(yieldData);

    a.reset_iflags_Y();
}

// Explicit instantiation for state_access
template void load_cmio_input(state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

// Explicit instantiation for record_state_access
template void load_cmio_input(record_state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

// Explicit instantiation for replay_state_access
template void load_cmio_input(replay_state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

} // namespace cartesi
// NOLINTEND(google-readability-casting, misc-const-correctness)
