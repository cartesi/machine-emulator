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

/// \file
/// \brief This file is be converted to Solidity by the machine-solidity-step.

// NOLINTBEGIN(google-readability-casting,misc-const-correctness,modernize-use-auto)

#include <stdexcept>

#include "record-state-access.h"
#include "replay-state-access.h"
#include "state-access.h"

#include "send-cmio-response.h"
#include "uarch-solidity-compat.h"

namespace cartesi {

template <typename STATE_ACCESS>
void send_cmio_response(STATE_ACCESS &a, uint16 reason, bytes data, uint32 dataLength) {
    if (!readIflagsY(a)) {
        throwRuntimeError(a, "iflags.Y is not set");
    }
    // A zero length data is a valid response. We just skip writing to the rx buffer.
    if (dataLength > 0) {
        // Find the write length: the smallest power of 2 that is >= dataLength and >= tree leaf size
        uint32 writeLengthLog2Size = uint32Log2(dataLength);
        if (writeLengthLog2Size < machine_merkle_tree::get_log2_word_size()) {
            writeLengthLog2Size = 5; // minimum write size is the tree leaf size
        }
        if (uint32ShiftLeft(1, writeLengthLog2Size) < dataLength) {
            writeLengthLog2Size += 1;
        }
        writeMemoryWithPadding(a, PMA_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size);
    }
    // Write data length and reason to fromhost
    const uint64 mask16 = uint64ShiftLeft(1, 16) - 1;
    const uint64 mask32 = uint64ShiftLeft(1, 32) - 1;
    uint64 yieldData = uint64ShiftLeft((uint64(reason) & mask16), 32) | (uint64(dataLength) & mask32);
    writeHtifFromhost(a, yieldData);
    // Reset iflags.Y
    resetIflagsY(a);
}

// Explicit instantiation for state_access
template void send_cmio_response(state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

// Explicit instantiation for record_state_access
template void send_cmio_response(record_state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

// Explicit instantiation for replay_state_access
template void send_cmio_response(replay_state_access &a, uint16_t reason, const unsigned char *data, uint32 length);

} // namespace cartesi
// NOLINTEND(google-readability-casting,misc-const-correctness,modernize-use-auto)
