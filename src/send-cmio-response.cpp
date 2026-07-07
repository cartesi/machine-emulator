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

#include "send-cmio-response.hpp"

#include "address-range-constants.hpp"
#include "hash-tree-constants.hpp"
#include "htif-constants.hpp"
#include "record-send-cmio-state-access.hpp" // IWYU pragma: keep
#include "replay-send-cmio-state-access.hpp" // IWYU pragma: keep
#include "state-access.hpp"                  // IWYU pragma: keep
#include "uarch-solidity-compat.hpp"

// NOLINTBEGIN(google-readability-casting,misc-const-correctness,modernize-use-auto,hicpp-use-auto,readability-use-std-min-max,modernize-avoid-c-style-cast)
namespace cartesi {

template <typename STATE_ACCESS>
void send_cmio_response(STATE_ACCESS a, bytes32 revertRootHash, uint16 reason, bytes data, uint32 dataLength) {
    // This function cannot fail. When a failure is detected, the operation is a no-op instead,
    // so the honest party can always log and prove the resulting state transition.
    // A response to a machine that is not waiting on a manual yield is a no-op.
    if (!readIflagsY(a)) {
        return;
    }
    if (reason == HTIF_YIELD_REASON_ADVANCE_STATE) {
        // Advance-state responses are the input boundary of the rollups flow. They only apply to a
        // machine waiting for an input on an rx-accepted manual yield. Sending one to a machine that
        // yielded manual with any other reason (e.g., rejected an input or threw an exception) is a no-op.
        uint64 tohost = readHtifTohost(a);
        if (!isYieldedManualWith(tohost, HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)) {
            return;
        }
    }
    // A zero length data is a valid response. We just skip writing to the rx buffer.
    uint32 writeLengthLog2Size = 0;
    if (dataLength > 0) {
        // Find the write length: the smallest power of 2 that is >= dataLength and >= tree leaf size
        writeLengthLog2Size = uint32Log2(dataLength);
        if (writeLengthLog2Size < HASH_TREE_LOG2_WORD_SIZE) {
            writeLengthLog2Size = HASH_TREE_LOG2_WORD_SIZE; // minimum write size is the tree leaf size
        }
        if (uint32ShiftLeft(1, writeLengthLog2Size) < dataLength) {
            writeLengthLog2Size += 1;
        }
        // A response with data that does not fit in the rx buffer is a no-op
        if (writeLengthLog2Size > AR_CMIO_RX_BUFFER_LOG2_SIZE) {
            return;
        }
    }
    // Record the machine root hash to revert to in case the response is eventually rejected
    writeRevertRootHash(a, revertRootHash);
    if (dataLength > 0) {
        writeMemoryWithPadding(a, AR_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size);
    }
    // Write data length and reason to fromhost
    const uint64 mask16 = uint64ShiftLeft(1, 16) - 1;
    const uint64 mask32 = uint64ShiftLeft(1, 32) - 1;
    uint64 yieldData = uint64ShiftLeft((uint64(reason) & mask16), 32) | (uint64(dataLength) & mask32);
    writeHtifFromhost(a, yieldData);
    // Reset iflags.Y
    writeIflagsY(a, 0);
}

// Explicit instantiation for state_access
template void send_cmio_response(state_access a, bytes32 revertRootHash, uint16_t reason, const unsigned char *data,
    uint32 length);

// Explicit instantiation for record_state_access
template void send_cmio_response(record_send_cmio_state_access a, bytes32 revertRootHash, uint16_t reason,
    const unsigned char *data, uint32 length);

// Explicit instantiation for replay_state_access
template void send_cmio_response(replay_send_cmio_state_access a, bytes32 revertRootHash, uint16_t reason,
    const unsigned char *data, uint32 length);

} // namespace cartesi
// NOLINTEND(google-readability-casting,misc-const-correctness,modernize-use-auto,hicpp-use-auto,readability-use-std-min-max,modernize-avoid-c-style-cast)
