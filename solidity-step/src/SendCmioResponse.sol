// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/// @dev This file is generated from C++ by solidity-step/tools/transpile-uarch.lua

pragma solidity ^0.8.30;

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

library SendCmioResponse {
    function sendCmioResponse(
        StepLog.Context memory a,
        bytes32 revertRootHash,
        uint16 reason,
        bytes calldata data,
        uint32 dataLength
    ) internal pure {
        // This function cannot fail. When a failure is detected, the operation is a no-op instead,
        // so the honest party can always log and prove the resulting state transition.
        // A response to a machine that is not waiting on a manual yield is a no-op.
        if (!StateAccess.readIflagsY(a)) {
            return;
        }
        if (reason == EmulatorConstants.HTIF_YIELD_REASON_ADVANCE_STATE) {
            // Advance-state responses are the input boundary of the rollups flow. They only apply to a
            // machine waiting for an input on an rx-accepted manual yield. Sending one to a machine that
            // yielded manual with any other reason (e.g., rejected an input or threw an exception) is a no-op.
            uint64 tohost = StateAccess.readHtifTohost(a);
            if (
                !StateAccess.isYieldedManualWith(
                    tohost, EmulatorConstants.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
                )
            ) {
                return;
            }
        }
        // A zero length data is a valid response. We just skip writing to the rx buffer.
        uint32 writeLengthLog2Size = 0;
        if (dataLength > 0) {
            // Find the write length: the smallest power of 2 that is >= dataLength and >= tree leaf size
            writeLengthLog2Size = StateAccess.uint32Log2(dataLength);
            if (writeLengthLog2Size < EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE) {
                writeLengthLog2Size = EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE; // minimum write size is the tree leaf size
            }
            if (StateAccess.uint32ShiftLeft(1, writeLengthLog2Size) < dataLength) {
                writeLengthLog2Size += 1;
            }
            // A response with data that does not fit in the rx buffer is a no-op
            if (writeLengthLog2Size > EmulatorConstants.AR_CMIO_RX_BUFFER_LOG2_SIZE) {
                return;
            }
        }
        // Record the machine root hash to revert to in case the response is eventually rejected. A consumer
        // recovers it from the uarch-reset step log (whose reset accesses this slot) to revert to this state
        // if the response is later rejected.
        StateAccess.writeRevertRootHash(a, revertRootHash);
        if (dataLength > 0) {
            StateAccess.writeMemoryWithPadding(
                a, EmulatorConstants.AR_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size
            );
        }
        // Write data length and reason to fromhost
        uint64 mask16 = StateAccess.uint64ShiftLeft(1, 16) - 1;
        uint64 mask32 = StateAccess.uint64ShiftLeft(1, 32) - 1;
        uint64 yieldData = StateAccess.uint64ShiftLeft((uint64(reason) & mask16), 32)
            | (uint64(dataLength) & mask32);
        StateAccess.writeHtifFromhost(a, yieldData);
        // Reset iflags.Y
        StateAccess.writeIflagsY(a, 0);
    }
}
