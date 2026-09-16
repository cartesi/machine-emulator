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

library UArchReset {
    function uarchResetState(StepLog.Context memory a) internal pure {
        StateAccess.resetState(a);
        // When the machine has rejected an input, the canonical state after the operation is
        // the one recorded in the revert root hash (which has a pristine uarch)
        uint64 iflagsY = StateAccess.readWord(a, EmulatorConstants.IFLAGS_Y_ADDRESS);
        if (iflagsY != 0) {
            uint64 tohost = StateAccess.readWord(a, EmulatorConstants.HTIF_TOHOST_ADDRESS);
            if (
                StateAccess.isYieldedManualWith(
                    tohost, EmulatorConstants.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
                )
            ) {
                StateAccess.revertState(a);
            }
        }
    }
}
