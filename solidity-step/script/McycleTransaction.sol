// SPDX-License-Identifier: Apache-2.0
// Measures whole-mcycle verifier gas and transaction admission.
// Fixtures start with pristine uarch state and end after one mcycle.
// Driver: machine-emulator-private/sepolia-admission/driver/
// Keep investigation inputs, receipts and ledgers beside that driver.
pragma solidity ^0.8.30;

import {StateAccess} from "../src/StateAccess.sol";
import {StepLog} from "../src/StepLog.sol";
import {UArchStep} from "../src/UArchStep.sol";
/// Transaction measurement harness; fixture pre-states have pristine uarch state.

contract McycleTransaction {
    function verifyMcycle(bytes calldata log, bytes32 beforeRoot, bytes32 afterRoot, uint64 cycles)
        external
        pure
        returns (bytes32)
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        require(ctx.rootHashBefore == beforeRoot, "before root");
        require(StateAccess.readCycle(ctx) == 0 && StateAccess.readHalt(ctx) == 0, "initial uarch");
        uint64 mcycle = StateAccess.readMcycle(ctx);
        for (uint64 i; i < cycles; ++i) {
            UArchStep.uarchStep(ctx);
        }
        require(
            StateAccess.readHalt(ctx) != 0 && StateAccess.readMcycle(ctx) == mcycle + 1,
            "one mcycle"
        );
        bytes32 afterComputed = StepLog.computeRootHash(ctx);
        require(afterComputed == afterRoot, "after root");
        return afterComputed;
    }
}
