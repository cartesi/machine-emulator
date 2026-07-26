// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {UArchStep} from "src/UArchStep.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// A uarch step at a fixed point executes nothing and reports a status instead of advancing:
/// CycleOverflow at the cycle ceiling, UArchHalted when halted. (The trapping instructions --
/// illegal / ebreak / unsupported ecall -- are exercised by the reject fixtures.)
contract UarchFixedPointTest is ManifestParser {
    bytes stepLog;

    function setUp() public {
        (stepLog,) = sampleStepLog();
    }

    function testCycleOverflowIsFixedPoint() public view {
        assertEq(
            this.stepStatusAtCycleCeiling(stepLog),
            uint8(UArchStep.UArchStepStatus.UArchCycleOverflow)
        );
    }

    function testHaltedIsFixedPoint() public view {
        assertEq(this.stepStatusWhenHalted(stepLog), uint8(UArchStep.UArchStepStatus.UArchHalted));
    }

    function stepStatusAtCycleCeiling(bytes calldata log) external pure returns (uint8) {
        StepLog.Context memory ctx = StepLog.decode(log);
        StateAccess.writeCycle(ctx, EmulatorConstants.UARCH_CYCLE_MAX);
        return uint8(UArchStep.uarchStep(ctx));
    }

    function stepStatusWhenHalted(bytes calldata log) external pure returns (uint8) {
        StepLog.Context memory ctx = StepLog.decode(log);
        StateAccess.writeHalt(ctx, 1);
        return uint8(UArchStep.uarchStep(ctx));
    }
}
