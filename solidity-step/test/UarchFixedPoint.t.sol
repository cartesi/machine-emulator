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

    function testRecordedLastCycle() public {
        checkLastCycle("last-cycle.log", false);
    }

    function testRecordedHaltOnLastCycle() public {
        checkLastCycle("last-cycle-halt.log", true);
    }

    function checkLastCycle(string memory name, bool halted) private {
        Row memory row =
            findManifestRowByName("test/fixtures/uarch-multi-cycle/_manifest.csv", Kind.Cycle, name);
        bytes memory log =
            vm.readFileBinary(string.concat("test/fixtures/uarch-multi-cycle/", name));
        assertEq(row.requestedCycleCount, 1);
        assertEq(this.verifyStep(log, row.rootHashBefore), row.rootHashAfter);
        this.checkLastCycleState(log, halted);
    }

    function checkLastCycleState(bytes calldata log, bool halted) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        assertEq(StateAccess.readCycle(ctx), EmulatorConstants.UARCH_CYCLE_MAX - 1);
        UArchStep.uarchStep(ctx);
        assertEq(StateAccess.readCycle(ctx), EmulatorConstants.UARCH_CYCLE_MAX);
        assertEq(StateAccess.readHalt(ctx), halted ? 1 : 0);
    }

    function testCycleOverflowIsFixedPoint() public view {
        assertEq(
            this.stepStatusAtCycleCeiling(stepLog, false),
            uint8(UArchStep.UArchStepStatus.UArchCycleOverflow)
        );
    }

    function testHaltedAtCycleCeilingIsFixedPoint() public view {
        assertEq(
            this.stepStatusAtCycleCeiling(stepLog, true),
            uint8(UArchStep.UArchStepStatus.UArchCycleOverflow)
        );
    }

    function testHaltedIsFixedPoint() public view {
        assertEq(this.stepStatusWhenHalted(stepLog), uint8(UArchStep.UArchStepStatus.UArchHalted));
    }

    function stepStatusAtCycleCeiling(bytes calldata log, bool halted)
        external
        pure
        returns (uint8)
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        StateAccess.writeCycle(ctx, EmulatorConstants.UARCH_CYCLE_MAX);
        StateAccess.writeHalt(ctx, halted ? 1 : 0);
        ctx.rootHashBefore = StepLog.computeRootHash(ctx);
        uint8 status = uint8(UArchStep.uarchStep(ctx));
        assertEq(StepLog.computeRootHash(ctx), ctx.rootHashBefore, "fixed point changed state");
        return status;
    }

    function stepStatusWhenHalted(bytes calldata log) external pure returns (uint8) {
        StepLog.Context memory ctx = StepLog.decode(log);
        StateAccess.writeHalt(ctx, 1);
        ctx.rootHashBefore = StepLog.computeRootHash(ctx);
        uint8 status = uint8(UArchStep.uarchStep(ctx));
        assertEq(StepLog.computeRootHash(ctx), ctx.rootHashBefore, "fixed point changed state");
        return status;
    }
}
