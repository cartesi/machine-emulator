// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";

import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Walks every rv64ui-uarch program (one per-cycle subdirectory, discovered from the
/// directory layout) and replays its per-cycle decomposition one cycle at a time via
/// Verify.verifyStep -- exactly the production dispute shape (one step log per uarchStep
/// call). The (before, after) values come from each cycle row in the per-program manifest,
/// giving real (non-tautological) Layer 2 coverage at the per-cycle granularity.
contract VerifyUarchTestsPerCycleTest is ManifestParser {
    function testReplaysAllUarchTestsPerCycle() public {
        string[] memory dirs = programDirs();
        vm.pauseGasMetering();
        for (uint256 i = 0; i < dirs.length; i++) {
            console.log("Replaying per-cycle:", dirs[i]);
            Row[] memory cycleRows =
                readManifestRows(string.concat(dirs[i], "/_manifest.csv"), Kind.Cycle);
            require(cycleRows.length > 0, "program has no recorded cycles");
            // The rows must form one contiguous whole-program replay: each cycle starts where the
            // previous ended. currentRoot threads that chain across the per-cycle logs.
            bytes32 currentRoot = cycleRows[0].rootHashBefore;
            for (uint256 j = 0; j < cycleRows.length; j++) {
                assertEq(cycleRows[j].rootHashBefore, currentRoot, "per-cycle rows must chain");
                bytes memory log = vm.readFileBinary(string.concat(dirs[i], "/", cycleRows[j].name));
                this.verifyOneCycle(
                    log,
                    cycleRows[j].rootHashBefore,
                    cycleRows[j].requestedCycleCount,
                    cycleRows[j].rootHashAfter
                );
                currentRoot = cycleRows[j].rootHashAfter;
            }
        }
    }

    /// External self-call so `log` arrives as `bytes calldata` for StepLog.decode.
    function verifyOneCycle(
        bytes calldata log,
        bytes32 rootBefore,
        uint64 cycleCount,
        bytes32 rootAfter
    ) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore, cycleCount, rootAfter);
    }
}
