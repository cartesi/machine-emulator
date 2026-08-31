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

import {console} from "forge-std/Test.sol";

import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Walks every rv64ui-uarch program (one per-cycle subdirectory, discovered from the
/// directory layout) and replays its per-cycle decomposition one cycle at a time via
/// Verify.verifyStep -- exactly the production dispute shape (one step log per uarchStep
/// call). The (before, after) values come from each cycle row in the per-program manifest --
/// recorded truth, keeping the comparisons non-tautological at the per-cycle granularity.
///
/// The same walk measures gas, so the reported worst case is discovered over every step the
/// corpus contains rather than sampled. Gas metering stays on for it, which is why
/// foundry.toml raises block_gas_limit.
contract VerifyUarchTestsPerCycleTest is ManifestParser {
    function testReplaysAllUarchTestsPerCycle() public {
        string[] memory dirs = programDirs();
        uint256 totalGas;
        uint256 totalSteps;
        uint256 maxGas;
        uint256 minGas = type(uint256).max;
        string memory worst;
        for (uint256 i = 0; i < dirs.length; i++) {
            Row[] memory cycleRows =
                readManifestRows(string.concat(dirs[i], "/_manifest.csv"), Kind.Cycle);
            require(cycleRows.length > 0, "program has no recorded cycles");
            // readDir yields absolute paths; the report only needs the program name.
            string[] memory parts = vm.split(dirs[i], "/");
            string memory program = parts[parts.length - 1];
            // The rows must form one contiguous whole-program replay: each cycle starts where the
            // previous ended. currentRoot threads that chain across the per-cycle logs.
            bytes32 currentRoot = cycleRows[0].rootHashBefore;
            for (uint256 j = 0; j < cycleRows.length; j++) {
                assertEq(cycleRows[j].rootHashBefore, currentRoot, "per-cycle rows must chain");
                bytes memory log = vm.readFileBinary(string.concat(dirs[i], "/", cycleRows[j].name));
                this.verifyOneCycle(log, cycleRows[j].rootHashBefore, cycleRows[j].rootHashAfter);
                uint256 used = vm.lastCallGas().gasTotalUsed;
                totalGas += used;
                totalSteps++;
                if (used < minGas) minGas = used;
                if (used > maxGas) {
                    maxGas = used;
                    worst = string.concat(program, "/", cycleRows[j].name);
                }
                currentRoot = cycleRows[j].rootHashAfter;
            }
        }
        console.log(
            string.concat(
                "  uarch step gas over ",
                vm.toString(dirs.length),
                " programs, ",
                vm.toString(totalSteps),
                " steps:"
            )
        );
        console.log(
            string.concat(
                "    avg ",
                vm.toString(totalGas / totalSteps),
                "  min ",
                vm.toString(minGas),
                "  max ",
                vm.toString(maxGas)
            )
        );
        console.log(string.concat("    worst ", worst));
    }

    /// External self-call so `log` arrives as `bytes calldata` for StepLog.decode, and so
    /// vm.lastCallGas() reports this step alone.
    function verifyOneCycle(bytes calldata log, bytes32 rootBefore, bytes32 rootAfter)
        external
        pure
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        require(Verify.verifyStep(ctx, rootBefore) == rootAfter, "root after mismatch");
    }
}
