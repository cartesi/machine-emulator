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
import {UArchStep} from "src/UArchStep.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Consolidated gas report, worst case first: whole-mcycle replay of the two corpus
/// champion mcycles through UArchStep (the production interpreter) against the
/// EIP-7825 per-tx cap, then the per-step dispute path. The champion numbers track
/// the production interpreter's distance from verifying a whole mcycle in one
/// transaction -- interpreter improvements and regressions move them directly.
/// Run via `make gas-report` (after `make fixtures` and `make mcycle-fixtures`).
/// One test per measurement so each runs in a fresh EVM frame -- measuring them in
/// one frame lets earlier memory expansion inflate later numbers. The whole-mcycle
/// tests skip with a notice when the champion logs are absent, so the plain suite
/// stays green without them.
contract GasReportTest is ManifestParser {
    uint256 constant EIP7825_CAP = 16777216;
    // runaway guard far above any real mcycle (corpus max 7,449 uarch cycles)
    uint256 constant MAX_MCYCLE_CYCLES = 1 << 21;
    string constant PROGRAM_DIR = "rv64ui-uarch-add";

    function testGasReport1CycleChampion() public view {
        reportMcycle("cycle champion (rv64uc-v-rvc 6527) ", "test/fixtures/worst-mcycle-rvc.log");
    }

    function testGasReport2PageChampion() public view {
        reportMcycle("page champion  (rv64ua-v-lrsc 3791)", "test/fixtures/worst-mcycle-pages.log");
    }

    function testGasReport3SingleStep() public {
        Row[] memory rows = readManifestRows(
            string.concat(UARCH_PER_CYCLE_DIR, "/", PROGRAM_DIR, "/_manifest.csv"), Kind.Cycle
        );
        uint256 totalGas;
        uint256 maxGas;
        uint256 minGas = type(uint256).max;
        for (uint256 j = 0; j < rows.length; j++) {
            bytes memory log = vm.readFileBinary(
                string.concat(UARCH_PER_CYCLE_DIR, "/", PROGRAM_DIR, "/", rows[j].name)
            );
            uint256 g0 = gasleft();
            this.verifyOneCycle(
                log, rows[j].rootHashBefore, rows[j].requestedCycleCount, rows[j].rootHashAfter
            );
            uint256 used = g0 - gasleft();
            totalGas += used;
            if (used > maxGas) maxGas = used;
            if (used < minGas) minGas = used;
        }
        console.log(
            string.concat(
                "single uarch step, Verify.verifyStep (",
                PROGRAM_DIR,
                ", ",
                vm.toString(rows.length),
                " steps):"
            )
        );
        console.log(
            string.concat(
                "  avg ",
                vm.toString(totalGas / rows.length),
                "  min ",
                vm.toString(minGas),
                "  max ",
                vm.toString(maxGas)
            )
        );
    }

    function reportMcycle(string memory label, string memory path) private view {
        if (!vm.exists(path)) {
            console.log(string.concat("  ", label, "  MISSING ", path, " (make mcycle-fixtures)"));
            return;
        }
        bytes memory log = vm.readFileBinary(path);
        uint256 g0 = gasleft();
        (uint256 cycles, uint256 gDecode, uint256 gLoop, uint256 gPost) = this.verifyMcycle(log);
        uint256 total = g0 - gasleft();
        console.log(
            string.concat(
                "  ",
                label,
                "  external ",
                vm.toString(total),
                total <= EIP7825_CAP ? "  cap fit YES" : "  cap fit NO"
            )
        );
        console.log(
            string.concat(
                "      cycles ",
                vm.toString(cycles),
                "  bytes ",
                vm.toString(log.length),
                "  decode ",
                vm.toString(gDecode),
                "  loop ",
                vm.toString(gLoop),
                " (",
                vm.toString(gLoop / cycles),
                "/cycle)",
                "  postroot ",
                vm.toString(gPost)
            )
        );
    }

    /// External self-calls so logs arrive as `bytes calldata` for StepLog.decode.
    /// Replays every uarch cycle of the log through UArchStep until its halt fixed
    /// point, then checks the recomputed post-state root against the header claim.
    function verifyMcycle(bytes calldata log)
        external
        view
        returns (uint256 cycles, uint256 gDecode, uint256 gLoop, uint256 gPost)
    {
        uint256 g0 = gasleft();
        StepLog.Context memory ctx = StepLog.decode(log);
        gDecode = g0 - gasleft();
        g0 = gasleft();
        while (UArchStep.uarchStep(ctx) == UArchStep.UArchStepStatus.Success) {
            cycles++;
            require(cycles <= MAX_MCYCLE_CYCLES, "runaway mcycle replay");
        }
        gLoop = g0 - gasleft();
        g0 = gasleft();
        bytes32 post = StepLog.computeRootHash(ctx, true);
        gPost = g0 - gasleft();
        require(post == ctx.rootHashAfter, "final root mismatch");
    }

    function verifyOneCycle(bytes calldata log, bytes32 before, uint64 cycleCount, bytes32 afterH)
        external
        pure
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, before, cycleCount, afterH);
    }
}
