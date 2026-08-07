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

import {Test, console} from "forge-std/Test.sol";

import {StepLog} from "src/StepLog.sol";
import {UArchStep} from "src/UArchStep.sol";

/// Ad-hoc probe for candidate mcycle logs: measures one whole-mcycle replay through
/// UArchStep end to end for the log named by the MCYCLE_PROBE_LOG env var. Skips
/// silently when the var is unset so the suite stays green without it.
/// Usage: record a candidate with tools/record-mcycle.lua, then
///   MCYCLE_PROBE_LOG=test/fixtures/candidate.log forge test --match-contract McycleProbe -vv
/// (the log must live inside the project; forge fs_permissions block outside reads)
contract McycleProbeTest is Test {
    uint256 constant MAX_MCYCLE_CYCLES = 1 << 21;

    function testProbeMcycle() public view {
        string memory path = vm.envOr("MCYCLE_PROBE_LOG", string(""));
        if (bytes(path).length == 0) return;
        bytes memory log = vm.readFileBinary(path);
        uint256 g0 = gasleft();
        (uint256 cycles, uint256 gDecode, uint256 gLoop, uint256 gPost) = this.verifyMcycle(log);
        uint256 total = g0 - gasleft();
        console.log(string.concat("log       ", path));
        console.log(string.concat("bytes     ", vm.toString(log.length)));
        console.log(string.concat("cycles    ", vm.toString(cycles)));
        console.log(string.concat("decode    ", vm.toString(gDecode)));
        console.log(string.concat("loop      ", vm.toString(gLoop)));
        console.log(string.concat("per cycle ", vm.toString(gLoop / cycles)));
        console.log(string.concat("postroot  ", vm.toString(gPost)));
        console.log(string.concat("external  ", vm.toString(total)));
        console.log(string.concat("cap 16777216 fit: ", total <= 16777216 ? "YES" : "NO"));
    }

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
}
