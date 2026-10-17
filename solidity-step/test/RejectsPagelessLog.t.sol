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

import {Test} from "forge-std/Test.sol";

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

/// A zero-page log with a single root-sized node would stand up a "witnessed tree" that is
/// nothing but one attacker-chosen hash. The page-count guard in decode rejects it.
contract RejectsPagelessLogTest is Test {
    /// Build an 88-byte step log: 40-byte header + one root-sized node, no pages,
    /// no siblings. The single node covers the entire address space (addr 0,
    /// log2Size 64), so it alone would determine the pre-state root.
    function buildSingleRootNodeLog(bytes32 rootBefore) internal pure returns (bytes memory) {
        return abi.encodePacked(
            EmulatorConstants.STEP_LOG_SIGNATURE, // signature (8)
            le64(uint64(EmulatorConstants.HASH_FUNCTION_KECCAK256)), // hash_function (8)
            le64(0), // page_count (8)
            le64(1), // node_count (8)
            le64(0), // sibling_count (8)
            // node entry (48):
            le64(0), // addr
            le64(uint64(EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE)), // log2_size = 64
            rootBefore // hash -> the whole "witnessed tree"
        );
    }

    function testPagelessLogIsRejected() public {
        bytes32 rootBefore = keccak256("arbitrary pre-state");
        bytes memory log = buildSingleRootNodeLog(rootBefore);
        vm.expectRevert(StepLog.PageCountZero.selector);
        this.verifyStep(log, rootBefore);
    }

    function verifyStep(bytes calldata log, bytes32 rootBefore) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore);
    }

    function le64(uint64 v) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}
