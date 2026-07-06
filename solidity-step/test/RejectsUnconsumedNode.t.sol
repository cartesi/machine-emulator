// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

/// A zero-page log with a single root-sized node could fold an arbitrary post-state root directly.
/// Two layered defenses reject it: the page-count guard in decode and the unconsumed-node check.
contract RejectsUnconsumedNodeTest is Test {
    /// Build a 192-byte step log: 112-byte header + one root-sized node, no pages,
    /// no siblings. The single node covers the entire address space (addr 0,
    /// log2Size 64), so it alone determines both the pre- and post-state roots.
    function buildSingleRootNodeLog(bytes32 rootBefore, bytes32 rootAfter)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            EmulatorConstants.STEP_LOG_SIGNATURE, // signature (8)
            rootBefore, // root_hash_before (32)
            le64(0), // requested_cycle_count (8)
            rootAfter, // root_hash_after (32)
            le64(uint64(EmulatorConstants.HASH_FUNCTION_KECCAK256)), // hash_function (8)
            le64(0), // page_count (8)
            le64(1), // node_count (8)
            le64(0), // sibling_count (8)
            // node entry (80):
            le64(0), // addr
            le64(uint64(EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE)), // log2_size = 64
            rootBefore, // hash_before  -> makes the pre-state root match
            rootAfter // hash_after   -> attacker-chosen post-state root
        );
    }

    /// A zero-cycle "step" must be a no-op: post root == pre root. A single root-sized node
    /// could carry an arbitrary, unrelated post root, but such a log witnesses no pages, so
    /// decode rejects it at the page-count guard before the unconsumed-node check is reached.
    function testForgedZeroCycleTransitionIsRejected() public {
        bytes32 rootBefore = keccak256("arbitrary pre-state");
        bytes32 rootAfter = keccak256("forged unrelated post-state");
        assertTrue(rootBefore != rootAfter, "roots must differ to prove the forgery");

        bytes memory log = buildSingleRootNodeLog(rootBefore, rootAfter);
        vm.expectRevert(StepLog.PageCountZero.selector);
        this.verifyStep(log, rootBefore, 0, rootAfter);
    }

    function verifyStep(
        bytes calldata log,
        bytes32 rootBefore,
        uint64 cycleCount,
        bytes32 rootAfter
    ) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore, cycleCount, rootAfter);
    }

    function le64(uint64 v) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}
