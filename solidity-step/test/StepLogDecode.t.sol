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
import {StepLog} from "src/StepLog.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Decode + structural validation of a real step-log fixture, plus corruption-rejection cases.
contract StepLogDecodeTest is ManifestParser {
    // shadow uarch state at 0x400000 = page 1024; the first cycle of any uarch
    // program touches it, so it is the log's first page.
    uint64 constant EXPECTED_FIRST_PAGE_INDEX =
        EmulatorConstants.AR_SHADOW_UARCH_STATE_START >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;

    bytes fixture;
    bytes32 expectedRootBefore;

    function setUp() public {
        Row memory row;
        (fixture, row) = sampleStepLog();
        expectedRootBefore = row.rootHashBefore;
    }

    /// The sibling cap must cover the slice cap's worst case: a maximally address-spread log can
    /// need one sibling per tree level per slice, so MAX_SIBLING_COUNT >= depth * MAX_SLICE_COUNT.
    function testSiblingCapCoversSliceCap() public pure {
        uint256 depth =
            EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE - EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE;
        assertGe(uint256(StepLog.MAX_SIBLING_COUNT), depth * uint256(StepLog.MAX_SLICE_COUNT));
    }

    /// decode parses the header and exposes a self-consistent context.
    function testDecodeHappy() public view {
        StepLog.Context memory ctx = this.decode(fixture);

        assertEq(
            ctx.hashFunction, EmulatorConstants.HASH_FUNCTION_KECCAK256, "hashFunction keccak256"
        );
        assertEq(
            ctx.rootHashBefore, expectedRootBefore, "recomputed rootHashBefore matches manifest"
        );

        uint256 sliceCount = ctx.pageIndices.length;
        assertGt(sliceCount, 0, "log has slices");
        uint256 contentBytes;
        for (uint256 i; i < sliceCount; ++i) {
            contentBytes += uint256(1) << StepLog.sliceLog2Size(ctx.slices[i]);
        }
        assertEq(ctx.sliceData.length, contentBytes, "sliceData length tracks slice contents");
        assertEq(ctx.sliceHashes.length, sliceCount, "sliceHashes allocated per slice");
        assertEq(ctx.pageIndices[0], EXPECTED_FIRST_PAGE_INDEX, "uarch shadow state page first");
    }

    /// decodeAt returns the offset just past the decoded log.
    function testDecodeAtAdvancesCursor() public view {
        (, uint256 newOff) = this.decodeAt(fixture, 0);
        assertEq(newOff, fixture.length, "cursor advanced past log");
    }

    function testRejectsShortLog() public {
        bytes memory truncated = new bytes(32);
        vm.expectRevert(StepLog.HeaderTruncated.selector);
        this.decodeAt(truncated, 0);
    }

    /// A hostile offset must revert cleanly (HeaderTruncated), not panic on
    /// offset + HEADER_SIZE overflow.
    function testRejectsOverflowingOffset() public {
        vm.expectRevert(StepLog.HeaderTruncated.selector);
        this.decodeAt(fixture, type(uint256).max);
    }

    function testRejectsBadSignature() public {
        bytes memory bad = bytes(fixture);
        bad[0] = 0x00;
        vm.expectRevert(StepLog.InvalidSignature.selector);
        this.decodeAt(bad, 0);
    }

    function testRejectsTruncatedAfterHeader() public {
        // Header says it has slices but we only provide the header.
        bytes memory bad = new bytes(StepLog.HEADER_SIZE);
        for (uint256 i = 0; i < StepLog.HEADER_SIZE; i++) {
            bad[i] = fixture[i];
        }
        vm.expectRevert(StepLog.LogTruncated.selector);
        this.decodeAt(bad, 0);
    }

    /// Decode recomputes the pre-state root, so a tampered slice byte changes it.
    function testTamperedSliceChangesRootBefore() public view {
        bytes memory bad = bytes(fixture);
        // Slice contents start after the complete fixed-stride table.
        StepLog.Context memory original = this.decode(fixture);
        uint256 firstSliceDataOff =
            StepLog.HEADER_SIZE + original.slices.length * StepLog.SLICE_ENTRY_SIZE;
        bad[firstSliceDataOff] = bytes1(uint8(bad[firstSliceDataOff]) ^ 0xff);
        StepLog.Context memory ctx = this.decode(bad);
        assertTrue(
            ctx.rootHashBefore != expectedRootBefore, "tamper must change the recomputed root"
        );
    }

    /// A valid log with junk appended is tolerated by decodeAt (cursor primitive) but
    /// rejected by decode (single-log entrypoint).
    function testDecodeRejectsTrailingBytes() public {
        bytes memory padded = bytes.concat(fixture, hex"deadbeef");
        // decodeAt stops at the end of the log body, leaving the cursor before the buffer end.
        (, uint256 newOff) = this.decodeAt(padded, 0);
        assertEq(newOff, fixture.length, "decodeAt stops at end of log body");
        vm.expectRevert(
            abi.encodeWithSelector(StepLog.TrailingBytes.selector, fixture.length, padded.length)
        );
        this.decode(padded);
    }

    // The three counts occupy the last 24 bytes of the header (slice, node, sibling).
    function testRejectsSliceCountOverCap() public {
        bytes memory bad = bytes(fixture);
        uint64 over = StepLog.MAX_SLICE_COUNT + 1;
        setLE64(bad, StepLog.HEADER_SIZE - 24, over);
        vm.expectRevert(abi.encodeWithSelector(StepLog.SliceCountExceedsLimit.selector, over));
        this.decodeAt(bad, 0);
    }

    function testRejectsNodeCountOverCap() public {
        bytes memory bad = bytes(fixture);
        uint64 over = StepLog.MAX_NODE_COUNT + 1;
        setLE64(bad, StepLog.HEADER_SIZE - 16, over);
        vm.expectRevert(abi.encodeWithSelector(StepLog.NodeCountExceedsLimit.selector, over));
        this.decodeAt(bad, 0);
    }

    function testRejectsSiblingCountOverCap() public {
        bytes memory bad = bytes(fixture);
        uint64 over = StepLog.MAX_SIBLING_COUNT + 1;
        setLE64(bad, StepLog.HEADER_SIZE - 8, over);
        vm.expectRevert(abi.encodeWithSelector(StepLog.SiblingCountExceedsLimit.selector, over));
        this.decodeAt(bad, 0);
    }

    /// Aligned/disjoint wire entries always consume all in-range nodes. Exercise
    /// the defensive leftover-node check directly on an invalid in-memory context:
    /// a root node consumes the whole tree, leaving a second node behind.
    function testRejectsLeftoverNodeInContext() public {
        StepLog.Context memory ctx;
        ctx.nodes = new StepLog.NodeEntry[](2);
        ctx.nodes[0] = StepLog.NodeEntry(0, 64, bytes32(uint256(1)));
        ctx.nodes[1] = StepLog.NodeEntry(0, 13, bytes32(uint256(2)));
        vm.expectRevert(StepLog.TooManyNodes.selector);
        this.computeRoot(ctx);
    }

    function testAssemblyErrorSelectors() public pure {
        assertEq(bytes4(0x245a1128), StepLog.TooFewSiblings.selector);
        assertEq(bytes4(0xabe197a9), StepLog.InvalidSliceSubtree.selector);
        assertEq(bytes4(0x10d24160), StepLog.AccessOutsideSlice.selector);
    }

    function testRejectsLeftoverSliceInContext() public {
        uint64[] memory pages = new uint64[](1);
        StepLog.Context memory ctx = contextWithPages(pages);
        ctx.sliceHashes[0] = bytes32(uint256(1));
        ctx.nodes = new StepLog.NodeEntry[](1);
        ctx.nodes[0] =
            StepLog.NodeEntry(0, EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE, bytes32(uint256(2)));
        vm.expectRevert(StepLog.TooManySlices.selector);
        this.computeRoot(ctx);
    }

    function testRejectsInvalidLeafSubtreeBothWalks() public {
        StepLog.Context memory ctx = contextWithPages(new uint64[](1));
        // The hand-built context deliberately leaves an earlier 32-byte slice unconsumed.
        ctx.slices[0] = StepLog.packSlice(0, 5, 0);
        for (uint256 twin; twin < 2; ++twin) {
            vm.expectRevert(StepLog.InvalidSliceSubtree.selector);
            this.invalidLeafSubtree(ctx, twin != 0);
        }
    }

    function invalidLeafSubtree(StepLog.Context memory ctx, bool twin) external pure {
        StepLog.TreeWalkCursors memory cursors;
        // Start one leaf after the slice: it is before the subtree end, but cannot be consumed.
        if (twin) {
            StepLog.computeSubtreeHashAsm(
                ctx, cursors, 32, EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE
            );
        } else {
            StepLog.computeSubtreeHash(ctx, cursors, 32, EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE);
        }
    }

    function computeRoot(StepLog.Context memory ctx) external pure returns (bytes32) {
        return StepLog.computeRootHash(ctx);
    }

    function decode(bytes calldata data) external pure returns (StepLog.Context memory ctx) {
        return StepLog.decode(data);
    }

    function decodeAt(bytes calldata data, uint256 offset)
        external
        pure
        returns (StepLog.Context memory ctx, uint256 newOff)
    {
        return StepLog.decodeAt(data, offset);
    }
}
