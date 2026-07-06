// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StepLog} from "src/StepLog.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Decode + structural validation of a real step-log fixture, plus corruption-rejection cases.
contract StepLogDecodeTest is ManifestParser {
    // shadow uarch state at 0x400000 = page 1024; the first cycle of any uarch
    // program touches it, so it is the log's first page.
    uint64 constant EXPECTED_FIRST_PAGE_INDEX = 1024;

    bytes fixture;
    uint64 expectedCycleCount;
    bytes32 expectedRootBefore;
    bytes32 expectedRootAfter;

    function setUp() public {
        Row memory row;
        (fixture, row) = sampleStepLog();
        expectedCycleCount = row.requestedCycleCount;
        expectedRootBefore = row.rootHashBefore;
        expectedRootAfter = row.rootHashAfter;
    }

    /// The sibling cap must cover the page cap's worst case: a maximally address-spread log can
    /// need one sibling per tree level per page, so MAX_SIBLING_COUNT >= depth * MAX_PAGE_COUNT.
    function testSiblingCapCoversPageCap() public pure {
        uint256 depth =
            EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE - EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        assertGe(uint256(StepLog.MAX_SIBLING_COUNT), depth * uint256(StepLog.MAX_PAGE_COUNT));
    }

    /// decode parses the header and exposes a self-consistent context.
    function testDecodeHappy() public view {
        StepLog.Context memory ctx = this.decode(fixture);

        assertEq(
            ctx.requestedCycleCount, expectedCycleCount, "requestedCycleCount matches manifest"
        );
        assertEq(ctx.hashFunction, 0, "hashFunction keccak256");
        assertEq(ctx.rootHashBefore, expectedRootBefore, "rootHashBefore matches manifest");
        assertEq(ctx.rootHashAfter, expectedRootAfter, "rootHashAfter matches manifest");

        uint256 pageCount = ctx.pageIndices.length;
        assertGt(pageCount, 0, "log has pages");
        assertEq(ctx.pageData.length, pageCount * 4096, "pageData length tracks pageCount");
        assertEq(ctx.pageHashes.length, pageCount, "pageHashes allocated per page");
        assertEq(ctx.pageIndices[0], EXPECTED_FIRST_PAGE_INDEX, "uarch shadow state page first");

        assertTrue(ctx.rootHashBefore != ctx.rootHashAfter, "step changed the root");
    }

    /// decodeAt returns the offset just past the decoded log.
    function testDecodeAtAdvancesCursor() public view {
        (, uint256 newOff) = this.decodeAt(fixture, 0);
        assertEq(newOff, fixture.length, "cursor advanced past log");
    }

    function testRejectsShortLog() public {
        bytes memory truncated = new bytes(50);
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
        // Header says it has pages but we only provide the header.
        bytes memory bad = new bytes(StepLog.HEADER_SIZE);
        for (uint256 i = 0; i < StepLog.HEADER_SIZE; i++) {
            bad[i] = fixture[i];
        }
        vm.expectRevert(StepLog.LogTruncated.selector);
        this.decodeAt(bad, 0);
    }

    /// Decoding verifies pre-state Merkle integrity, so a tampered page byte must reject.
    function testRejectsTamperedPage() public {
        bytes memory bad = bytes(fixture);
        // First page data starts after the header + the 8-byte page index.
        uint256 firstPageDataOff = StepLog.HEADER_SIZE + 8;
        bad[firstPageDataOff] = bytes1(uint8(bad[firstPageDataOff]) ^ 0xff);
        vm.expectRevert(StepLog.InitialRootHashMismatch.selector);
        this.decodeAt(bad, 0);
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

    // The three counts occupy the last 24 bytes of the header (page, node, sibling).
    function testRejectsPageCountOverCap() public {
        bytes memory bad = bytes(fixture);
        uint64 over = StepLog.MAX_PAGE_COUNT + 1;
        setLE64(bad, StepLog.HEADER_SIZE - 24, over);
        vm.expectRevert(abi.encodeWithSelector(StepLog.PageCountExceedsLimit.selector, over));
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

    function setLE64(bytes memory b, uint256 off, uint64 v) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            b[off + i] = bytes1(uint8(v >> (8 * i)));
        }
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
