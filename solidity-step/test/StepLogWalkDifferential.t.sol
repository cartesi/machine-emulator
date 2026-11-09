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
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StepLog} from "src/StepLog.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Keep the assembly walk equivalent to the readable recursion, including cursor
/// consumption and the current (possibly rewritten) hash in every NodeEntry.
contract StepLogWalkDifferentialTest is ManifestParser {
    uint8 constant ROOT_LOG2_SIZE = EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE;

    function testWalkTwinMatchesReferenceOnAllFixtures() public {
        vm.pauseGasMetering();
        uint256 count;
        string[] memory dirs = programDirs();
        for (uint256 i; i < dirs.length; ++i) {
            count += runDir(dirs[i], Kind.Cycle);
        }
        count += runDir("test/fixtures/reset-uarch", Kind.ResetUarch);
        count += runDir("test/fixtures/send-cmio-response", Kind.SendCmioResponse);
        assertGt(count, 0, "no walk fixtures");
        console.log("walk differential fixture logs", count);
    }

    function runDir(string memory dir, Kind kind) private returns (uint256 count) {
        Row[] memory rows = readManifestRows(string.concat(dir, "/_manifest.csv"), kind);
        for (uint256 j; j < rows.length; ++j) {
            this.assertWalksAgree(vm.readFileBinary(string.concat(dir, "/", rows[j].name)));
            ++count;
        }
    }

    function assertWalksAgree(bytes calldata log) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        assertEq(compareWalks(ctx, 0, ROOT_LOG2_SIZE), ctx.rootHashBefore, "decoded root");
        // Replay rewrites slice and node hash slots in place; perturb them so the walks
        // are compared on non-decoded hashes.
        for (uint256 i; i < ctx.sliceHashes.length; ++i) {
            ctx.sliceHashes[i] = keccak256(abi.encode(ctx.sliceHashes[i], i));
        }
        for (uint256 i; i < ctx.nodes.length; ++i) {
            ctx.nodes[i].hash = keccak256(abi.encode(ctx.nodes[i].hash, i));
        }
        compareWalks(ctx, 0, ROOT_LOG2_SIZE);
    }

    function compareWalks(StepLog.Context memory ctx, uint64 addr, uint8 log2Size)
        private
        pure
        returns (bytes32 expected)
    {
        bytes32 inputBefore = keccak256(
            abi.encode(ctx.pageIndices, ctx.slices, ctx.sliceHashes, ctx.nodes, ctx.siblings)
        );
        StepLog.TreeWalkCursors memory cRef;
        StepLog.TreeWalkCursors memory cAsm;
        expected = StepLog.computeSubtreeHash(ctx, cRef, addr, log2Size);
        bytes32 actual = StepLog.computeSubtreeHashAsm(ctx, cAsm, addr, log2Size);
        uint256 zeroSlot;
        assembly ("memory-safe") {
            zeroSlot := mload(0x60)
        }
        assertEq(actual, expected, "walk root");
        assertEq(cAsm.nextSlice, cRef.nextSlice, "slice cursor");
        assertEq(cAsm.nextNode, cRef.nextNode, "node cursor");
        assertEq(cAsm.nextSibling, cRef.nextSibling, "sibling cursor");
        assertEq(zeroSlot, 0, "zero slot");
        assertEq(
            keccak256(
                abi.encode(ctx.pageIndices, ctx.slices, ctx.sliceHashes, ctx.nodes, ctx.siblings)
            ),
            inputBefore,
            "walk changed input arrays"
        );
        // An allocation after the recursive walk must remain independent of its state.
        bytes memory later = new bytes(96);
        for (uint256 i; i < later.length; ++i) {
            assertEq(later[i], bytes1(0), "subsequent allocation");
        }
    }

    function testWalkTwinRevertsOnMissingSibling() public {
        (bytes memory log,) = sampleStepLog();
        for (uint256 mode; mode < 2; ++mode) {
            vm.expectRevert(StepLog.TooFewSiblings.selector);
            this.walkWithoutSiblings(log, mode != 0, false);
            vm.expectRevert(StepLog.TooFewSiblings.selector);
            this.walkWithoutSiblings(log, mode != 0, true);
        }
    }

    function walkWithoutSiblings(bytes calldata log, bool useTwin, bool truncateLast)
        external
        pure
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        StepLog.TreeWalkCursors memory c;
        if (truncateLast) {
            bytes32[] memory fewer = new bytes32[](ctx.siblings.length - 1);
            for (uint256 i; i < fewer.length; ++i) {
                fewer[i] = ctx.siblings[i];
            }
            ctx.siblings = fewer;
        } else {
            c.nextSibling = ctx.siblings.length;
        }
        if (useTwin) {
            StepLog.computeSubtreeHashAsm(ctx, c, 0, ROOT_LOG2_SIZE);
        } else {
            StepLog.computeSubtreeHash(ctx, c, 0, ROOT_LOG2_SIZE);
        }
    }

    function testFuzzWalkWithBoundaryPagesAndNodes(bytes32 seed) public pure {
        StepLog.Context memory ctx;
        ctx.pageIndices = new uint64[](4);
        ctx.pageIndices[0] = 0;
        ctx.pageIndices[1] = 1;
        ctx.pageIndices[2] = uint64(1) << 51;
        ctx.pageIndices[3] = (uint64(1) << 52) - 1;
        ctx = contextWithPages(ctx.pageIndices);
        for (uint256 i; i < ctx.slices.length; ++i) {
            uint64 log2Size = 5 + uint64(uint256(seed) >> (i * 8)) % 8;
            uint64 addr = StepLog.sliceAddress(ctx.slices[i])
                | (uint64(uint256(seed) >> (i * 16)) & (4095 ^ ((uint64(1) << log2Size) - 1)));
            ctx.slices[i] =
                StepLog.packSlice(addr, log2Size, StepLog.sliceDataOffset(ctx.slices[i]));
        }
        for (uint256 i; i < ctx.sliceHashes.length; ++i) {
            ctx.sliceHashes[i] = keccak256(abi.encode(seed, i));
        }
        // Adjacent, disjoint nodes immediately after the first two pages. Different
        // sizes exercise both the node match and descent paths; other pages span
        // the root's two halves and include the last physical page.
        ctx.nodes = new StepLog.NodeEntry[](2);
        ctx.nodes[0] = StepLog.NodeEntry(0x2000, 13, seed);
        ctx.nodes[1] = StepLog.NodeEntry(0x4000, 14, ~seed);
        ctx.siblings = new bytes32[](256);
        for (uint256 i; i < ctx.siblings.length; ++i) {
            ctx.siblings[i] = keccak256(abi.encode(i, seed));
        }
        compareWalks(ctx, 0, ROOT_LOG2_SIZE);
    }

    function testRootNodeAndEmptySubtree() public pure {
        StepLog.Context memory ctx;
        ctx = contextWithPages(new uint64[](0));
        ctx.nodes = new StepLog.NodeEntry[](1);
        ctx.nodes[0] = StepLog.NodeEntry(0, 64, bytes32(uint256(0x1234)));
        ctx.siblings = new bytes32[](1);
        ctx.siblings[0] = bytes32(uint256(0x5678));
        assertEq(compareWalks(ctx, 0, ROOT_LOG2_SIZE), ctx.nodes[0].hash, "root node");
        ctx.nodes = new StepLog.NodeEntry[](0);
        assertEq(compareWalks(ctx, 0, ROOT_LOG2_SIZE), ctx.siblings[0], "empty root");
        assertEq(compareWalks(ctx, type(uint64).max & ~uint64(31), 5), ctx.siblings[0], "last leaf");
    }
}
