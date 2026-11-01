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

/// Shared witness builders and call boundaries for the replayer tests.
abstract contract StepLogTestBase is Test {
    function contextWithPages(uint64[] memory pageIndices)
        internal
        pure
        returns (StepLog.Context memory ctx)
    {
        ctx.pageIndices = pageIndices;
        ctx.slices = new uint256[](pageIndices.length);
        ctx.sliceData = new bytes(pageIndices.length * EmulatorConstants.PAGE_SIZE);
        ctx.sliceHashes = new bytes32[](pageIndices.length);
        for (uint256 i; i < pageIndices.length; ++i) {
            ctx.slices[i] = StepLog.packSlice(
                pageIndices[i] << EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE,
                EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE,
                i * EmulatorConstants.PAGE_SIZE
            );
        }
    }

    function registerPageContext() internal pure returns (StepLog.Context memory ctx) {
        uint64[] memory pages = new uint64[](1);
        pages[0] = EmulatorConstants.UARCH_HALT_ADDR >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        ctx = contextWithPages(pages);
        ctx.siblings = new bytes32[](
            EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE - EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE
        );
    }

    function collidingPageContext(uint64 base) internal pure returns (StepLog.Context memory) {
        uint64[] memory pages = new uint64[](3);
        for (uint64 i; i < pages.length; ++i) {
            pages[i] = base + i * 61;
        }
        return contextWithPages(pages);
    }

    function maximumPageContext() internal pure returns (StepLog.Context memory) {
        uint64[] memory pages = new uint64[](64);
        for (uint64 i; i < pages.length; ++i) {
            pages[i] = i == 63 ? type(uint64).max >> 12 : i;
        }
        return contextWithPages(pages);
    }

    function physicalBase(uint64 seed) internal pure returns (uint64 base) {
        base = (seed >> 12) % ((uint64(1) << 52) - 183);
        // Keep the three colliding physical pages outside the register alias page.
        uint64 shadow = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        if (base <= shadow && base + 122 >= shadow) base = shadow + 1;
    }

    function compareRevert(bytes memory actualCall, bytes memory referenceCall, bytes memory reason)
        internal
        view
    {
        (bool actualOk, bytes memory actual) = address(this).staticcall(actualCall);
        (bool referenceOk, bytes memory expected) = address(this).staticcall(referenceCall);
        assertFalse(actualOk);
        assertFalse(referenceOk);
        assertEq(actual, expected, "revert mismatch");
        assertEq(actual, reason, "wrong revert");
    }

    function assertCleanRevert(bool ok, bytes memory reason) internal pure {
        assertFalse(ok, "mutated log accepted");
        assertGe(reason.length, 4, "empty revert");
        assertTrue(bytes4(reason) != bytes4(0x4e487b71), "panic instead of explicit rejection");
    }

    function verifyStep(bytes calldata log, bytes32 rootBefore) external pure returns (bytes32) {
        return Verify.verifyStep(StepLog.decode(log), rootBefore);
    }

    function verifyReset(bytes calldata log, bytes32 rootBefore) external pure returns (bytes32) {
        return Verify.verifyReset(StepLog.decode(log), rootBefore);
    }

    function setLE64(bytes memory data, uint256 off, uint64 value) internal pure {
        for (uint256 i; i < 8; ++i) {
            data[off + i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function le64(uint64 value) internal pure returns (bytes memory data) {
        data = new bytes(8);
        setLE64(data, 0, value);
    }

    function le64(bytes calldata data, uint256 off) internal pure returns (uint256 value) {
        for (uint256 i; i < 8; ++i) {
            value |= uint256(uint8(data[off + i])) << (i * 8);
        }
    }
}
