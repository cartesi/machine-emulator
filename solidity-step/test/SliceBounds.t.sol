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
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

contract SliceBoundsTest is Test {
    function testFuzzPackedSliceFields(uint64 addressSeed, uint8 sizeSeed, uint32 offsetSeed)
        public
        pure
    {
        uint64 log2Size = 5 + uint64(sizeSeed % 8);
        uint64 addr = addressSeed & ~((uint64(1) << log2Size) - 1);
        uint256 offset = uint256(offsetSeed) % (64 * 4096);
        uint256 slice = StepLog.packSlice(addr, log2Size, offset);
        assertEq(StepLog.sliceAddress(slice), addr);
        assertEq(StepLog.sliceLog2Size(slice), log2Size);
        assertEq(StepLog.sliceDataOffset(slice), offset);
    }

    function context(uint64 start, uint64 log2Size)
        private
        pure
        returns (StepLog.Context memory ctx)
    {
        ctx.pageIndices = new uint64[](1);
        ctx.pageIndices[0] = start >> 12;
        ctx.slices = new uint256[](1);
        ctx.slices[0] = StepLog.packSlice(start, log2Size, 0);
        ctx.sliceData = new bytes(uint256(1) << log2Size);
        ctx.sliceHashes = new bytes32[](1);
    }

    function access(
        uint64 start,
        uint64 log2Size,
        uint64 target,
        bool write,
        bool warm,
        bool useReference
    ) external pure returns (uint64) {
        StepLog.Context memory ctx = context(start, log2Size);
        if (warm) StateAccess.readWord(ctx, start);
        if (useReference) {
            if (write) StepLog.writeLE64Memory(StepLog.findDataForWrite(ctx, target), 42);
            uint256 ptr = StepLog.findData(ctx, target);
            uint64 result;
            assembly ("memory-safe") {
                result := byte(0, mload(ptr))
            }
            return result;
        }
        if (write) StateAccess.writeWord(ctx, target, 42);
        return StateAccess.readWord(ctx, target);
    }

    function testFuzzColdAndWarmBounds(
        uint8 sizeSeed,
        uint16 offsetSeed,
        bool write,
        bool warm,
        bool useReference
    ) public {
        uint64 log2Size = 5 + uint64(sizeSeed % 8);
        uint64 size = uint64(1) << log2Size;
        uint64 start = 0x80000000 + (uint64(offsetSeed) & 4095 & ~(size - 1));
        assertEq(this.access(start, log2Size, start, write, warm, useReference), write ? 42 : 0);
        assertEq(
            this.access(start, log2Size, start + size - 8, write, warm, useReference),
            write ? 42 : 0
        );
        // Stay in the same enclosing page so a warm cache hit cannot hide missing bytes.
        if ((start & 4095) != 0) {
            vm.expectRevert(StepLog.AccessOutsideSlice.selector);
            this.access(start, log2Size, start - 8, write, warm, useReference);
        }
        if ((start & 4095) + size < 4096) {
            vm.expectRevert(StepLog.AccessOutsideSlice.selector);
            this.access(start, log2Size, start + size, write, warm, useReference);
        }
    }

    function registerWindow(uint64 log2Size) external pure {
        StepLog.Context memory ctx = context(EmulatorConstants.UARCH_HALT_ADDR, log2Size);
        StateAccess.writeX(ctx, 31, 42);
        StepLog.flushUarchRegisters(ctx);
        assertEq(StateAccess.readX(ctx, 31), 42);
        // The format witnesses all 35 registers; the 8 extra bytes in their last leaf must remain untouched.
        for (uint256 i = 280; i < 288; ++i) {
            assertEq(ctx.sliceData[i], bytes1(0));
        }
    }

    function testRegisterWindowMatchesNineLeaves() public {
        assertEq(EmulatorConstants.UARCH_REGISTER_WORD_COUNT, 35);
        assertEq((EmulatorConstants.UARCH_REGISTER_WORD_COUNT * 8 + 31) / 32, 9);
        vm.expectRevert(StepLog.AccessOutsideSlice.selector);
        this.registerWindow(8);
        this.registerWindow(9);
    }

    function paddedWrite(uint64 log2Size, uint32 writeLengthLog2Size, bool warm) external view {
        StepLog.Context memory ctx = context(0x80000000, log2Size);
        if (warm) StateAccess.writeWord(ctx, 0x80000000, 7);
        this.writePadded(ctx, writeLengthLog2Size, hex"01");
    }

    function writePadded(StepLog.Context memory ctx, uint32 log2Size, bytes calldata data)
        external
        pure
    {
        StateAccess.writeMemoryWithPadding(ctx, 0x80000000, data, 1, log2Size);
    }

    function testPaddedWriteChecksFullRange() public {
        for (uint256 warm; warm < 2; ++warm) {
            this.paddedWrite(9, 9, warm != 0);
            vm.expectRevert(StepLog.AccessOutsideSlice.selector);
            this.paddedWrite(9, 10, warm != 0);
        }
    }

    function tlbOutside(bool warm) external pure {
        StepLog.Context memory ctx = context(0x1000, 5);
        if (warm) StateAccess.writeTlbECALL(ctx, 0, 0, 1, 2, 3);
        StateAccess.writeTlbECALL(ctx, 0, 1, 1, 2, 3);
    }

    function testTlbWriteChecksSliceOnCacheHit() public {
        vm.expectRevert(StepLog.AccessOutsideSlice.selector);
        this.tlbOutside(false);
        vm.expectRevert(StepLog.AccessOutsideSlice.selector);
        this.tlbOutside(true);
    }
}
