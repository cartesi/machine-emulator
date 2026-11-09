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

import {StepLogTestBase} from "./StepLogTestBase.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

contract StateAccessCacheTest is StepLogTestBase {
    function testFuzzByteSwap(uint64 value) public pure {
        uint64 expected;
        for (uint256 i; i < 8; ++i) {
            expected = (expected << 8) | uint8(value >> (i * 8));
        }
        assertEq(StepLog.swapBytes64(value), expected);
        assertEq(StepLog.swapBytes64(expected), value);
    }

    function testFuzzWordSerializationPreservesNeighbors(uint64 value, uint16 slot) public pure {
        StepLog.Context memory ctx = collidingPages();
        uint256 offset = uint256(slot % 512) * 8;
        for (uint256 i; i < 32; ++i) {
            ctx.sliceData[(offset & ~uint256(31)) + i] = bytes1(uint8(i + 1));
        }
        bytes memory expected = abi.encodePacked(ctx.sliceData);
        for (uint256 i; i < 8; ++i) {
            expected[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
        StateAccess.writeWord(ctx, uint64(offset), value);
        assertEq(StateAccess.readWord(ctx, uint64(offset)), value);
        assertEq(keccak256(ctx.sliceData), keccak256(expected));
    }

    function testCacheLastPositionAndMaximumPhysicalPage() public pure {
        StepLog.Context memory ctx = maximumPageContext();
        for (uint64 i; i < 64; ++i) {
            uint64 paddr = (ctx.pageIndices[i] << 12) | 4088;
            StateAccess.writeWord(ctx, paddr, 100 + i);
            assertEq(StateAccess.readWord(ctx, paddr), 100 + i);
        }
        for (uint64 i; i < 64; ++i) {
            assertEq(StateAccess.readWord(ctx, (ctx.pageIndices[i] << 12) | 4088), 100 + i);
        }
    }

    function checkTlbSlot(
        uint64 setIndex,
        uint64 slotIndex,
        uint64 vaddrPage,
        uint64 vpOffset,
        uint64 pmaIndex
    ) private pure {
        uint64 slotAddr = EmulatorConstants.AR_SHADOW_TLB_START
            + setIndex * EmulatorConstants.SHADOW_TLB_SET_LENGTH
            + slotIndex * EmulatorConstants.SHADOW_TLB_SLOT_SIZE;
        StepLog.Context memory ctx;
        ctx.pageIndices = new uint64[](1);
        ctx.pageIndices[0] = slotAddr >> 12;
        ctx = contextWithPages(ctx.pageIndices);
        ctx.sliceHashes[0] = bytes32(uint256(1));
        uint256 offset = slotAddr & 4095;
        for (uint256 i; i < 64; ++i) {
            ctx.sliceData[(offset & ~uint256(63)) + i] = bytes1(uint8(i + 1));
        }
        bytes memory expected = abi.encodePacked(ctx.sliceData);
        uint64[4] memory values = [vaddrPage, vpOffset, pmaIndex, uint64(0)];
        for (uint256 field; field < 4; ++field) {
            for (uint256 i; i < 8; ++i) {
                expected[offset + field * 8 + i] = bytes1(uint8(values[field] >> (i * 8)));
            }
        }
        StateAccess.writeTlbECALL(ctx, setIndex, slotIndex, vaddrPage, vpOffset, pmaIndex);
        assertEq(keccak256(ctx.sliceData), keccak256(expected));
        assertEq(ctx.sliceHashes[0], bytes32(0));
    }

    function testFuzzTlbSlotSerialization(
        uint8 setIndex,
        uint16 slotIndex,
        uint64 vaddrPage,
        uint64 vpOffset,
        uint64 pmaIndex
    ) public pure {
        checkTlbSlot(
            uint64(setIndex) % EmulatorConstants.TLB_SET_COUNT,
            uint64(slotIndex) % EmulatorConstants.TLB_SET_SIZE,
            vaddrPage,
            vpOffset,
            pmaIndex
        );
    }

    function testTlbSlotsAtPageBoundaries() public pure {
        for (uint64 setIndex; setIndex < EmulatorConstants.TLB_SET_COUNT; ++setIndex) {
            checkTlbSlot(setIndex, 0, 0x123456789abcdef0, 0xfedcba9876543210, 7);
            checkTlbSlot(setIndex, 127, type(uint64).max, 0, 0);
            checkTlbSlot(setIndex, 128, 0, type(uint64).max, type(uint64).max);
            checkTlbSlot(setIndex, 255, type(uint64).max, 0, 0);
        }
    }

    function registerContext() private pure returns (StepLog.Context memory ctx) {
        ctx = registerPageContext();
        ctx.sliceData[280] = 0xa5;
        ctx.sliceData[4095] = 0x7e;
        ctx.nodes = new StepLog.NodeEntry[](0);
        ctx.siblings = new bytes32[](52);
    }

    function rawRegisterWrite(StepLog.Context memory ctx, uint8 reg, uint64 value) private pure {
        uint256 offset = EmulatorConstants.UARCH_X_BASE_ADDR - EmulatorConstants.UARCH_HALT_ADDR
            + uint256(reg) * 8;
        for (uint256 i; i < 8; ++i) {
            ctx.sliceData[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
        ctx.sliceHashes[0] = bytes32(0);
    }

    function testFuzzRegisterAliasesAndRepeatedRoots(uint8 reg, uint64 first, uint64 second)
        public
        pure
    {
        reg %= EmulatorConstants.UARCH_X_REG_COUNT;
        StepLog.Context memory ctx = registerContext();
        StepLog.Context memory expected = registerContext();
        uint64 addr = EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8;
        bytes32 initial = StepLog.computeRootHash(ctx);
        assertEq(StateAccess.readX(ctx, reg), 0);
        assertEq(StepLog.computeRootHash(ctx), initial);

        StateAccess.writeX(ctx, reg, first);
        assertEq(StateAccess.readWord(ctx, addr), first);
        assertEq(ctx.sliceHashes[0], bytes32(0));
        rawRegisterWrite(expected, reg, first);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.sliceData), keccak256(expected.sliceData));

        StateAccess.writeWord(ctx, addr, second);
        assertEq(StateAccess.readX(ctx, reg), second);
        rawRegisterWrite(expected, reg, second);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.sliceData), keccak256(expected.sliceData));
    }

    function testRawPointerReadFlushesRegisters() public pure {
        StepLog.Context memory ctx = registerContext();
        StateAccess.writeX(ctx, 1, 0x123456789abcdef0);
        uint256 ptr = StepLog.findData(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + 8);
        uint64 raw;
        assembly ("memory-safe") {
            raw := shr(192, mload(ptr))
        }
        assertEq(raw, 0xf0debc9a78563412);
        assertEq(StateAccess.readX(ctx, 1), 0x123456789abcdef0);
    }

    function testFuzzRegisterCacheEndPreservesFollowingWord(
        uint64 registerValue,
        uint64 followingValue
    ) public pure {
        StepLog.Context memory ctx = registerContext();
        StepLog.Context memory expected = registerContext();
        uint8 lastReg = EmulatorConstants.UARCH_X_REG_COUNT - 1;
        uint64 followingAddr =
            EmulatorConstants.UARCH_X_BASE_ADDR + uint64(EmulatorConstants.UARCH_X_REG_COUNT) * 8;

        StateAccess.writeX(ctx, lastReg, registerValue);
        // The following word must use page bytes and flush the pending register write.
        StateAccess.writeWord(ctx, followingAddr, followingValue);
        assertEq(StateAccess.readX(ctx, lastReg), registerValue);
        StateAccess.writeX(ctx, lastReg, ~registerValue);
        assertEq(StateAccess.readWord(ctx, followingAddr), followingValue);

        rawRegisterWrite(expected, lastReg, ~registerValue);
        uint256 offset = followingAddr - EmulatorConstants.UARCH_HALT_ADDR;
        for (uint256 i; i < 8; ++i) {
            expected.sliceData[offset + i] = bytes1(uint8(followingValue >> (i * 8)));
        }
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.sliceData), keccak256(expected.sliceData));
    }

    function testRawPointerWriteInvalidatesRegisters() public pure {
        StepLog.Context memory ctx = registerContext();
        StateAccess.writeX(ctx, 1, 42);
        uint256 ptr = StepLog.findDataForWrite(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + 8);
        assembly ("memory-safe") {
            mstore8(ptr, 99)
        }
        assertEq(StateAccess.readX(ctx, 1), 99);
        StateAccess.writeX(ctx, 2, 123);
        StepLog.Context memory expected = registerContext();
        rawRegisterWrite(expected, 1, 99);
        rawRegisterWrite(expected, 2, 123);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.sliceData), keccak256(expected.sliceData));
    }

    function collidingPages() private pure returns (StepLog.Context memory) {
        return collidingPageContext(0);
    }

    function testCollisionsAndPageZero() public pure {
        StepLog.Context memory ctx = collidingPages();
        for (uint64 i; i < 3; ++i) {
            StateAccess.writeWord(ctx, (i * 61 << 12) + 4088, 100 + i);
        }
        for (uint64 i; i < 3; ++i) {
            assertEq(StateAccess.readWord(ctx, (i * 61 << 12) + 4088), 100 + i);
            assertEq(StateAccess.readWord(ctx, i * 61 << 12), 0);
        }
    }

    function testCollidingMissingPageRejects() public {
        vm.expectRevert(abi.encodeWithSelector(StepLog.RequiredSliceNotFound.selector, uint64(183)));
        this.readCollidingMissingPage();
    }

    function testUnwitnessedPageZeroRejects() public {
        vm.expectRevert(abi.encodeWithSelector(StepLog.RequiredSliceNotFound.selector, uint64(0)));
        this.readUnwitnessedPageZero();
    }

    function readUnwitnessedPageZero() external pure returns (uint64) {
        StepLog.Context memory ctx = collidingPages();
        ctx.pageIndices[0] = 1;
        return StateAccess.readWord(ctx, 0);
    }

    function readCollidingMissingPage() external pure returns (uint64) {
        StepLog.Context memory ctx = collidingPages();
        StateAccess.writeWord(ctx, 61 << 12, 42);
        return StateAccess.readWord(ctx, 183 << 12);
    }

    function testUnwitnessedRegisterPageRejects() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                StepLog.RequiredSliceNotFound.selector, EmulatorConstants.UARCH_HALT_ADDR >> 12
            )
        );
        this.writeUnwitnessedRegister();
    }

    function writeUnwitnessedRegister() external pure {
        StepLog.Context memory ctx = collidingPages();
        StateAccess.writeCycle(ctx, 1);
    }

    function testCachedPageWriteInvalidatesHash() public pure {
        StepLog.Context memory ctx = collidingPages();
        StateAccess.readWord(ctx, 61 << 12);
        ctx.sliceHashes[1] = bytes32(uint256(1));
        StateAccess.writeWord(ctx, 61 << 12, 42);
        assertEq(ctx.sliceHashes[1], bytes32(0));
        assertEq(StateAccess.readWord(ctx, 61 << 12), 42);
    }
}
