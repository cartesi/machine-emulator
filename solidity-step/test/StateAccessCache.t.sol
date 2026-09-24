// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

contract StateAccessCacheTest is Test {
    function registerContext() private pure returns (StepLog.Context memory ctx) {
        ctx.pageIndices = new uint64[](1);
        ctx.pageIndices[0] = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        ctx.pageData = new bytes(4096);
        ctx.pageData[280] = 0xa5;
        ctx.pageData[4095] = 0x7e;
        ctx.pageHashes = new bytes32[](1);
        ctx.nodes = new StepLog.NodeEntry[](0);
        ctx.siblings = new bytes32[](52);
    }

    function rawRegisterWrite(StepLog.Context memory ctx, uint8 reg, uint64 value) private pure {
        uint256 offset = EmulatorConstants.UARCH_X_BASE_ADDR - EmulatorConstants.UARCH_HALT_ADDR
            + uint256(reg) * 8;
        for (uint256 i; i < 8; ++i) {
            ctx.pageData[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
        ctx.pageHashes[0] = bytes32(0);
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
        assertEq(ctx.pageHashes[0], bytes32(0));
        rawRegisterWrite(expected, reg, first);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.pageData), keccak256(expected.pageData));

        StateAccess.writeWord(ctx, addr, second);
        assertEq(StateAccess.readX(ctx, reg), second);
        rawRegisterWrite(expected, reg, second);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.pageData), keccak256(expected.pageData));
    }

    function testRawPointerReadFlushesRegisters() public pure {
        StepLog.Context memory ctx = registerContext();
        StateAccess.writeX(ctx, 1, 0x123456789abcdef0);
        uint256 ptr = StepLog.findPage(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + 8);
        uint64 raw;
        assembly ("memory-safe") {
            raw := shr(192, mload(ptr))
        }
        assertEq(raw, 0xf0debc9a78563412);
        assertEq(StateAccess.readX(ctx, 1), 0x123456789abcdef0);
    }

    function testRawPointerWriteInvalidatesRegisters() public pure {
        StepLog.Context memory ctx = registerContext();
        StateAccess.writeX(ctx, 1, 42);
        uint256 ptr = StepLog.findPageForWrite(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + 8);
        assembly ("memory-safe") {
            mstore8(ptr, 99)
        }
        assertEq(StateAccess.readX(ctx, 1), 99);
        StateAccess.writeX(ctx, 2, 123);
        StepLog.Context memory expected = registerContext();
        rawRegisterWrite(expected, 1, 99);
        rawRegisterWrite(expected, 2, 123);
        assertEq(StepLog.computeRootHash(ctx), StepLog.computeRootHash(expected));
        assertEq(keccak256(ctx.pageData), keccak256(expected.pageData));
    }

    function collidingPages() private pure returns (StepLog.Context memory ctx) {
        ctx.pageIndices = new uint64[](3);
        ctx.pageIndices[1] = 61;
        ctx.pageIndices[2] = 122;
        ctx.pageData = new bytes(3 * 4096);
        ctx.pageHashes = new bytes32[](3);
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
        vm.expectRevert(abi.encodeWithSelector(StepLog.RequiredPageNotFound.selector, uint64(183)));
        this.readCollidingMissingPage();
    }

    function readCollidingMissingPage() external pure returns (uint64) {
        StepLog.Context memory ctx = collidingPages();
        StateAccess.writeWord(ctx, 61 << 12, 42);
        return StateAccess.readWord(ctx, 183 << 12);
    }

    function testUnwitnessedRegisterPageRejects() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                StepLog.RequiredPageNotFound.selector, EmulatorConstants.UARCH_HALT_ADDR >> 12
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
        ctx.pageHashes[1] = bytes32(uint256(1));
        StateAccess.writeWord(ctx, 61 << 12, 42);
        assertEq(ctx.pageHashes[1], bytes32(0));
        assertEq(StateAccess.readWord(ctx, 61 << 12), 42);
    }
}
