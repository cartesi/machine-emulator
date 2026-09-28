// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {UArchStep} from "src/UArchStep.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Differential coverage for the physical-write twins. The references preserve
/// the readable lookup/invalidation path, including register aliases and reverts.
contract StateAccessWritesTest is ManifestParser {
    function referenceWriteWord(StepLog.Context memory ctx, uint64 paddr, uint64 value)
        private
        pure
    {
        if (paddr & 7 != 0) revert StateAccess.UnalignedWordAccess(paddr);
        if (
            paddr >= EmulatorConstants.UARCH_HALT_ADDR
                && paddr < EmulatorConstants.UARCH_REGISTER_END_ADDR
        ) {
            StepLog.writeUarchWord(ctx, (paddr - EmulatorConstants.UARCH_HALT_ADDR) / 8, value);
            return;
        }
        StepLog.writeLE64Memory(StepLog.findPageForWrite(ctx, paddr), value);
    }

    function referenceWriteTlb(
        StepLog.Context memory ctx,
        uint64 setIndex,
        uint64 slotIndex,
        uint64[3] memory fields
    ) private pure {
        uint64 addr = EmulatorConstants.AR_SHADOW_TLB_START
            + setIndex * EmulatorConstants.SHADOW_TLB_SET_LENGTH
            + slotIndex * EmulatorConstants.SHADOW_TLB_SLOT_SIZE;
        uint256 ptr = StepLog.findPageForWrite(ctx, addr);
        uint256 word = (uint256(StepLog.swapBytes64(fields[0])) << 192)
            | (uint256(StepLog.swapBytes64(fields[1])) << 128)
            | (uint256(StepLog.swapBytes64(fields[2])) << 64);
        assembly ("memory-safe") {
            mstore(ptr, word)
        }
    }

    function compareState(StepLog.Context memory actual, StepLog.Context memory expected)
        private
        pure
    {
        assertEq(keccak256(actual.pageData), keccak256(expected.pageData), "page bytes/neighbors");
        assertEq(
            keccak256(abi.encode(actual.pageHashes)),
            keccak256(abi.encode(expected.pageHashes)),
            "hash invalidation"
        );
        assertEq(
            keccak256(abi.encode(actual.pageLookupCache)),
            keccak256(abi.encode(expected.pageLookupCache)),
            "page cache"
        );
        assertEq(
            keccak256(abi.encode(actual.uarchRegisters)),
            keccak256(abi.encode(expected.uarchRegisters)),
            "register cache"
        );
        assertEq(actual.uarchRegistersDirty, expected.uarchRegistersDirty, "register dirty flag");
        assertEq(actual.uarchShadowPageIndex, expected.uarchShadowPageIndex, "shadow position");
        // The independently decoded contexts have different physical memory pointers.
        assertEq(actual.uarchShadowPtr == 0, expected.uarchShadowPtr == 0, "register cache valid");
    }

    function compareWord(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 addr,
        uint64 value
    ) private pure {
        StateAccess.writeWord(actual, addr, value);
        referenceWriteWord(expected, addr, value);
        compareState(actual, expected);
    }

    function compareTlb(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 setIndex,
        uint64 slotIndex,
        uint64[3] memory fields
    ) private pure {
        StateAccess.writeTlbECALL(actual, setIndex, slotIndex, fields[0], fields[1], fields[2]);
        referenceWriteTlb(expected, setIndex, slotIndex, fields);
        compareState(actual, expected);
    }

    function compareColdWarmWord(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 addr,
        uint64 value
    ) private pure {
        uint256 cacheSlot = (addr >> 12) % 61;
        actual.pageLookupCache[cacheSlot] = 0;
        expected.pageLookupCache[cacheSlot] = 0;
        compareWord(actual, expected, addr, value);
        compareWord(actual, expected, addr, ~value);
    }

    function testEveryFixture() public {
        string[] memory dirs = programDirs();
        uint256 count;
        for (uint256 i; i < dirs.length; ++i) {
            count += runDir(dirs[i], Kind.Cycle);
        }
        count += runDir("test/fixtures/reset-uarch", Kind.ResetUarch);
        count += runDir("test/fixtures/send-cmio-response", Kind.SendCmioResponse);
        assertGt(count, 0, "no write fixtures");
        console.log("write differential fixture logs", count);
    }

    function runDir(string memory dir, Kind kind) private returns (uint256 count) {
        Row[] memory rows = readManifestRows(string.concat(dir, "/_manifest.csv"), kind);
        for (uint256 i; i < rows.length; ++i) {
            this.compareFixture(vm.readFileBinary(string.concat(dir, "/", rows[i].name)), i);
            ++count;
        }
    }

    function compareFixture(bytes calldata log, uint256 sample) external pure {
        StepLog.Context memory actual = StepLog.decode(log);
        StepLog.Context memory expected = StepLog.decode(log);
        for (uint256 i; i < actual.pageIndices.length; ++i) {
            uint64 start = actual.pageIndices[i] << 12;
            uint64 value = uint64(uint256(keccak256(abi.encode(sample, start))));
            compareColdWarmWord(actual, expected, start, value);
            compareColdWarmWord(actual, expected, start + 4088, value);
            compareColdWarmWord(actual, expected, start + uint64(sample % 512) * 8, value);
            if (start >= 0x1000 && start < 0x7000) {
                // Every TLB slot in every witnessed TLB page, including page/set edges.
                uint64 setIndex = (start - 0x1000) / 0x2000;
                uint64 firstSlot = ((start - 0x1000) % 0x2000) / 32;
                for (uint64 j; j < 128; ++j) {
                    uint256 cacheSlot = (start >> 12) % 61;
                    actual.pageLookupCache[cacheSlot] = 0;
                    expected.pageLookupCache[cacheSlot] = 0;
                    compareTlb(actual, expected, setIndex, firstSlot + j, [value, ~value, j]);
                    compareTlb(
                        actual,
                        expected,
                        setIndex,
                        firstSlot + j,
                        [type(uint64).max, uint64(0), type(uint64).max]
                    );
                }
            }
        }
        assertEq(StepLog.computeRootHash(actual), StepLog.computeRootHash(expected), "post root");
        compareState(actual, expected);
    }

    function physicalContext(uint64 base) private pure returns (StepLog.Context memory ctx) {
        ctx.pageIndices = new uint64[](3);
        ctx.pageData = new bytes(3 * 4096);
        ctx.pageHashes = new bytes32[](3);
        for (uint64 i; i < 3; ++i) {
            ctx.pageIndices[i] = base + i * 61;
            ctx.pageHashes[i] = bytes32(uint256(i) + 1);
            ctx.pageData[uint256(i) * 4096] = 0xa5;
            ctx.pageData[uint256(i) * 4096 + 4095] = 0x5a;
        }
    }

    function physicalBase(uint64 seed) private pure returns (uint64 base) {
        base = (seed >> 12) % ((uint64(1) << 52) - 183);
        uint64 shadow = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        if (base <= shadow && base + 122 >= shadow) base = shadow + 1;
    }

    function testFuzzWordColdWarmCollision(uint64 seed, uint16 wordSeed, uint64 value)
        public
        pure
    {
        uint64 base = physicalBase(seed);
        uint64 offset = uint64(wordSeed % 512) * 8;
        StepLog.Context memory actual = physicalContext(base);
        StepLog.Context memory expected = physicalContext(base);
        compareColdWarmWord(actual, expected, (base << 12) + offset, value);
        compareWord(actual, expected, ((base + 61) << 12) + offset, value);
        compareWord(actual, expected, ((base + 122) << 12) + offset, ~value);
        compareWord(actual, expected, (base << 12) + offset, value);
    }

    function testFuzzTlbColdWarmCollision(uint8 setSeed, uint8 slot, uint64[3] memory fields)
        public
        pure
    {
        uint64 setIndex = setSeed % 3;
        uint64 base = (0x1000 + setIndex * 0x2000 + uint64(slot) * 32) >> 12;
        StepLog.Context memory actual = physicalContext(base);
        StepLog.Context memory expected = physicalContext(base);
        compareTlb(actual, expected, setIndex, slot, fields);
        compareTlb(actual, expected, setIndex, slot, [~fields[0], ~fields[1], ~fields[2]]);
        compareWord(actual, expected, (base + 61) << 12, fields[0]);
        compareTlb(actual, expected, setIndex, slot, fields);
    }

    function testAllPositionsAndTlbSlots() public pure {
        StepLog.Context memory actual = maximumContext();
        StepLog.Context memory expected = maximumContext();
        for (uint64 i; i < 64; ++i) {
            uint64 addr = (actual.pageIndices[i] << 12) | 4088;
            compareColdWarmWord(actual, expected, addr, i + 42);
        }
        for (uint64 setIndex; setIndex < 3; ++setIndex) {
            for (uint64 slot; slot < 256; ++slot) {
                compareTlb(actual, expected, setIndex, slot, [setIndex, slot, type(uint64).max]);
            }
        }
    }

    function maximumContext() private pure returns (StepLog.Context memory ctx) {
        ctx.pageIndices = new uint64[](64);
        ctx.pageData = new bytes(64 * 4096);
        ctx.pageHashes = new bytes32[](64);
        for (uint64 i; i < 64; ++i) {
            ctx.pageIndices[i] = i == 63 ? type(uint64).max >> 12 : i;
            ctx.pageHashes[i] = bytes32(uint256(i) + 1);
        }
    }

    function testFuzzDirtyWordOperands(uint256 rawAddr, uint256 rawValue) public pure {
        uint64 cleanAddr = uint64(rawAddr) & ~uint64(7);
        uint64 base = cleanAddr >> 12;
        // Avoid register aliases and leave room for the two colliding pages.
        base = physicalBase(base << 12);
        cleanAddr = (base << 12) | (cleanAddr & 4095);
        rawAddr = (rawAddr & ~uint256(type(uint64).max)) | cleanAddr;
        uint64 addr;
        uint64 value;
        assembly ("memory-safe") {
            addr := rawAddr
            value := rawValue
        }
        compareWord(physicalContext(base), physicalContext(base), addr, value);
    }

    function testFuzzDirtyTlbIndices(uint256 rawSet, uint256 rawSlot, uint64[3] memory fields)
        public
        pure
    {
        rawSet = (rawSet & ~uint256(type(uint64).max)) | (rawSet % 3);
        rawSlot = (rawSlot & ~uint256(type(uint64).max)) | (rawSlot % 256);
        uint64 setIndex;
        uint64 slotIndex;
        assembly ("memory-safe") {
            setIndex := rawSet
            slotIndex := rawSlot
        }
        uint64 base = (0x1000 + uint64(rawSet) * 0x2000 + uint64(rawSlot) * 32) >> 12;
        compareTlb(physicalContext(base), physicalContext(base), setIndex, slotIndex, fields);
    }

    function testFuzzShadowPendingRegisters(uint8 regSeed, uint64 value, uint16 wordSeed)
        public
        pure
    {
        uint64 shadow = EmulatorConstants.UARCH_HALT_ADDR;
        StepLog.Context memory actual = physicalContext(shadow >> 12);
        StepLog.Context memory expected = physicalContext(shadow >> 12);
        uint8 reg = regSeed % 32;
        StateAccess.writeX(actual, reg, value);
        StateAccess.writeX(expected, reg, value);
        compareWord(actual, expected, EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8, ~value);
        assertTrue(actual.uarchRegistersDirty, "alias should stay pending");
        // Raw write after the cached register window must flush pending words and
        // drop the cache; the next register read must reload the preserved value.
        uint64 end = EmulatorConstants.UARCH_REGISTER_END_ADDR - shadow;
        uint64 offset = end + uint64(wordSeed % ((4096 - end) / 8)) * 8;
        compareWord(actual, expected, shadow + offset, value);
        assertEq(actual.uarchShadowPtr, 0, "raw write must drop register cache");
        assertFalse(actual.uarchRegistersDirty, "pending register writes not flushed");
        assertEq(StateAccess.readX(actual, reg), ~value);
        assertEq(StateAccess.readX(expected, reg), ~value);
        compareState(actual, expected);
    }

    function testFuzzEqualReverts(uint64 seed, uint16 wordSeed, uint8 skew) public view {
        uint64 base = physicalBase(seed);
        uint64 offset = uint64(wordSeed % 512) * 8;
        uint64 missing = ((base + 183) << 12) | offset;
        uint64 unaligned = (base << 12) + offset + 1 + uint64(skew % 7);
        for (uint256 warm; warm < 2; ++warm) {
            compareRevert(
                base,
                missing,
                false,
                warm != 0,
                abi.encodeWithSelector(StepLog.RequiredPageNotFound.selector, base + 183)
            );
            compareRevert(
                base,
                unaligned,
                false,
                warm != 0,
                abi.encodeWithSelector(StateAccess.UnalignedWordAccess.selector, unaligned)
            );
            // Valid indices 2/255 address page 6; only colliding pages 67/128/189 exist.
            compareRevert(
                67,
                0,
                true,
                warm != 0,
                abi.encodeWithSelector(StepLog.RequiredPageNotFound.selector, uint64(6))
            );
        }
    }

    function compareRevert(uint64 base, uint64 addr, bool tlb, bool warm, bytes memory reason)
        private
        view
    {
        (bool aOk, bytes memory a) =
            address(this).staticcall(abi.encodeCall(this.probe, (true, base, addr, tlb, warm)));
        (bool eOk, bytes memory e) =
            address(this).staticcall(abi.encodeCall(this.probe, (false, base, addr, tlb, warm)));
        assertFalse(aOk);
        assertFalse(eOk);
        assertEq(a, e, "revert mismatch");
        assertEq(a, reason, "wrong revert");
    }

    function probe(bool fast, uint64 base, uint64 addr, bool tlb, bool warm) external pure {
        StepLog.Context memory ctx = physicalContext(base);
        if (warm) StepLog.findPageForWrite(ctx, base << 12);
        if (tlb) {
            if (fast) StateAccess.writeTlbECALL(ctx, 2, 255, 1, 2, 3);
            else referenceWriteTlb(ctx, 2, 255, [uint64(1), uint64(2), uint64(3)]);
        } else {
            if (fast) StateAccess.writeWord(ctx, addr, 42);
            else referenceWriteWord(ctx, addr, 42);
        }
    }

    function testGeneratedTlbIndexGuards() public {
        uint64[4] memory bad = [uint64(3), uint64(256), type(uint64).max, uint64(1)];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(
                abi.encodeWithSelector(StateAccess.RuntimeError.selector, "TLB index out of range")
            );
            this.invalidEcall(4, i == 3 ? 0 : bad[i], i == 3 ? 256 : 0);
            vm.expectRevert(
                abi.encodeWithSelector(
                    StateAccess.RuntimeError.selector, "TLB batch index out of range or unaligned"
                )
            );
            this.invalidEcall(5, i == 3 ? 0 : bad[i], i == 3 ? 1 : 0);
        }
    }

    function invalidEcall(uint64 selector, uint64 setIndex, uint64 slotIndex) external pure {
        StepLog.Context memory ctx;
        ctx.pageIndices = new uint64[](2);
        ctx.pageIndices[0] = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        ctx.pageIndices[1] = 0x600;
        ctx.pageHashes = new bytes32[](2);
        ctx.pageData = new bytes(8192);
        ctx.pageData[4096] = 0x73; // ECALL
        StateAccess.writePc(ctx, 0x600000);
        StateAccess.writeX(ctx, 10, setIndex);
        StateAccess.writeX(ctx, 11, slotIndex);
        StateAccess.writeX(ctx, 17, selector);
        UArchStep.uarchStep(ctx);
    }
}
