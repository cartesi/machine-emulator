// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Differential coverage for the inline physical-read twin and its cache side effects.
contract StateAccessReadWordTest is ManifestParser {
    // The original readable readWord path, including its register aliases and reverts.
    function referenceReadWord(StepLog.Context memory ctx, uint64 paddr)
        private
        pure
        returns (uint64)
    {
        if (paddr & 7 != 0) revert StateAccess.UnalignedWordAccess(paddr);
        if (
            paddr >= EmulatorConstants.UARCH_HALT_ADDR
                && paddr < EmulatorConstants.UARCH_REGISTER_END_ADDR
        ) {
            return StepLog.readUarchWord(ctx, (paddr - EmulatorConstants.UARCH_HALT_ADDR) / 8);
        }
        uint256 ptr = StepLog.findPage(ctx, paddr);
        bytes32 word;
        assembly ("memory-safe") {
            word := mload(ptr)
        }
        return StepLog.swapBytes64(uint64(bytes8(word)));
    }

    function cacheHash(StepLog.Context memory ctx) private pure returns (bytes32) {
        return keccak256(abi.encode(ctx.pageLookupCache));
    }

    function compareRead(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 paddr
    ) private pure returns (uint64 value) {
        value = StateAccess.readWord(actual, paddr);
        assertEq(value, referenceReadWord(expected, paddr), "read value");
        assertEq(cacheHash(actual), cacheHash(expected), "cache fill");
    }

    function compareState(StepLog.Context memory actual, StepLog.Context memory expected)
        private
        pure
    {
        assertEq(actual.pageData, expected.pageData, "page bytes");
        assertEq(
            keccak256(abi.encode(actual.pageHashes)), keccak256(abi.encode(expected.pageHashes))
        );
        assertEq(
            keccak256(abi.encode(actual.uarchRegisters)),
            keccak256(abi.encode(expected.uarchRegisters))
        );
        assertEq(actual.uarchRegistersDirty, expected.uarchRegistersDirty);
        assertEq(actual.uarchShadowPageIndex, expected.uarchShadowPageIndex);
        // The two contexts have different physical EVM memory addresses.
        assertEq(actual.uarchShadowPtr == 0, expected.uarchShadowPtr == 0);
    }

    function compareColdAndWarm(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 paddr
    ) private pure {
        uint256 slot = (paddr >> 12) % actual.pageLookupCache.length;
        actual.pageLookupCache[slot] = 0;
        expected.pageLookupCache[slot] = 0;
        compareRead(actual, expected, paddr);
        bytes32 filled = cacheHash(actual);
        compareRead(actual, expected, paddr);
        assertEq(cacheHash(actual), filled, "warm read changed cache");
    }

    function testEveryPerStepFixture() public {
        string[] memory dirs = programDirs();
        uint256 fixtures;
        for (uint256 i; i < dirs.length; ++i) {
            Row[] memory rows =
                readManifestRows(string.concat(dirs[i], "/_manifest.csv"), Kind.Cycle);
            require(rows.length != 0, "program has no cycles");
            for (uint256 j; j < rows.length; ++j) {
                this.compareFixture(
                    vm.readFileBinary(string.concat(dirs[i], "/", rows[j].name)),
                    rows[j].rootHashBefore,
                    j
                );
                ++fixtures;
            }
        }
        require(fixtures != 0, "no fixtures");
        console.log("readWord differential programs / fixtures", dirs.length, fixtures);
    }

    function compareFixture(bytes calldata log, bytes32 rootBefore, uint256 sample) external pure {
        StepLog.Context memory actual = StepLog.decode(log);
        StepLog.Context memory expected = StepLog.decode(log);
        assertEq(actual.rootHashBefore, rootBefore);
        assertEq(expected.rootHashBefore, rootBefore);
        // Every witnessed page: first/last aligned word and a rotating interior
        // word, each cold and warm. Fuzz tests below cover arbitrary word contents.
        for (uint256 i; i < actual.pageIndices.length; ++i) {
            uint64 start = StepLog.sliceAddress(actual.slices[i]);
            uint64 size = uint64(1) << StepLog.sliceLog2Size(actual.slices[i]);
            compareColdAndWarm(actual, expected, start);
            compareColdAndWarm(actual, expected, start + size - 8);
            compareColdAndWarm(actual, expected, start + uint64(sample % (size / 8)) * 8);
        }
        compareState(actual, expected);
    }

    function physicalBase(uint64 seed) private pure returns (uint64 page) {
        page = (seed >> 12) % ((uint64(1) << 52) - 183);
        // This fuzz isolates physical reads; pending-register aliases have their
        // own test below and are also present in the real fixture differential.
        uint64 shadow = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        if (page <= shadow && page + 122 >= shadow) page = shadow + 1;
    }

    function physicalContext(uint64 base, uint64 offset, uint64 value)
        private
        pure
        returns (StepLog.Context memory ctx)
    {
        ctx.pageIndices = new uint64[](3);
        ctx.slices = new uint256[](3);
        for (uint256 si; si < ctx.slices.length; ++si) {
            ctx.slices[si] = StepLog.packSlice(0, 12, si * 4096);
        }
        ctx.pageData = new bytes(3 * 4096);
        ctx.pageHashes = new bytes32[](3);
        for (uint64 i; i < 3; ++i) {
            ctx.pageIndices[i] = base + i * 61;
            ctx.slices[i] = StepLog.packSlice(ctx.pageIndices[i] << 12, 12, uint256(i) * 4096);
            for (uint256 j; j < 8; ++j) {
                ctx.pageData[uint256(i) * 4096 + offset + j] = bytes1(uint8(value >> (j * 8)));
            }
        }
    }

    function testFuzzColdWarmAndCollidingReads(
        uint64 pageSeed,
        uint16 wordSeed,
        uint64 value,
        uint8 selected
    ) public pure {
        uint64 base = physicalBase(pageSeed);
        uint64 offset = uint64(wordSeed % 512) * 8;
        StepLog.Context memory actual = physicalContext(base, offset, value);
        StepLog.Context memory expected = physicalContext(base, offset, value);
        uint256 pos = selected % 3;
        uint64 addr = (actual.pageIndices[pos] << 12) + offset;
        compareColdAndWarm(actual, expected, addr);
        assertEq(StateAccess.readWord(actual, addr), value);
        uint64 collision = (actual.pageIndices[(pos + 1) % 3] << 12) + offset;
        compareRead(actual, expected, collision);
        bytes32 colliding = cacheHash(actual);
        compareRead(actual, expected, addr);
        assertTrue(cacheHash(actual) != colliding, "miss did not replace colliding tag");
        compareState(actual, expected);
    }

    function testFuzzEqualReverts(uint64 pageSeed, uint16 wordSeed, uint8 skew) public view {
        uint64 base = physicalBase(pageSeed);
        uint64 offset = uint64(wordSeed % 512) * 8;
        uint64 missing = ((base + 183) << 12) + offset;
        uint64 unaligned = (base << 12) + offset + 1 + uint64(skew % 7);
        for (uint256 warm; warm < 2; ++warm) {
            compareRevert(
                base,
                missing,
                warm != 0,
                abi.encodeWithSelector(StepLog.RequiredPageNotFound.selector, base + 183)
            );
            compareRevert(
                base,
                unaligned,
                warm != 0,
                abi.encodeWithSelector(StateAccess.UnalignedWordAccess.selector, unaligned)
            );
        }
    }

    function compareRevert(uint64 base, uint64 paddr, bool warm, bytes memory reason)
        private
        view
    {
        (bool actualOk, bytes memory actual) =
            address(this).staticcall(abi.encodeCall(this.probe, (true, base, paddr, warm)));
        (bool expectedOk, bytes memory expected) =
            address(this).staticcall(abi.encodeCall(this.probe, (false, base, paddr, warm)));
        assertFalse(actualOk);
        assertFalse(expectedOk);
        assertEq(actual, expected, "different reverts");
        assertEq(actual, reason, "wrong revert");
    }

    function probe(bool fast, uint64 base, uint64 paddr, bool warm)
        external
        pure
        returns (uint64)
    {
        StepLog.Context memory ctx = physicalContext(base, 0, 0);
        if (warm) {
            if (fast) StateAccess.readWord(ctx, base << 12);
            else referenceReadWord(ctx, base << 12);
        }
        return fast ? StateAccess.readWord(ctx, paddr) : referenceReadWord(ctx, paddr);
    }

    function shadowContext(uint64 offset, uint64 value)
        private
        pure
        returns (StepLog.Context memory ctx)
    {
        ctx.pageIndices = new uint64[](1);
        ctx.slices = new uint256[](1);
        for (uint256 si; si < ctx.slices.length; ++si) {
            ctx.slices[si] = StepLog.packSlice(0, 12, si * 4096);
        }
        ctx.pageIndices[0] = EmulatorConstants.UARCH_HALT_ADDR >> 12;
        ctx.slices[0] = StepLog.packSlice(ctx.pageIndices[0] << 12, 12, uint256(0) * 4096);
        ctx.pageData = new bytes(4096);
        ctx.pageHashes = new bytes32[](1);
        ctx.nodes = new StepLog.NodeEntry[](0);
        ctx.siblings = new bytes32[](52);
        for (uint256 i; i < 8; ++i) {
            ctx.pageData[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function testFuzzShadowReadWithPendingRegisters(
        uint8 reg,
        uint16 wordSeed,
        uint64 registerValue,
        uint64 followingValue
    ) public pure {
        reg %= EmulatorConstants.UARCH_X_REG_COUNT;
        uint64 end = EmulatorConstants.UARCH_REGISTER_END_ADDR - EmulatorConstants.UARCH_HALT_ADDR;
        uint64 offset = end + uint64(wordSeed % ((4096 - end) / 8)) * 8;
        StepLog.Context memory actual = shadowContext(offset, followingValue);
        StepLog.Context memory expected = shadowContext(offset, followingValue);
        StateAccess.writeX(actual, reg, registerValue);
        StateAccess.writeX(expected, reg, registerValue);
        uint64 registerAddr = EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8;
        assertEq(compareRead(actual, expected, registerAddr), registerValue);
        assertTrue(actual.uarchRegistersDirty, "register alias unexpectedly flushed");
        assertEq(
            compareRead(actual, expected, EmulatorConstants.UARCH_HALT_ADDR + offset),
            followingValue
        );
        assertFalse(actual.uarchRegistersDirty, "physical shadow read did not flush");
        compareState(actual, expected);
        assertEq(StepLog.computeRootHash(actual), StepLog.computeRootHash(expected));
    }
}
