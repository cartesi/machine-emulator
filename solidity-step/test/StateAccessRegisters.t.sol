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
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Compare inline accessors with the readable register-word helpers.
contract StateAccessRegistersTest is ManifestParser {
    function referenceReadX(StepLog.Context memory ctx, uint8 reg) private pure returns (uint64) {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) {
            revert StateAccess.UarchXRegisterOutOfRange(reg);
        }
        return StepLog.readUarchWord(ctx, EmulatorConstants.UARCH_X_WORD_INDEX + uint256(reg));
    }

    function referenceWriteX(StepLog.Context memory ctx, uint8 reg, uint64 value) private pure {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) {
            revert StateAccess.UarchXRegisterOutOfRange(reg);
        }
        StepLog.writeUarchWord(ctx, EmulatorConstants.UARCH_X_WORD_INDEX + uint256(reg), value);
    }

    function compareState(StepLog.Context memory actual, StepLog.Context memory expected)
        private
        pure
    {
        assertEq(
            keccak256(abi.encode(actual.uarchRegisters)),
            keccak256(abi.encode(expected.uarchRegisters)),
            "register words"
        );
        assertEq(actual.uarchRegistersDirty, expected.uarchRegistersDirty, "dirty");
        assertEq(actual.uarchShadowPageIndex, expected.uarchShadowPageIndex, "page position");
        assertEq(actual.uarchShadowPtr == 0, expected.uarchShadowPtr == 0, "loaded");
        assertEq(
            keccak256(abi.encode(actual.sliceHashes)),
            keccak256(abi.encode(expected.sliceHashes)),
            "page hashes"
        );
        assertEq(
            keccak256(abi.encode(actual.pageLookupCache)),
            keccak256(abi.encode(expected.pageLookupCache)),
            "lookup cache"
        );
        assertEq(actual.sliceData, expected.sliceData, "page bytes");
    }

    function compareWriteX(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint8 reg,
        uint64 value
    ) private pure {
        StateAccess.writeX(actual, reg, value);
        referenceWriteX(expected, reg, value);
        compareState(actual, expected);
        assertTrue(actual.uarchRegistersDirty);
        assertEq(actual.sliceHashes[actual.uarchShadowPageIndex], bytes32(0));
    }

    function compareWritePc(
        StepLog.Context memory actual,
        StepLog.Context memory expected,
        uint64 value
    ) private pure {
        StateAccess.writePc(actual, value);
        StepLog.writeUarchWord(expected, EmulatorConstants.UARCH_PC_WORD_INDEX, value);
        compareState(actual, expected);
        assertEq(StateAccess.readPc(actual), value);
    }

    function compareRoots(StepLog.Context memory actual, StepLog.Context memory expected)
        private
        pure
    {
        assertEq(StepLog.computeRootHash(actual), StepLog.computeRootHash(expected), "root");
        assertFalse(actual.uarchRegistersDirty);
        compareState(actual, expected);
    }

    function testEveryPerStepFixture() public {
        string[] memory dirs = programDirs();
        require(dirs.length > 0, "no per-cycle uarch fixtures");
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
        console.log("register differential programs / fixtures", dirs.length, fixtures);
    }

    function compareFixture(bytes calldata log, bytes32 rootBefore, uint256 sample) external pure {
        StepLog.Context memory actual = StepLog.decode(log);
        StepLog.Context memory expected = StepLog.decode(log);
        assertEq(actual.rootHashBefore, rootBefore);
        assertEq(expected.rootHashBefore, rootBefore);
        uint8 reg = uint8(sample % EmulatorConstants.UARCH_X_REG_COUNT);
        uint64 value = uint64(uint256(rootBefore));
        // Rotate which accessor sees the cold cache; all registers are read warm too.
        if (sample % 3 == 0) compareWriteX(actual, expected, reg, value);
        else if (sample % 3 == 1) compareWritePc(actual, expected, value);
        for (uint8 i; i < EmulatorConstants.UARCH_X_REG_COUNT; ++i) {
            assertEq(StateAccess.readX(actual, i), referenceReadX(expected, i));
        }
        compareState(actual, expected);
        compareWriteX(actual, expected, reg, ~value);
        compareWritePc(actual, expected, uint64(sample));
        compareRoots(actual, expected);
    }

    function registerContext() private pure returns (StepLog.Context memory ctx) {
        ctx = registerPageContext();
        ctx.nodes = new StepLog.NodeEntry[](0);
        ctx.siblings = new bytes32[](52);
        for (uint256 i; i < EmulatorConstants.UARCH_REGISTER_WORD_COUNT; ++i) {
            ctx.sliceData[i * 8] = bytes1(uint8(i + 1));
        }
        ctx.sliceData[280] = 0xa5;
        ctx.sliceData[4095] = 0x7e;
        StepLog.computeRootHash(ctx);
    }

    function testFuzzRegisterCacheCoherence(uint8 reg, uint64 first, uint64 second, uint64 pc)
        public
        pure
    {
        reg %= EmulatorConstants.UARCH_X_REG_COUNT;
        StepLog.Context memory actual = registerContext();
        StepLog.Context memory expected = registerContext();
        compareWriteX(actual, expected, reg, first); // cold write
        uint64 addr = EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8;
        assertEq(StateAccess.readWord(actual, addr), first);
        compareWriteX(actual, expected, reg, second); // already dirty
        compareWritePc(actual, expected, pc);
        compareRoots(actual, expected);
        compareRoots(actual, expected); // cached root; no pending writes

        // Raw writes invalidate the register cache. The next read must reload it.
        uint256 actualPtr = StepLog.findDataForWrite(actual, addr);
        uint256 expectedPtr = StepLog.findDataForWrite(expected, addr);
        StepLog.writeLE64Memory(actualPtr, ~second);
        StepLog.writeLE64Memory(expectedPtr, ~second);
        assertEq(actual.uarchShadowPtr, 0);
        assertEq(StateAccess.readX(actual, reg), referenceReadX(expected, reg));
        assertEq(StateAccess.readX(actual, reg), ~second);
        compareState(actual, expected);

        // A raw read materializes dirty words without invalidating cached registers.
        compareWriteX(actual, expected, reg, first);
        StepLog.findData(actual, addr);
        StepLog.findData(expected, addr);
        assertFalse(actual.uarchRegistersDirty);
        compareState(actual, expected);
        // Flush/invalidate again to exercise the PC writer's cold loader.
        StepLog.findDataForWrite(actual, addr);
        StepLog.findDataForWrite(expected, addr);
        compareWritePc(actual, expected, ~pc);
        compareRoots(actual, expected);
        assertEq(actual.sliceData[280], bytes1(0xa5));
        assertEq(actual.sliceData[4095], bytes1(0x7e));
    }

    function testFuzzNarrowOperands(uint256 rawReg, uint256 rawValue) public pure {
        // Solidity assembly may leave upper bits dirty; the accessors must behave
        // like the typed readable path, including truncating stored uint64 values.
        rawReg = (rawReg & ~uint256(0xff)) | (rawReg % 32);
        uint8 reg;
        uint64 value;
        assembly ("memory-safe") {
            reg := rawReg
            value := rawValue
        }
        StepLog.Context memory actual = registerContext();
        StepLog.Context memory expected = registerContext();
        compareWriteX(actual, expected, reg, value);
        assertEq(StateAccess.readX(actual, reg), referenceReadX(expected, reg));
        compareWritePc(actual, expected, value);
        compareRoots(actual, expected);
    }

    function probe(bool fast, uint8 op, uint8 reg, bool witnessed, bool warm)
        external
        pure
        returns (uint64)
    {
        StepLog.Context memory ctx;
        if (witnessed) {
            ctx = registerContext();
        } else {
            ctx = contextWithPages(new uint64[](0));
        }
        if (warm) StepLog.readUarchWord(ctx, 0);
        if (op == 0) return fast ? StateAccess.readX(ctx, reg) : referenceReadX(ctx, reg);
        if (op == 1) {
            if (fast) StateAccess.writeX(ctx, reg, 42);
            else referenceWriteX(ctx, reg, 42);
        } else {
            if (fast) StateAccess.writePc(ctx, 42);
            else StepLog.writeUarchWord(ctx, EmulatorConstants.UARCH_PC_WORD_INDEX, 42);
        }
        return 0;
    }

    function compareReverts(uint8 op, uint8 reg, bool witnessed, bool warm, bytes memory reason)
        private
        view
    {
        compareRevert(
            abi.encodeCall(this.probe, (true, op, reg, witnessed, warm)),
            abi.encodeCall(this.probe, (false, op, reg, witnessed, warm)),
            reason
        );
    }

    function testFuzzOutOfRangeReverts(uint8 seed) public view {
        uint8 reg = uint8(uint256(seed) % 224 + 32);
        bytes memory reason =
            abi.encodeWithSelector(StateAccess.UarchXRegisterOutOfRange.selector, reg);
        for (uint8 op; op < 2; ++op) {
            compareReverts(op, reg, true, false, reason);
            compareReverts(op, reg, true, true, reason);
            // Register validation must still precede the missing-page error.
            compareReverts(op, reg, false, false, reason);
        }
    }

    function testMissingRegisterPageReverts() public view {
        bytes memory reason = abi.encodeWithSelector(
            StepLog.RequiredSliceNotFound.selector, EmulatorConstants.UARCH_HALT_ADDR >> 12
        );
        for (uint8 op; op < 3; ++op) {
            compareReverts(op, 31, false, false, reason);
        }
    }
}
