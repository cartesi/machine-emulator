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
import {console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {HashTree} from "src/HashTree.sol";

contract SliceHashDifferentialTest is StepLogTestBase {
    function compareSlice(bytes memory data, uint256 start, uint256 size) private pure {
        bytes32 contentsBefore = keccak256(data);
        bytes32 expected = HashTree.merkleTreeHash(data, start, size);
        uint256 freeBefore;
        assembly ("memory-safe") {
            freeBefore := mload(0x40)
        }
        bytes32 actual = HashTree.merkleTreeHashAsm(data, start, size);
        uint256 freeAfter;
        uint256 zeroSlot;
        assembly ("memory-safe") {
            freeAfter := mload(0x40)
            zeroSlot := mload(0x60)
        }
        assertEq(actual, expected, "page hash");
        assertEq(freeAfter, freeBefore, "temporary space became an allocation");
        assertEq(zeroSlot, 0, "zero slot");
        assertEq(keccak256(data), contentsBefore, "input or neighbors changed");
        assertEq(HashTree.merkleTreeHashAsm(data, start, size), expected, "reused scratch");
        // Subsequent Solidity allocation must initialize memory even where scratch
        // hashes were left above the free pointer.
        bytes memory later = new bytes(96);
        for (uint256 i; i < later.length; ++i) {
            assertEq(later[i], bytes1(0));
        }
        assertEq(HashTree.merkleTreeHashAsm(data, start, size), expected, "moved scratch");
    }

    function testEveryFixtureSlice() public view {
        VmSafe.DirEntry[] memory entries = vm.readDir("test/fixtures", 3);
        require(entries.length > 0, "no fixture entries");
        uint256 logs;
        uint256 pages;
        for (uint256 i; i < entries.length; ++i) {
            if (entries[i].isDir || !isLog(entries[i].path)) continue;
            uint256 count = this.compareLogSlices(vm.readFileBinary(entries[i].path));
            if (count != 0) {
                ++logs;
                pages += count;
            }
        }
        require(logs != 0 && pages != 0, "no fixture pages");
        console.log("page differential logs / pages", logs, pages);
    }

    function isLog(string memory path) private pure returns (bool) {
        bytes memory name = bytes(path);
        uint256 n = name.length;
        return n >= 4 && name[n - 4] == "." && name[n - 3] == "l" && name[n - 2] == "o"
            && name[n - 1] == "g";
    }

    function compareLogSlices(bytes calldata log) external pure returns (uint256 pages) {
        // Parse slice bodies independently, including complete entries in rejected logs.
        if (log.length < 40) return 0;
        uint256 declared = le64(log, 16);
        uint256 cursor = 40;
        for (uint256 i; i < declared; ++i) {
            if (log.length - cursor < 16) break;
            uint256 log2Size = le64(log, cursor + 8);
            if (log2Size < 5 || log2Size > 12) break;
            uint256 size = uint256(1) << log2Size;
            cursor += 16;
            if (log.length - cursor < size + 32) break;
            bytes memory slice = log[cursor:cursor + size];
            compareSlice(slice, 0, size);
            cursor += size + 32;
            ++pages;
        }
    }

    function testFuzzPageBuffer(bytes32[128] memory words, uint8 prefixSeed, uint8 placement)
        public
        pure
    {
        // Every byte in the hashed 4 KiB is fuzzed. Vary alignment and page position,
        // leaving prefix/suffix regions whose bytes must remain unchanged.
        uint256 prefix = uint256(placement % 3) * EmulatorConstants.PAGE_SIZE + prefixSeed;
        bytes memory data = new bytes(prefix + EmulatorConstants.PAGE_SIZE + 64);
        data[0] = 0x5a;
        data[data.length - 1] = 0xa5;
        for (uint256 i; i < words.length; ++i) {
            bytes32 word = words[i];
            assembly ("memory-safe") {
                mstore(add(add(data, 32), add(prefix, shl(5, i))), word)
            }
        }
        for (uint256 log2Size = 5; log2Size <= 12; ++log2Size) {
            compareSlice(data, prefix, uint256(1) << log2Size);
        }
    }

    function testKnownPatterns() public pure {
        bytes memory data = new bytes(EmulatorConstants.PAGE_SIZE);
        compareSlice(data, 0, EmulatorConstants.PAGE_SIZE);
        for (uint256 i; i < data.length; ++i) {
            data[i] = 0xff;
        }
        compareSlice(data, 0, EmulatorConstants.PAGE_SIZE);
        for (uint256 i; i < data.length; ++i) {
            data[i] = bytes1(uint8(i));
        }
        compareSlice(data, 0, EmulatorConstants.PAGE_SIZE);
        for (uint256 i; i < data.length; ++i) {
            data[i] = i % 2 == 0 ? bytes1(0x55) : bytes1(0xaa);
        }
        compareSlice(data, 0, EmulatorConstants.PAGE_SIZE);
    }
}
