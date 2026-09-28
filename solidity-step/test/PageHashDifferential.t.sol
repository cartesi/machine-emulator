// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {HashTree} from "src/HashTree.sol";

contract PageHashDifferentialTest is Test {
    function comparePage(bytes memory data, uint256 start) private pure {
        bytes32 contentsBefore = keccak256(data);
        bytes32 expected = HashTree.merkleTreeHash(data, start, EmulatorConstants.PAGE_SIZE);
        uint256 freeBefore;
        assembly ("memory-safe") {
            freeBefore := mload(0x40)
        }
        bytes32 actual = HashTree.merkleTreeHashAsm(data, start);
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
        assertEq(HashTree.merkleTreeHashAsm(data, start), expected, "reused scratch");
        // Subsequent Solidity allocation must initialize memory even where scratch
        // hashes were left above the free pointer.
        bytes memory later = new bytes(96);
        for (uint256 i; i < later.length; ++i) {
            assertEq(later[i], bytes1(0));
        }
        assertEq(HashTree.merkleTreeHashAsm(data, start), expected, "moved scratch");
    }

    function testEveryFixturePage() public view {
        VmSafe.DirEntry[] memory entries = vm.readDir("test/fixtures", 3);
        uint256 logs;
        uint256 pages;
        for (uint256 i; i < entries.length; ++i) {
            if (entries[i].isDir || !isLog(entries[i].path)) continue;
            uint256 count = this.compareLogPages(vm.readFileBinary(entries[i].path));
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

    function compareLogPages(bytes calldata log) external pure returns (uint256 pages) {
        // Read page bodies independently of decode. This includes complete page
        // entries in malformed/rejected logs; truncated bodies cannot supply 4 KiB.
        uint256 header = 40;
        uint256 entrySize = 8 + EmulatorConstants.PAGE_SIZE + 32;
        if (log.length < header) return 0;
        uint256 declared;
        for (uint256 i; i < 8; ++i) {
            declared |= uint256(uint8(log[16 + i])) << (i * 8);
        }
        uint256 available = (log.length - header) / entrySize;
        pages = declared < available ? declared : available;
        for (uint256 i; i < pages; ++i) {
            uint256 offset = header + i * entrySize + 8;
            bytes memory page = log[offset:offset + EmulatorConstants.PAGE_SIZE];
            comparePage(page, 0);
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
        comparePage(data, prefix);
    }

    function testKnownPatterns() public pure {
        bytes memory data = new bytes(EmulatorConstants.PAGE_SIZE);
        comparePage(data, 0);
        for (uint256 i; i < data.length; ++i) {
            data[i] = 0xff;
        }
        comparePage(data, 0);
        for (uint256 i; i < data.length; ++i) {
            data[i] = bytes1(uint8(i));
        }
        comparePage(data, 0);
        for (uint256 i; i < data.length; ++i) {
            data[i] = i % 2 == 0 ? bytes1(0x55) : bytes1(0xaa);
        }
        comparePage(data, 0);
    }
}
