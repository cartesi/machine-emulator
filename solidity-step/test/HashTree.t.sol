// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {HashTree} from "src/HashTree.sol";

/// Cross-checks src/HashTree.sol's two primitives against independent oracles:
/// merkleTreeHash vs an iterative bottom-up reference; merkleTreeHashPadded vs
/// brute-force "materialise the pad, then merkleTreeHash".
contract HashTreeTest is Test {
    // Literals: Solidity can't use cross-library constants in fixed-array sizes.
    uint256 constant PAGE_LEAF_COUNT = 128;
    uint256 constant SIBLING_SIZE = 32;

    /// Iterative bottom-up reference oracle: halves the level array in place.
    /// Independent of production's recursive merkleTreeHash.
    function hashIter(bytes memory pageData, uint256 startOffset) internal pure returns (bytes32) {
        bytes32[PAGE_LEAF_COUNT] memory level;
        for (uint256 i = 0; i < PAGE_LEAF_COUNT; i++) {
            bytes32 word;
            assembly {
                word := mload(add(add(pageData, 32), add(startOffset, mul(i, SIBLING_SIZE))))
            }
            level[i] = keccak256(abi.encodePacked(word));
        }
        uint256 n = PAGE_LEAF_COUNT;
        while (n > 1) {
            n >>= 1;
            for (uint256 i = 0; i < n; i++) {
                level[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            }
        }
        return level[0];
    }

    /// The recursive production hash must agree with the iterative oracle on both a
    /// pristine (all-zero) page and a non-trivial one.
    function testRecursiveMatchesIterative() public pure {
        bytes memory zero = new bytes(EmulatorConstants.PAGE_SIZE);
        bytes memory data = filler(EmulatorConstants.PAGE_SIZE);
        for (uint256 p = 0; p < 2; p++) {
            bytes memory page = p == 0 ? zero : data;
            bytes32 rec = HashTree.merkleTreeHash(page, 0, EmulatorConstants.PAGE_SIZE);
            bytes32 iter = hashIter(page, 0);
            assertEq(rec, iter, "production recursive disagrees with iterative oracle");
        }
    }

    /// Brute-force oracle: materialise `data || zeros` of 2^totalLog2Size bytes and
    /// hash via merkleTreeHash.
    function padAndHash(bytes memory data, uint8 totalLog2Size) internal pure returns (bytes32) {
        uint256 totalSize = uint256(1) << totalLog2Size;
        require(totalSize >= data.length, "totalSize < data.length");
        bytes memory padded = new bytes(totalSize); // zero-initialised
        uint256 srcLen = data.length;
        assembly {
            mcopy(add(padded, 32), add(data, 32), srcLen)
        }
        return HashTree.merkleTreeHash(padded, 0, totalSize);
    }

    /// Hand-picked sizes that exercise each branch of merkleTreeHashPadded's
    /// recursion: entirely-pristine, entirely-within, leaf-overlap, mixed
    /// supra-page, full (no padding).
    function testFixedBoundaries() public view {
        // log2Size 13 = 8 KB (smallest supra-page case)
        check("", 13);
        check(filler(1), 13);
        check(filler(32), 13); // exactly one leaf
        check(filler(33), 13); // leaf-overlap branch
        check(filler(4096), 13); // exactly one page
        check(filler(4097), 13); // mixed supra-page
        check(filler((1 << 13) - 1), 13);
        check(filler(1 << 13), 13); // no padding

        // log2Size 17 = 128 KB (matches our largest cmio fixture write size)
        check("", 17);
        check(filler(1), 17);
        check(filler(65536), 17);
        check(filler((1 << 17) - 1), 17);
        check(filler(1 << 17), 17);
    }

    /// Random data + random log2Size in [LEAF_LOG2, 17]; 17 caps per-iteration
    /// memory while still spanning the leaf-overlap regime.
    function testFuzz(bytes memory data, uint8 log2Size) public view {
        log2Size = uint8(bound(uint256(log2Size), EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE, 17));
        uint256 totalSize = uint256(1) << log2Size;
        if (data.length > totalSize) {
            // Trim rather than reject: avoids wasted fuzz runs.
            assembly {
                mstore(data, totalSize)
            }
        }
        check(data, log2Size);
    }

    /// log2Size outside [WORD, ROOT) is rejected.
    function testRejectsBadPaddedLog2() public {
        vm.expectPartialRevert(HashTree.PaddedMerkleHashLog2SizeOutOfRange.selector);
        this.calldataWrap("", EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE - 1); // too small
        vm.expectPartialRevert(HashTree.PaddedMerkleHashLog2SizeOutOfRange.selector);
        this.calldataWrap("", EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE); // == root, too large
    }

    /// Data longer than the padded region is rejected.
    function testRejectsOversizedData() public {
        vm.expectPartialRevert(HashTree.DataExceedsPaddedSize.selector);
        this.calldataWrap(filler((1 << 13) + 1), 13);
    }

    function check(bytes memory data, uint8 log2Size) internal view {
        bytes32 oracle = padAndHash(data, log2Size);
        bytes32 fast = this.calldataWrap(data, log2Size);
        assertEq(fast, oracle, "merkleTreeHashPadded disagrees with brute-force oracle");
    }

    /// Calldata bridge: merkleTreeHashPadded takes `bytes calldata`.
    function calldataWrap(bytes calldata data, uint8 log2Size) external pure returns (bytes32) {
        return HashTree.merkleTreeHashPadded(data, log2Size);
    }

    /// a..z cycling, so a byte error surfaces as a hash mismatch rather than a same-byte hash.
    function filler(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[i] = bytes1(uint8(0x61 + (i % 26)));
        }
    }
}
