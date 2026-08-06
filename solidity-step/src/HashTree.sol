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

import {EmulatorConstants} from "src/EmulatorConstants.sol";

library HashTree {
    error PaddedMerkleHashLog2SizeOutOfRange(uint8 log2Size);
    error DataExceedsPaddedSize(uint8 log2Size, uint256 dataLength);

    function merkleTreeHash(bytes memory data, uint256 start, uint256 size)
        internal
        pure
        returns (bytes32 result)
    {
        // Hashing goes through the EVM scratch space (0x00-0x40) rather than
        // abi.encodePacked, which would allocate a fresh buffer per node (255 per page).
        if (size > EmulatorConstants.LEAF_SIZE) {
            uint256 half = size >> 1;
            bytes32 left = merkleTreeHash(data, start, half);
            bytes32 right = merkleTreeHash(data, start + half, half);
            assembly ("memory-safe") {
                mstore(0x00, left)
                mstore(0x20, right)
                result := keccak256(0x00, 0x40)
            }
            return result;
        }
        assembly ("memory-safe") {
            // skip 32-byte length prefix; hash the single leaf word
            mstore(0x00, mload(add(add(data, 32), start)))
            result := keccak256(0x00, 0x20)
        }
    }

    /// Merkle root of `data` zero-padded to 2^totalLog2Size bytes. Subtrees entirely
    /// beyond `data.length` collapse to a precomputed pristine hash; subtrees entirely
    /// within fall through to `merkleTreeHash`. Only the boundary subtree at each level
    /// recurses.
    function merkleTreeHashPadded(bytes calldata data, uint8 totalLog2Size)
        internal
        pure
        returns (bytes32)
    {
        if (
            totalLog2Size < EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE
                || totalLog2Size >= EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE
        ) {
            revert PaddedMerkleHashLog2SizeOutOfRange(totalLog2Size);
        }
        if ((uint256(1) << totalLog2Size) < data.length) {
            revert DataExceedsPaddedSize(totalLog2Size, data.length);
        }

        // Pristine table is small and rebuilt per call (single caller, send_cmio_response).
        uint8 leafLog2 = EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE;
        bytes32[] memory pristine = new bytes32[](uint256(totalLog2Size) + 1);
        pristine[leafLog2] = keccak256(abi.encodePacked(bytes32(0)));
        for (uint8 k = leafLog2 + 1; k <= totalLog2Size; k++) {
            pristine[k] = keccak256(abi.encodePacked(pristine[k - 1], pristine[k - 1]));
        }
        bytes memory dataMem = data;
        return merkleSubtreeHashPadded(dataMem, data.length, 0, totalLog2Size, pristine);
    }

    function merkleSubtreeHashPadded(
        bytes memory data,
        uint256 dataLength,
        uint256 start,
        uint8 log2Size,
        bytes32[] memory pristine
    ) private pure returns (bytes32) {
        if (start >= dataLength) return pristine[log2Size];
        uint256 size = uint256(1) << log2Size;
        if (log2Size == EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE) {
            // A full in-bounds leaf goes through merkleTreeHash. A leaf straddling the
            // boundary is masked to zero past dataLength (bytes-memory padding is not
            // guaranteed zero); matches the C++ recorder's zeroed-buffer write.
            if (start + size <= dataLength) {
                return merkleTreeHash(data, start, size);
            }
            bytes32 word;
            assembly ("memory-safe") {
                word := mload(add(add(data, 32), start))
            }
            uint256 zeroBits = (size - (dataLength - start)) << 3;
            word = bytes32((uint256(word) >> zeroBits) << zeroBits);
            return keccak256(abi.encodePacked(word));
        }
        if (start + size <= dataLength) return merkleTreeHash(data, start, size);
        uint256 half = size >> 1;
        bytes32 left = merkleSubtreeHashPadded(data, dataLength, start, log2Size - 1, pristine);
        bytes32 right =
            merkleSubtreeHashPadded(data, dataLength, start + half, log2Size - 1, pristine);
        return keccak256(abi.encodePacked(left, right));
    }
}
