// SPDX-License-Identifier: Apache-2.0
// R1-A7-2 input sender: adds n copies of one payload to the InputBox in one transaction (about 30k gas per
// input, the batching that Dave's docs/dimensioning.md prices the flood with). Compiled bytecode: Flood.bin
// (build-flood.sh, solc 0.8.30 --optimize).
pragma solidity ^0.8.30;

interface IInputBox {
    function addInput(address appContract, bytes calldata payload) external returns (bytes32);
}

contract Flood {
    function flood(IInputBox box, address app, bytes calldata payload, uint256 n) external {
        for (uint256 i; i < n; ++i) {
            box.addInput(app, payload);
        }
    }
}
