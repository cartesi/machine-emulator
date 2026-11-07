pragma solidity ^0.8.30;
import "./UArchStep.sol";
import "./UArchReset.sol";
import "./SendCmioResponse.sol";

contract Harness {
    using AccessLogs for AccessLogs.Context;
    function stepOnly(bytes32 root, bytes calldata proof) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = AccessLogs.Context(root, Buffer.Context(proof, 0));
        UArchStep.UArchStepStatus s = UArchStep.step(a);
        require(a.buffer.data.length == a.buffer.offset, "buffer should be fully consumed");
        return (a.currentRootHash, uint8(s));
    }
    function resetOnly(bytes32 root, bytes calldata proof) external pure returns (bytes32) {
        AccessLogs.Context memory a = AccessLogs.Context(root, Buffer.Context(proof, 0));
        UArchReset.reset(a);
        require(a.buffer.data.length == a.buffer.offset, "buffer should be fully consumed");
        return a.currentRootHash;
    }
    function stepReset(bytes32 root, bytes calldata proof) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = AccessLogs.Context(root, Buffer.Context(proof, 0));
        UArchStep.UArchStepStatus s = UArchStep.step(a);
        UArchReset.reset(a);
        require(a.buffer.data.length == a.buffer.offset, "buffer should be fully consumed");
        return (a.currentRootHash, uint8(s));
    }
    function send(bytes32 root, uint16 reason, bytes32 dataHash, uint32 len, bytes32 revertRoot, bytes calldata proof) external pure returns (bytes32) {
        AccessLogs.Context memory a = AccessLogs.Context(root, Buffer.Context(proof, 0));
        SendCmioResponse.sendCmioResponse(a, reason, dataHash, len, revertRoot);
        require(a.buffer.data.length == a.buffer.offset, "buffer should be fully consumed");
        return a.currentRootHash;
    }

    function bridge(bytes32 root, uint256 flags, bytes32 dataHash, bytes calldata proof) external pure returns (bytes32) {
        // flags: 1 = at input start, 2 = slot holds input, 4 = last ucycle (reset)
        bytes calldata rest = proof;
        uint256 len = 0;
        if (flags & 1 != 0) {
            len = uint64(bytes8(proof[0:8]));
            rest = proof[8 + len:];
        }
        AccessLogs.Context memory a = AccessLogs.Context(root, Buffer.Context(rest, 0));
        if (flags & 2 != 0) {
            SendCmioResponse.sendCmioResponse(a, EmulatorConstants.HTIF_YIELD_REASON_ADVANCE_STATE, dataHash, uint32(len), root);
        }
        UArchStep.step(a);
        if (flags & 4 != 0) UArchReset.reset(a);
        require(a.buffer.data.length == a.buffer.offset, "buffer should be fully consumed");
        return a.currentRootHash;
    }
}
