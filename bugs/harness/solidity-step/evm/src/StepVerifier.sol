// SPDX-License-Identifier: Apache-2.0
// Audit harness: external entry points over the regenerated machine-solidity-step libraries, so scripts can
// verify emulator access logs on an EVM (anvil) with eth_call. Proof bytes use the encoding of the PRT
// recipes (doc/recipes/prt-ethereum.lua append_log, = what Dave's CartesiStateTransition consumes):
// per access, a word access (log2_size 3) contributes its 32-byte leaf; a region read contributes read data
// (32 bytes) and read_hash; otherwise read_hash; then the sibling hashes, leaf to root.
pragma solidity ^0.8.30;

import {AccessLogs} from "step/src/AccessLogs.sol";
import {Buffer} from "step/src/Buffer.sol";
import {EmulatorConstants} from "step/src/EmulatorConstants.sol";
import {MetaStep} from "step/src/MetaStep.sol";
import {SendCmioResponse} from "step/src/SendCmioResponse.sol";
import {UArchReset} from "step/src/UArchReset.sol";
import {UArchStep} from "step/src/UArchStep.sol";

contract StepVerifier {
    error ProofNotFullyConsumed(uint256 consumed, uint256 provided);

    function _ctx(bytes32 root, bytes calldata proofs) private pure returns (AccessLogs.Context memory) {
        return AccessLogs.Context(root, Buffer.Context(proofs, 0));
    }

    function _consumed(AccessLogs.Context memory a) private pure {
        if (a.buffer.offset != a.buffer.data.length) {
            revert ProofNotFullyConsumed(a.buffer.offset, a.buffer.data.length);
        }
    }

    /// One uarch step (UArchStep.step); returns the after root and the UArchStepStatus.
    function step(bytes32 root, bytes calldata proofs) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        UArchStep.UArchStepStatus s = UArchStep.step(a);
        _consumed(a);
        return (a.currentRootHash, uint8(s));
    }

    /// The uarch reset (UArchReset.reset).
    function reset(bytes32 root, bytes calldata proofs) external pure returns (bytes32) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        UArchReset.reset(a);
        _consumed(a);
        return a.currentRootHash;
    }

    /// A uarch step followed by the reset (the closing transition of an mcycle).
    function stepThenReset(bytes32 root, bytes calldata proofs) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        UArchStep.UArchStepStatus s = UArchStep.step(a);
        UArchReset.reset(a);
        _consumed(a);
        return (a.currentRootHash, uint8(s));
    }

    /// SendCmioResponse.sendCmioResponse with the given data hash (keccak Merkle root of the padded data,
    /// as the referee computes it) and length.
    function sendCmioResponse(
        bytes32 root,
        uint16 reason,
        bytes32 dataHash,
        uint32 length,
        bytes32 revertRootHash,
        bytes calldata proofs
    ) external pure returns (bytes32) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        SendCmioResponse.sendCmioResponse(a, reason, dataHash, length, revertRootHash);
        _consumed(a);
        return a.currentRootHash;
    }

    /// Input delivery followed by a uarch step (the opening transition of an input slot).
    function sendCmioResponseThenStep(
        bytes32 root,
        bytes32 dataHash,
        uint32 length,
        bytes calldata proofs
    ) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        SendCmioResponse.sendCmioResponse(
            a, EmulatorConstants.HTIF_YIELD_REASON_ADVANCE_STATE, dataHash, length, root
        );
        UArchStep.UArchStepStatus s = UArchStep.step(a);
        _consumed(a);
        return (a.currentRootHash, uint8(s));
    }

    /// MetaStep.step (step, plus reset when counter is a multiple of the uarch span).
    function metaStep(bytes32 root, uint256 counter, bytes calldata proofs) external pure returns (bytes32, uint8) {
        AccessLogs.Context memory a = _ctx(root, proofs);
        UArchStep.UArchStepStatus s = MetaStep.step(counter, a);
        return (a.currentRootHash, uint8(s));
    }

    function constants() external pure returns (uint64 marchid, bytes32 pristine) {
        return (EmulatorConstants.CM_MARCHID, EmulatorConstants.UARCH_PRISTINE_STATE_HASH);
    }
}
