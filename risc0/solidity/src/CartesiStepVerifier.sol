// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol";

/// @title CartesiStepVerifier
/// @notice Verifies Cartesi Machine step transitions using RISC Zero Groth16 proofs.
///         The caller provides a Groth16 seal and ABI-encoded journal. This contract
///         verifies the proof via the RISC Zero Verifier Router and decodes the
///         journal into the step transition values.
contract CartesiStepVerifier {
    IRiscZeroVerifier public immutable verifier;

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    /// @notice Verify a Cartesi Machine step transition.
    /// Reverts if the proof is invalid or the journal does not match the expected values.
    /// @param seal Groth16 seal (260 bytes: 4-byte selector + 256-byte proof)
    /// @param journal ABI-encoded journal: abi.encode(bytes32, uint64, bytes32)
    /// @param rootHashBefore Expected machine state hash before the step
    /// @param mcycleCount Expected number of machine cycles executed
    /// @param rootHashAfter Expected machine state hash after the step
    function verifyStep(
        bytes calldata seal,
        bytes calldata journal,
        bytes32 rootHashBefore,
        uint64 mcycleCount,
        bytes32 rootHashAfter
    ) external view {
        (bytes32 jHashBefore, uint64 jMcycle, bytes32 jHashAfter) =
            abi.decode(journal, (bytes32, uint64, bytes32));
        require(jHashBefore == rootHashBefore, "root_hash_before mismatch");
        require(jMcycle == mcycleCount, "mcycle_count mismatch");
        require(jHashAfter == rootHashAfter, "root_hash_after mismatch");
        verifier.verify(seal, ImageID.CARTESI_STEP_VERIFIER_ID, sha256(journal));
    }
}
