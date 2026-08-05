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

pragma solidity ^0.8.20;

import {ISP1Verifier} from "sp1-contracts/ISP1Verifier.sol";
import {VKeyHash} from "./VKeyHash.sol";

/// @title CartesiSp1StepVerifier
/// @notice Verifies Cartesi Machine step transitions using SP1 Groth16 proofs.
///         The caller provides a Groth16 seal and ABI-encoded journal. This
///         contract verifies the proof through the SP1 Verifier Gateway and
///         checks the journal against the expected step transition.
contract CartesiSp1StepVerifier {
    ISP1Verifier public immutable verifier;

    constructor(ISP1Verifier _verifier) {
        verifier = _verifier;
    }

    /// @notice Verify a Cartesi Machine step transition.
    /// Reverts if the proof is invalid or the journal does not match the expected values.
    /// @param seal SP1 Groth16 proof bytes (4-byte vkey-hash selector + proof)
    /// @param journal ABI-encoded public values: abi.encode(bytes32, uint64, bytes32)
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
        verifier.verifyProof(VKeyHash.CARTESI_SP1_STEP_VKEY, journal, seal);
    }
}
