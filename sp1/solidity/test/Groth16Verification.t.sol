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

import {Test} from "forge-std/Test.sol";
import {ISP1Verifier} from "sp1-contracts/ISP1Verifier.sol";
import {CartesiSp1StepVerifier} from "../src/CartesiSp1StepVerifier.sol";

/// seal.bin is a real proof of the one-mcycle step log, so a passing run means
/// the deployed Sepolia verifier accepts a proof this pipeline produced end to
/// end. Generate it with `make -C sp1 fixtures seal`.
contract Groth16VerificationTest is Test {
    // SP1_VERIFIER_GATEWAY_GROTH16 on Sepolia, from succinctlabs/sp1-contracts
    // deployments/11155111.json. Routes on the seal's 4-byte selector.
    address constant VERIFIER_GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    bytes32 constant WRONG_HASH = bytes32(uint256(1));

    // The step transition the committed seal proves: the one-mcycle fixture.
    // Spelled out rather than read from a journal.bin, because the journal is
    // just abi.encode of these three values -- storing it would be storing a
    // derivation of data already here, and it would hide what the proof asserts.
    bytes32 constant ROOT_HASH_BEFORE = 0x5640b321bff684d65cfe3fb077276638d9cddc9646c881688b145ff44af732a7;
    uint64 constant MCYCLE_COUNT = 1;
    bytes32 constant ROOT_HASH_AFTER = 0xa4b56312ccbe75348f78191ba2b96d213908d89a34a2cb2346d03613ab6843d1;

    CartesiSp1StepVerifier stepVerifier;
    bytes seal;
    bytes journal;

    function setUp() public {
        stepVerifier = new CartesiSp1StepVerifier(ISP1Verifier(VERIFIER_GATEWAY));
        seal = vm.readFileBinary("./test/fixtures/seal.bin");
        journal = abi.encode(ROOT_HASH_BEFORE, MCYCLE_COUNT, ROOT_HASH_AFTER);
    }

    function test_validProofVerifies() public view {
        stepVerifier.verifyStep(seal, journal, ROOT_HASH_BEFORE, MCYCLE_COUNT, ROOT_HASH_AFTER);
    }

    function test_wrongRootHashBeforeReverts() public {
        vm.expectRevert("root_hash_before mismatch");
        stepVerifier.verifyStep(seal, journal, WRONG_HASH, MCYCLE_COUNT, ROOT_HASH_AFTER);
    }

    function test_wrongMcycleCountReverts() public {
        vm.expectRevert("mcycle_count mismatch");
        stepVerifier.verifyStep(seal, journal, ROOT_HASH_BEFORE, MCYCLE_COUNT + 1, ROOT_HASH_AFTER);
    }

    function test_wrongRootHashAfterReverts() public {
        vm.expectRevert("root_hash_after mismatch");
        stepVerifier.verifyStep(seal, journal, ROOT_HASH_BEFORE, MCYCLE_COUNT, WRONG_HASH);
    }

    /// The journal is what the proof commits to, so altering it must fail at the
    /// verifier even though the arguments still agree with the tampered values.
    function test_tamperedJournalReverts() public {
        bytes memory tamperedJournal = journal;
        tamperedJournal[95] ^= 0xff;
        (bytes32 tBefore, uint64 tMcycle, bytes32 tAfter) =
            abi.decode(tamperedJournal, (bytes32, uint64, bytes32));

        vm.expectRevert();
        stepVerifier.verifyStep(seal, tamperedJournal, tBefore, tMcycle, tAfter);
    }

    /// A proof is only meaningful against the guest it was produced for. The
    /// gateway must reject our seal when presented under a different vkey.
    function test_wrongVKeyReverts() public {
        ISP1Verifier gateway = ISP1Verifier(VERIFIER_GATEWAY);
        vm.expectRevert();
        gateway.verifyProof(WRONG_HASH, journal, seal);
    }
}
