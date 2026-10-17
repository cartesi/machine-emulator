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

import {Test, console} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CartesiStepVerifier} from "../src/CartesiStepVerifier.sol";

contract Groth16VerificationTest is Test {
    // RISC Zero Verifier Router on Sepolia
    address constant VERIFIER_ROUTER = 0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187;
    bytes32 constant WRONG_HASH = bytes32(uint256(1));

    CartesiStepVerifier stepVerifier;
    bytes seal;
    bytes journal;
    bytes32 rootHashBefore;
    uint64 mcycleCount;
    bytes32 rootHashAfter;

    function setUp() public {
        stepVerifier = new CartesiStepVerifier(IRiscZeroVerifier(VERIFIER_ROUTER));
        seal = vm.readFileBinary("../test/fixtures/seal.bin");
        journal = vm.readFileBinary("../test/fixtures/journal.bin");
        (rootHashBefore, mcycleCount, rootHashAfter) =
            abi.decode(journal, (bytes32, uint64, bytes32));
    }

    function test_validProofVerifies() public view {
        stepVerifier.verifyStep(seal, journal, rootHashBefore, mcycleCount, rootHashAfter);
    }

    function test_wrongRootHashBeforeReverts() public {
        vm.expectRevert("root_hash_before mismatch");
        stepVerifier.verifyStep(seal, journal, WRONG_HASH, mcycleCount, rootHashAfter);
    }

    function test_wrongMcycleCountReverts() public {
        vm.expectRevert("mcycle_count mismatch");
        stepVerifier.verifyStep(seal, journal, rootHashBefore, mcycleCount + 1, rootHashAfter);
    }

    function test_wrongRootHashAfterReverts() public {
        vm.expectRevert("root_hash_after mismatch");
        stepVerifier.verifyStep(seal, journal, rootHashBefore, mcycleCount, WRONG_HASH);
    }

    function test_tamperedJournalReverts() public {
        bytes memory tamperedJournal = journal;
        tamperedJournal[95] ^= 0xff;

        vm.expectRevert();
        stepVerifier.verifyStep(seal, tamperedJournal, rootHashBefore, mcycleCount, rootHashAfter);
    }

    function test_wrongImageIdReverts() public {
        IRiscZeroVerifier router = IRiscZeroVerifier(VERIFIER_ROUTER);
        bytes32 journalDigest = sha256(journal);
        bytes32 fakeImageId = WRONG_HASH;

        vm.expectRevert();
        router.verify(seal, fakeImageId, journalDigest);
    }
}
