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

import {Test} from "forge-std/Test.sol";
import {RiscZeroVerifierRouter} from "risc0/RiscZeroVerifierRouter.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {CartesiStepVerifier} from "../src/CartesiStepVerifier.sol";

contract Groth16VerificationTest is Test {
    bytes32 constant WRONG_HASH = bytes32(uint256(1));

    RiscZeroVerifierRouter router;
    CartesiStepVerifier stepVerifier;
    bytes seal;
    bytes journal;
    bytes32 rootHashBefore;
    uint64 mcycleCount;
    bytes32 rootHashAfter;

    function setUp() public {
        RiscZeroGroth16Verifier verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        router = new RiscZeroVerifierRouter(address(this));
        router.addVerifier(verifier.SELECTOR(), verifier);
        stepVerifier = new CartesiStepVerifier(router);
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
        bytes32 journalDigest = sha256(journal);
        bytes32 fakeImageId = WRONG_HASH;

        vm.expectRevert();
        router.verify(seal, fakeImageId, journalDigest);
    }
}
