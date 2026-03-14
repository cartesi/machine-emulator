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

import {Test, console} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CartesiStepVerifier} from "../src/CartesiStepVerifier.sol";

contract Groth16VerificationTest is Test {
    // RISC Zero Verifier Router on Sepolia
    address constant VERIFIER_ROUTER = 0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187;

    CartesiStepVerifier stepVerifier;
    bytes seal;
    bytes journal;

    function setUp() public {
        stepVerifier = new CartesiStepVerifier(IRiscZeroVerifier(VERIFIER_ROUTER));
        seal = vm.readFileBinary("../test/fixtures/seal.bin");
        journal = vm.readFileBinary("../test/fixtures/journal.bin");
    }

    function test_validProofVerifies() public view {
        (bytes32 rootHashBefore, uint64 mcycleCount, bytes32 rootHashAfter) =
            stepVerifier.verifyStep(seal, journal);

        console.log("Verified step transition:");
        console.log("  root_hash_before:", vm.toString(rootHashBefore));
        console.log("  mcycle_count:", mcycleCount);
        console.log("  root_hash_after:", vm.toString(rootHashAfter));
    }

    function test_tamperedJournalReverts() public {
        bytes memory tamperedJournal = journal;
        tamperedJournal[95] ^= 0xff;

        vm.expectRevert();
        stepVerifier.verifyStep(seal, tamperedJournal);
    }

    function test_wrongImageIdReverts() public {
        IRiscZeroVerifier router = IRiscZeroVerifier(VERIFIER_ROUTER);
        bytes32 journalDigest = sha256(journal);
        bytes32 fakeImageId = bytes32(uint256(1));

        vm.expectRevert();
        router.verify(seal, fakeImageId, journalDigest);
    }
}
