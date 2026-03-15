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
