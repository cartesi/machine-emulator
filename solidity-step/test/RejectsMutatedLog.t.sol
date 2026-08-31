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
pragma solidity ^0.8.30;

import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// The wire format is tightly packed (no padding, trailing bytes and nonzero scratch rejected), so
/// every byte is bound into the recomputed pre-state root or a count: flipping any one must revert.
contract RejectsMutatedLogTest is ManifestParser {
    bytes fixture;
    bytes32 rootHashBefore;

    function setUp() public {
        Row memory row;
        (fixture, row) = sampleStepLog();
        rootHashBefore = row.rootHashBefore;
    }

    /// Flip one byte (xor a non-zero mask) at an arbitrary offset and require rejection.
    /// forge-config: default.fuzz.runs = 2048
    function testFuzzSingleByteFlipRejected(uint256 index, uint8 mask) public {
        vm.assume(mask != 0);
        index = bound(index, 0, fixture.length - 1);
        bytes memory bad = bytes(fixture);
        bad[index] = bytes1(uint8(bad[index]) ^ mask);
        vm.expectRevert();
        this.verifyStep(bad, rootHashBefore);
    }

    /// External wrapper so `log` arrives as calldata for StepLog.decode.
    function verifyStep(bytes calldata log, bytes32 rootBefore) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore);
    }
}

/// Same soundness invariant for the uarch-reset proof. The reset accesses the revert root hash and
/// htif.tohost, recording their shadow page into the log; this fuzz proves every byte of that
/// page -- and of the node and header -- is bound, so no single-byte flip can yield an accepted
/// reset. Fuzzed over the real reset fixture.
contract RejectsMutatedResetLogTest is ManifestParser {
    string constant RESET_DIR = "test/fixtures/reset-uarch";
    string constant MANIFEST_CSV = "test/fixtures/reset-uarch/_manifest.csv";

    bytes fixture;
    bytes32 rootHashBefore;

    function setUp() public {
        Row memory row = firstRow(MANIFEST_CSV, Kind.ResetUarch);
        fixture = vm.readFileBinary(string.concat(RESET_DIR, "/", row.name));
        rootHashBefore = row.rootHashBefore;
    }

    /// Flip one byte (xor a non-zero mask) at an arbitrary offset and require rejection.
    /// forge-config: default.fuzz.runs = 2048
    function testFuzzSingleByteFlipRejected(uint256 index, uint8 mask) public {
        vm.assume(mask != 0);
        index = bound(index, 0, fixture.length - 1);
        bytes memory bad = bytes(fixture);
        bad[index] = bytes1(uint8(bad[index]) ^ mask);
        vm.expectRevert();
        this.verifyReset(bad, rootHashBefore);
    }

    /// External wrapper so `log` arrives as calldata for StepLog.decode.
    function verifyReset(bytes calldata log, bytes32 rootBefore) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyReset(ctx, rootBefore);
    }
}
