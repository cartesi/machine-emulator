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

/// Pins that Verify.verifyStep runs exactly one uarch step. A one-cycle log cannot catch a
/// verifier that loops, so the two-cycle log (same starting state) is replayed and must land
/// on the one-cycle log's root, not its own endpoint.
contract VerifyUarchMultiCycleTest is ManifestParser {
    string constant DIR = "test/fixtures/uarch-multi-cycle";
    string constant MANIFEST = "test/fixtures/uarch-multi-cycle/_manifest.csv";

    function testMultiCycleLogVerifiesOnlyItsFirstCycle() public {
        Row memory one = findManifestRowByName(MANIFEST, Kind.Cycle, "one-cycle.log");
        Row memory two = findManifestRowByName(MANIFEST, Kind.Cycle, "two-cycle.log");
        assertEq(one.rootHashBefore, two.rootHashBefore, "both logs must share a starting state");
        assertGt(two.requestedCycleCount, 1, "two-cycle fixture must be multi-cycle");
        bytes memory log = vm.readFileBinary(string.concat(DIR, "/", two.name));
        assertEq(
            this.verifyStep(log, two.rootHashBefore),
            one.rootHashAfter,
            "one step of a two-cycle log must land on the one-cycle root"
        );
    }

    /// External wrapper so `log` arrives as calldata for StepLog.decode.
    function verifyStep(bytes calldata log, bytes32 rootBefore) external pure returns (bytes32) {
        StepLog.Context memory ctx = StepLog.decode(log);
        return Verify.verifyStep(ctx, rootBefore);
    }
}
