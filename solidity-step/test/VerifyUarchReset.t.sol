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

import {console} from "forge-std/Test.sol";

import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Replays the three reset_uarch fixtures (plain, rejected, accepted) via Verify.verifyReset.
contract VerifyUarchResetTest is ManifestParser {
    string constant RESET_DIR = "test/fixtures/reset-uarch";
    string constant MANIFEST_CSV = "test/fixtures/reset-uarch/_manifest.csv";

    function testReplaysReset() public {
        Row[] memory rows = readManifestRows(MANIFEST_CSV, Kind.ResetUarch);
        require(rows.length == 3, "expected the plain, rejected, and accepted reset rows");
        for (uint256 i = 0; i < rows.length; i++) {
            console.log("Replaying reset:", rows[i].name);
            bytes memory log = vm.readFileBinary(string.concat(RESET_DIR, "/", rows[i].name));
            this.replayReset(log, rows[i]);
        }
    }

    /// External self-call so `log` arrives as `bytes calldata` for StepLog.decode.
    function replayReset(bytes calldata log, Row memory r) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        // The reset reads iflags.Y, forcing page 0 (which holds the revert root hash slot) into this
        // proof, so the revert hash round-trips off the witnessed page in every case.
        require(
            StateAccess.readRevertRootHash(ctx) == r.revertRootHash, "revert hash not in reset log"
        );
        // The rejected reset substitutes the revert hash (== rootHashAfter); the plain and accepted
        // resets do not revert and check the recomputed tree root. All must agree with the manifest.
        Verify.verifyReset(ctx, r.rootHashBefore, r.rootHashAfter);
    }
}
