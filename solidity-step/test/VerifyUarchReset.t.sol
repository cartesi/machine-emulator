// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";

import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Replays the singleton reset_uarch fixture via Verify.verifyReset.
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
