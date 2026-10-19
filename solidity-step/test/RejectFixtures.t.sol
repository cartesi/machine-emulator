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

import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Replays the shared reject fixtures and asserts the Solidity verifier rejects every entry
/// with the error its `expectError` tag names. The same logs run through the C++ host, so a
/// tag pins identical rejection across implementations. Generation and the tag vocabulary
/// live with the recorders: tests/lua/record-adversarial-uarch.lua (step + reset) and
/// record-adversarial-send-cmio-response.lua. One cmio rejection (a response whose length implies a
/// write size the log's node was not recorded for) is about the data argument rather than the log
/// bytes, so it can't be a fixture row and is checked inline.
contract RejectFixturesTest is ManifestParser {
    string constant UARCH_DIR = "test/fixtures/reject-uarch";
    string constant UARCH_MANIFEST = "test/fixtures/reject-uarch/_manifest.csv";
    string constant REJECT_SEND_CMIO_RESPONSE_DIR = "test/fixtures/reject-send-cmio-response";
    string constant REJECT_SEND_CMIO_RESPONSE_MANIFEST =
        "test/fixtures/reject-send-cmio-response/_manifest.csv";
    string constant SEND_CMIO_RESPONSE_DIR = "test/fixtures/send-cmio-response";
    string constant SEND_CMIO_RESPONSE_MANIFEST = "test/fixtures/send-cmio-response/_manifest.csv";

    function testRejectsUarchSteps() public {
        replayUarch(Kind.Cycle);
    }

    function testRejectsUarchResets() public {
        replayUarch(Kind.ResetUarch);
    }

    function testRejectsCmio() public {
        Row[] memory rows =
            readManifestRows(REJECT_SEND_CMIO_RESPONSE_MANIFEST, Kind.SendCmioResponse);
        require(rows.length > 0, "no cmio reject rows");
        for (uint256 i = 0; i < rows.length; i++) {
            bytes memory log =
                vm.readFileBinary(string.concat(REJECT_SEND_CMIO_RESPONSE_DIR, "/", rows[i].name));
            if (isRootAfterMismatchTag(rows[i].expectError)) {
                bytes32 obtained = this.verifyCmio(
                    log,
                    rows[i].rootHashBefore,
                    rows[i].reason,
                    rows[i].data,
                    rows[i].revertRootHash
                );
                assertEq(
                    obtained, trueAfter(rows[i]), "replay must return the true transition root"
                );
                assertTrue(obtained != rows[i].rootHashAfter, "forged transition must not verify");
                continue;
            }
            expectRevertFor(rows[i].expectError);
            this.verifyCmio(
                log, rows[i].rootHashBefore, rows[i].reason, rows[i].data, rows[i].revertRootHash
            );
        }
    }

    /// A response whose length implies a different write size than the log's node was
    /// recorded for must be rejected. Like the oversized case, the mismatch is in the data
    /// argument (independent of the log's tree), so it is built inline against a supra-page
    /// fixture rather than carried as a row.
    function testRejectsCmioNodeWrongSize() public {
        Row[] memory rows = readManifestRows(SEND_CMIO_RESPONSE_MANIFEST, Kind.SendCmioResponse);
        Row memory big;
        bool found;
        for (uint256 i = 0; i < rows.length; i++) {
            if (rows[i].dataLength >= 65536) {
                big = rows[i];
                found = true;
                break;
            }
        }
        require(found, "need a >=64 KB cmio fixture");
        bytes memory log = vm.readFileBinary(string.concat(SEND_CMIO_RESPONSE_DIR, "/", big.name));
        // The node is sized for 64 KB; claim a smaller supra-page write (4097 B -> log2 13).
        bytes memory data = new bytes(4097);
        vm.expectPartialRevert(StateAccess.WriteMemoryNodeWrongSize.selector);
        this.verifyCmio(log, big.rootHashBefore, big.reason, data, big.revertRootHash);
    }

    function replayUarch(Kind kind) internal {
        Row[] memory rows = readManifestRows(UARCH_MANIFEST, kind);
        require(rows.length > 0, "no uarch reject rows for kind");
        for (uint256 i = 0; i < rows.length; i++) {
            bytes memory log = vm.readFileBinary(string.concat(UARCH_DIR, "/", rows[i].name));
            if (isRootAfterMismatchTag(rows[i].expectError)) {
                bytes32 obtained = kind == Kind.Cycle
                    ? this.verifyCycle(log, rows[i].rootHashBefore)
                    : this.verifyReset(log, rows[i].rootHashBefore);
                assertEq(
                    obtained, trueAfter(rows[i]), "replay must return the true transition root"
                );
                assertTrue(obtained != rows[i].rootHashAfter, "forged transition must not verify");
                continue;
            }
            expectRevertFor(rows[i].expectError);
            if (kind == Kind.Cycle) {
                this.verifyCycle(log, rows[i].rootHashBefore);
            } else {
                this.verifyReset(log, rows[i].rootHashBefore);
            }
        }
    }

    /// The claimed root is forged; independently recorded base roots pin the exact
    /// result. The cleared-iflags case instead modifies the pre-state into a no-op.
    function trueAfter(Row memory row) internal returns (bytes32) {
        if (row.kind == Kind.Cycle) {
            return findManifestRowByName(
                string.concat(UARCH_PER_CYCLE_DIR, "/rv64ui-uarch-add/_manifest.csv"),
                Kind.Cycle,
                "00000.log"
            ).rootHashAfter;
        }
        if (row.kind == Kind.ResetUarch) {
            return findManifestRowByName(
                "test/fixtures/reset-uarch/_manifest.csv", Kind.ResetUarch, "reset-uarch.log"
            ).rootHashAfter;
        }
        if (keccak256(bytes(row.name)) == keccak256("cmio_iflags_cleared.log")) {
            return row.rootHashBefore;
        }
        return findManifestRowByName(
            SEND_CMIO_RESPONSE_MANIFEST, Kind.SendCmioResponse, "send-cmio-response-1.log"
        ).rootHashAfter;
    }

    /// The one tag whose rejection is not a revert: the verifier returns an obtained root
    /// the caller's comparison must refuse.
    function isRootAfterMismatchTag(string memory tag) internal pure returns (bool) {
        return keccak256(bytes(tag)) == keccak256("root_after_mismatch");
    }

    /// The recorder exports the shared C++ message/Solidity signature table.
    /// Keeping both expectations in each entry prevents independent tag vocabularies.
    function expectRevertFor(string memory tag) internal {
        string memory errors = vm.readFile(string.concat(UARCH_DIR, "/_errors.json"));
        string memory signature =
            vm.parseJsonString(errors, string.concat(".", tag, ".solidity_signature"));
        require(bytes(signature).length != 0, "unmapped reject selector");
        string memory message =
            vm.parseJsonString(errors, string.concat(".", tag, ".solidity_message"));
        bytes4 selector = bytes4(keccak256(bytes(signature)));
        if (bytes(message).length != 0) {
            vm.expectRevert(abi.encodeWithSelector(selector, message));
        } else {
            vm.expectPartialRevert(selector);
        }
    }

    // External wrappers so `log`/`data` arrive as calldata for StepLog.decode.

    function verifyCycle(bytes calldata log, bytes32 rootBefore) external pure returns (bytes32) {
        StepLog.Context memory ctx = StepLog.decode(log);
        return Verify.verifyStep(ctx, rootBefore);
    }

    function verifyReset(bytes calldata log, bytes32 rootBefore) external pure returns (bytes32) {
        StepLog.Context memory ctx = StepLog.decode(log);
        return Verify.verifyReset(ctx, rootBefore);
    }

    function verifyCmio(
        bytes calldata log,
        bytes32 rootBefore,
        uint16 reason,
        bytes calldata data,
        bytes32 revertRootHash
    ) external pure returns (bytes32) {
        StepLog.Context memory ctx = StepLog.decode(log);
        return Verify.verifySendCmioResponse(ctx, rootBefore, reason, data, revertRootHash);
    }
}
