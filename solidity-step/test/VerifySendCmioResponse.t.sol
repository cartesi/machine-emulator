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

import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// Replays each send_cmio_response fixture row via Verify.verifySendCmioResponse, covering
/// sub-leaf through supra-page payload writes. The manifest carries the raw payload bytes
/// (column `data`); the verifier hashes it on-chain.
contract VerifySendCmioResponseTest is ManifestParser {
    string constant CMIO_DIR = "test/fixtures/send-cmio-response";
    string constant MANIFEST_CSV = "test/fixtures/send-cmio-response/_manifest.csv";

    struct ReplayArgs {
        bytes32 rootHashBefore;
        bytes32 rootHashAfter;
        bytes32 revertRootHash;
        uint16 reason;
    }

    function testReplaysCmio() public {
        Row[] memory rows = readManifestRows(MANIFEST_CSV, Kind.SendCmioResponse);
        require(rows.length > 0, "expected at least one cmio row");
        for (uint256 i = 0; i < rows.length; i++) {
            console.log("Replaying cmio:", rows[i].name);
            bytes memory log = vm.readFileBinary(string.concat(CMIO_DIR, "/", rows[i].name));
            ReplayArgs memory args = ReplayArgs({
                rootHashBefore: rows[i].rootHashBefore,
                rootHashAfter: rows[i].rootHashAfter,
                revertRootHash: rows[i].revertRootHash,
                reason: rows[i].reason
            });
            this.replayCmio(log, args, rows[i].data);
        }
    }

    /// The no-op fixture (an advance-state response to a machine that rejected its previous input)
    /// leaves the state unchanged, so its log verifies with equal root hashes before and after.
    function testNoopIsIdentity() public {
        Row[] memory rows = readManifestRows(MANIFEST_CSV, Kind.SendCmioResponse);
        bool found;
        for (uint256 i = 0; i < rows.length; i++) {
            if (keccak256(bytes(rows[i].name)) == keccak256("send-cmio-response-noop.log")) {
                assertEq(
                    rows[i].rootHashBefore, rows[i].rootHashAfter, "no-op must not change root hash"
                );
                found = true;
            }
        }
        assertTrue(found, "manifest has no send-cmio-response-noop.log row");
    }

    /// External self-call so `log` and `data` arrive as `bytes calldata`
    /// (Verify.verifySendCmioResponse requires calldata for on-chain hashing).
    /// Args bundled into a struct to stay under via-ir's stack budget.
    function replayCmio(bytes calldata log, ReplayArgs calldata args, bytes calldata data)
        external
        pure
    {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifySendCmioResponse(
            ctx, args.rootHashBefore, args.reason, data, args.revertRootHash, args.rootHashAfter
        );
    }
}
