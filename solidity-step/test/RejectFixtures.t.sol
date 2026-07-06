// SPDX-License-Identifier: Apache-2.0
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
            armExpected(rows[i].expectError);
            this.verifyCmio(
                log,
                rows[i].rootHashBefore,
                rows[i].reason,
                rows[i].data,
                rows[i].revertRootHash,
                rows[i].rootHashAfter
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
        this.verifyCmio(
            log, big.rootHashBefore, big.reason, data, big.revertRootHash, big.rootHashAfter
        );
    }

    function replayUarch(Kind kind) internal {
        Row[] memory rows = readManifestRows(UARCH_MANIFEST, kind);
        require(rows.length > 0, "no uarch reject rows for kind");
        for (uint256 i = 0; i < rows.length; i++) {
            bytes memory log = vm.readFileBinary(string.concat(UARCH_DIR, "/", rows[i].name));
            armExpected(rows[i].expectError);
            if (kind == Kind.Cycle) {
                this.verifyCycle(
                    log, rows[i].rootHashBefore, rows[i].requestedCycleCount, rows[i].rootHashAfter
                );
            } else {
                this.verifyReset(log, rows[i].rootHashBefore, rows[i].rootHashAfter);
            }
        }
    }

    /// Map the reject tag to the Solidity error it must revert with. Custom errors match by
    /// selector (arguments vary); the interpreter traps share one RuntimeError selector, so
    /// they match the exact message that distinguishes them.
    function armExpected(string memory tag) internal {
        bytes32 t = keccak256(bytes(tag));
        if (t == keccak256("illegal_instruction")) {
            expectRuntime("illegal instruction");
        } else if (t == keccak256("uarch_aborted")) {
            expectRuntime("uarch aborted");
        } else if (t == keccak256("unsupported_ecall")) {
            expectRuntime("unsupported ecall function");
        } else {
            vm.expectPartialRevert(selectorFor(t));
        }
    }

    function expectRuntime(string memory message) internal {
        vm.expectRevert(abi.encodeWithSelector(StateAccess.RuntimeError.selector, message));
    }

    function selectorFor(bytes32 t) internal pure returns (bytes4) {
        if (t == keccak256("bad_signature")) return StepLog.InvalidSignature.selector;
        if (t == keccak256("unsupported_hash_function")) {
            return StepLog.UnsupportedHashFunction.selector;
        }
        if (t == keccak256("node_misaligned")) return StepLog.NodeNotAligned.selector;
        if (t == keccak256("node_log2_out_of_range")) {
            return StepLog.NodeLog2SizeOutOfRange.selector;
        }
        if (t == keccak256("nonzero_scratch_hash")) return StepLog.NonZeroScratchHash.selector;
        if (t == keccak256("page_count_zero")) return StepLog.PageCountZero.selector;
        if (t == keccak256("page_index_not_ascending")) return StepLog.PagesNotInOrder.selector;
        if (t == keccak256("entries_overlap")) return StepLog.OverlappingEntries.selector;
        if (t == keccak256("unconsumed_node")) return StepLog.UnconsumedNodes.selector;
        if (t == keccak256("initial_root_mismatch")) {
            return StepLog.InitialRootHashMismatch.selector;
        }
        if (t == keccak256("nonzero_cycle_count")) {
            return Verify.RequestedCycleCountMustBeZero.selector;
        }
        if (t == keccak256("root_before_mismatch")) return Verify.RootHashBeforeMismatch.selector;
        if (t == keccak256("root_after_mismatch")) return Verify.RootHashAfterMismatch.selector;
        if (t == keccak256("cycle_count_mismatch")) return Verify.UarchCycleCountMismatch.selector;
        if (t == keccak256("final_root_mismatch")) return Verify.FinalRootHashMismatch.selector;
        if (t == keccak256("reset_node_wrong_posthash")) {
            return StateAccess.ResetUarchWrongPostHash.selector;
        }
        if (t == keccak256("cmio_node_hash_mismatch")) {
            return StateAccess.WriteMemoryHashMismatch.selector;
        }
        revert("unmapped reject tag");
    }

    // External wrappers so `log`/`data` arrive as calldata for StepLog.decode.

    function verifyCycle(
        bytes calldata log,
        bytes32 rootBefore,
        uint64 cycleCount,
        bytes32 rootAfter
    ) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore, cycleCount, rootAfter);
    }

    function verifyReset(bytes calldata log, bytes32 rootBefore, bytes32 rootAfter) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyReset(ctx, rootBefore, rootAfter);
    }

    function verifyCmio(
        bytes calldata log,
        bytes32 rootBefore,
        uint16 reason,
        bytes calldata data,
        bytes32 revertRootHash,
        bytes32 rootAfter
    ) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifySendCmioResponse(ctx, rootBefore, reason, data, revertRootHash, rootAfter);
    }
}
