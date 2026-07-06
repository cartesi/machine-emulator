// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {StepLog} from "src/StepLog.sol";
import {Verify} from "src/Verify.sol";

import {ManifestParser} from "./ManifestParser.sol";

/// verifyStep verifies exactly one uarch step. A multi-cycle log_step_uarch log is valid for the
/// C++ replayer but out of scope on-chain. This replays a recorded, C++-verified multi-cycle log
/// and asserts verifyStep rejects it on the single-step scope rule (RequestedCycleCountMustBeOne),
/// not on any malformation -- the log is well-formed.
contract VerifyUarchScopeRejectedTest is ManifestParser {
    string constant SCOPE_DIR = "test/fixtures/uarch-solidity-scope";
    string constant SCOPE_MANIFEST = "test/fixtures/uarch-solidity-scope/_manifest.csv";

    function testRejectsMultiCycleStepLog() public {
        Row memory row = firstRow(SCOPE_MANIFEST, Kind.Program);
        // A single-cycle log would pass verifyStep and prove nothing; the fixture must be multi-cycle.
        assertGt(row.requestedCycleCount, 1, "scope fixture must be multi-cycle");
        bytes memory log = vm.readFileBinary(string.concat(SCOPE_DIR, "/", row.name));
        // cycleCount is the log's real count, so the caller belief-check passes and the only possible
        // revert is the single-step scope rule.
        vm.expectRevert(
            abi.encodeWithSelector(
                Verify.RequestedCycleCountMustBeOne.selector, row.requestedCycleCount
            )
        );
        this.verifyStep(log, row.rootHashBefore, row.requestedCycleCount, row.rootHashAfter);
    }

    /// External wrapper so `log` arrives as calldata for StepLog.decode.
    function verifyStep(
        bytes calldata log,
        bytes32 rootBefore,
        uint64 cycleCount,
        bytes32 rootAfter
    ) external pure {
        StepLog.Context memory ctx = StepLog.decode(log);
        Verify.verifyStep(ctx, rootBefore, cycleCount, rootAfter);
    }
}
