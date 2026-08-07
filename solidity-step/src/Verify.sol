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

import {SendCmioResponse} from "src/SendCmioResponse.sol";
import {StepLog} from "src/StepLog.sol";
import {UArchReset} from "src/UArchReset.sol";
import {UArchStep} from "src/UArchStep.sol";

/// Verifies binary step logs. Decode once, then verify:
///
///     StepLog.Context memory ctx = StepLog.decode(log);
///     Verify.verifyStep(ctx, rootBefore, cycleCount, rootAfter);
///
/// decode checks the pre-state root and that the log occupies the whole buffer; each
/// verifyXXX checks the caller's beliefs, runs the operation, and checks the post-state
/// root. Reverts on mismatch. MUTATES `ctx`; do not reuse a Context across calls. For
/// multi-log composition, call StepLog.decodeAt in a cursor loop instead.
///
/// Scope: verifyStep verifies exactly one uarch step. A multi-cycle log_step_uarch log, which the
/// host can record and replay, is rejected here by design; the on-chain dispute granularity is a
/// single uarch step.
library Verify {
    error RootHashBeforeMismatch(bytes32 expected, bytes32 fromLog);
    error RootHashAfterMismatch(bytes32 expected, bytes32 fromLog);
    error UarchCycleCountMismatch(uint64 expected, uint64 fromLog);
    /// Step logs must declare requested_cycle_count = 1: one verifyStep call is one uarch step.
    error RequestedCycleCountMustBeOne(uint64 fromLog);
    /// Reset/cmio logs must declare requested_cycle_count = 0.
    error RequestedCycleCountMustBeZero(uint64 fromLog);
    /// Recomputed post-state root does not match the log header (Layer 1).
    error FinalRootHashMismatch();

    function verifyStep(
        StepLog.Context memory ctx,
        bytes32 rootHashBefore,
        uint64 cycleCount,
        bytes32 rootHashAfter
    ) internal pure {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }
        if (ctx.requestedCycleCount != cycleCount) {
            revert UarchCycleCountMismatch(cycleCount, ctx.requestedCycleCount);
        }
        if (ctx.requestedCycleCount != 1) {
            revert RequestedCycleCountMustBeOne(ctx.requestedCycleCount);
        }

        UArchStep.uarchStep(ctx);

        if (StepLog.computeRootHash(ctx, true) != ctx.rootHashAfter) {
            revert FinalRootHashMismatch();
        }
        if (ctx.rootHashAfter != rootHashAfter) {
            revert RootHashAfterMismatch(rootHashAfter, ctx.rootHashAfter);
        }
    }

    function verifyReset(StepLog.Context memory ctx, bytes32 rootHashBefore, bytes32 rootHashAfter)
        internal
        pure
    {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }
        if (ctx.requestedCycleCount != 0) {
            revert RequestedCycleCountMustBeZero(ctx.requestedCycleCount);
        }

        UArchReset.uarchResetState(ctx);

        // When the reset reverted the state on a rejected input, the canonical post-state hash is the
        // recorded revert root hash (carried on the context by revertState), not the recomputed tree root.
        bytes32 finalRootHash;
        if (ctx.reverted) {
            // Revert substitutes the recorded root instead of recomputing it; still assert no node was
            // left unconsumed (computeRootHash makes this assertion on the non-reverted path).
            StepLog.checkAllNodesConsumed(ctx);
            finalRootHash = ctx.revertedRootHash;
        } else {
            finalRootHash = StepLog.computeRootHash(ctx, true);
        }
        if (finalRootHash != ctx.rootHashAfter) {
            revert FinalRootHashMismatch();
        }
        if (ctx.rootHashAfter != rootHashAfter) {
            revert RootHashAfterMismatch(rootHashAfter, ctx.rootHashAfter);
        }
    }

    function verifySendCmioResponse(
        StepLog.Context memory ctx,
        bytes32 rootHashBefore,
        uint16 reason,
        bytes calldata data,
        bytes32 revertRootHash,
        bytes32 rootHashAfter
    ) internal pure {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }
        if (ctx.requestedCycleCount != 0) {
            revert RequestedCycleCountMustBeZero(ctx.requestedCycleCount);
        }

        SendCmioResponse.sendCmioResponse(ctx, reason, data, uint32(data.length), revertRootHash);

        if (StepLog.computeRootHash(ctx, true) != ctx.rootHashAfter) {
            revert FinalRootHashMismatch();
        }
        if (ctx.rootHashAfter != rootHashAfter) {
            revert RootHashAfterMismatch(rootHashAfter, ctx.rootHashAfter);
        }
    }
}
