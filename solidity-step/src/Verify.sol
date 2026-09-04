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
///     bytes32 rootAfter = Verify.verifyStep(ctx, rootBefore);
///
/// decode recomputes the pre-state root and checks that the log occupies the whole
/// buffer; each verifyXXX checks the caller's claimed pre-state root, runs the
/// operation, and returns the post-state root it obtained, for the caller to compare
/// against the root under dispute. MUTATES `ctx`; do not reuse a Context across calls.
/// For multi-log composition, call StepLog.decodeAt in a cursor loop instead.
///
/// Scope: verifyStep runs exactly one uarch step; the on-chain dispute granularity is a
/// single uarch step. A multi-cycle log is a valid witness for its first cycle only:
/// replaying one step of it returns that intermediate root, not the log's endpoint. It
/// must still fit the witness-size caps StepLog.decode enforces; those bound the on-chain
/// decode work and are sized for single-step logs, not for arbitrarily long recordings.
library Verify {
    error RootHashBeforeMismatch(bytes32 expected, bytes32 fromLog);
    error CmioResponseTooLong(uint256 length);

    function verifyStep(StepLog.Context memory ctx, bytes32 rootHashBefore)
        internal
        pure
        returns (bytes32)
    {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }

        UArchStep.uarchStep(ctx);

        return StepLog.computeRootHash(ctx);
    }

    function verifyReset(StepLog.Context memory ctx, bytes32 rootHashBefore)
        internal
        pure
        returns (bytes32)
    {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }

        UArchReset.uarchResetState(ctx);

        // When the reset reverted the state on a rejected input, the canonical post-state hash is the
        // recorded revert root hash (carried on the context by revertState), not the recomputed tree root.
        if (ctx.reverted) {
            return ctx.revertedRootHash;
        }
        return StepLog.computeRootHash(ctx);
    }

    function verifySendCmioResponse(
        StepLog.Context memory ctx,
        bytes32 rootHashBefore,
        uint16 reason,
        bytes calldata data,
        bytes32 revertRootHash
    ) internal pure returns (bytes32) {
        if (ctx.rootHashBefore != rootHashBefore) {
            revert RootHashBeforeMismatch(rootHashBefore, ctx.rootHashBefore);
        }

        // The shared core takes a uint32 length; refuse what would be silently narrowed, as the
        // C++ verifier does.
        if (data.length > type(uint32).max) {
            revert CmioResponseTooLong(data.length);
        }
        SendCmioResponse.sendCmioResponse(ctx, reason, data, uint32(data.length), revertRootHash);

        return StepLog.computeRootHash(ctx);
    }
}
