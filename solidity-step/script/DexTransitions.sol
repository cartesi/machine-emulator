// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;
import {StepLog} from "../src/StepLog.sol";
import {Verify} from "../src/Verify.sol";

// Measurement harness for the three dense-leaf shapes in the DEX recipe.
contract DexTransitions {
    function inputBoundary(
        bytes calldata cmioLog,
        bytes calldata stepLog,
        bytes calldata data,
        bytes32 beforeRoot,
        bytes32 afterRoot
    ) external pure returns (bytes32) {
        bytes32 mid = Verify.verifySendCmioResponse(
            StepLog.decode(cmioLog), beforeRoot, 0, data, beforeRoot
        );
        require(Verify.verifyStep(StepLog.decode(stepLog), mid) == afterRoot, "input boundary root");
        return afterRoot;
    }

    function resetBoundary(
        bytes calldata stepLog,
        bytes calldata resetLog,
        bytes32 beforeRoot,
        bytes32 afterRoot
    ) external pure returns (bytes32) {
        bytes32 mid = Verify.verifyStep(StepLog.decode(stepLog), beforeRoot);
        require(
            Verify.verifyReset(StepLog.decode(resetLog), mid) == afterRoot, "reset boundary root"
        );
        return afterRoot;
    }

    function ordinary(bytes calldata log, bytes32 beforeRoot, bytes32 afterRoot)
        external
        pure
        returns (bytes32)
    {
        require(Verify.verifyStep(StepLog.decode(log), beforeRoot) == afterRoot, "ordinary root");
        return afterRoot;
    }
}
