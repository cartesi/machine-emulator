// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {DexTransitions} from "./DexTransitions.sol";
import {McycleTransaction} from "./McycleTransaction.sol";
import {Script} from "forge-std/Script.sol";

/// Deploy the same wrappers used by receipts.py; all verifier libraries are internal.
contract DeployMeasurement is Script {
    function run() external returns (McycleTransaction mcycle, DexTransitions transitions) {
        require(block.chainid == 11155111 || block.chainid == 31337, "measurement chain");
        vm.startBroadcast(vm.envUint("SEPOLIA_PRIVATE_KEY"));
        mcycle = new McycleTransaction();
        transitions = new DexTransitions();
        vm.stopBroadcast();
    }
}
