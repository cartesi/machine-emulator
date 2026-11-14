// SPDX-License-Identifier: Apache-2.0
// R8-GOALOUTPUT-1: execute, through the released Application (cartesi-rollups-contracts 3.0.0-alpha.10 as built
// by the pinned Dave v3.0.0-alpha.7), the vouchers that a machine run of the manual's `puppet` application
// committed to, within the gas that one Ethereum transaction may carry (EIP-7825 cap, 2^24).
//
// Inputs (written by test.lua into $GOAL_DIR):
//   root.bin         outputs Merkle root the guest wrote to the tx buffer at its last rx-accepted yield (32 bytes)
//   output-<i>.bin   the exact bytes of output i, as the guest emitted them
//   siblings-<i>.bin the 63 sibling hashes of output i in the full-height outputs tree (63 * 32 bytes)
//   count.txt        number of outputs (decimal)
//   big.txt          index of the large voucher;  small.txt  index of the small control voucher
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";

/// Stands in for the settled-state validator (DaveConsensus): accepts exactly the outputs Merkle root that the
/// machine's settled state holds in its tx buffer.
contract SettledRootValidator {
    bytes32 public immutable ROOT;

    constructor(bytes32 root) {
        ROOT = root;
    }

    function isOutputsMerkleRootValid(address, bytes32 root) external view returns (bool) {
        return root == ROOT;
    }
}

/// Destination of the vouchers (the input's msg_sender, 0x...0c0ffe): accepts any call.
contract Sink {
    fallback() external payable {}
}

struct WithdrawalConfig {
    address guardian;
    uint8 log2LeavesPerAccount;
    uint8 log2MaxNumOfAccounts;
    uint64 accountsDriveStartIndex;
    address withdrawalOutputBuilder;
}

struct OutputValidityProof {
    uint64 outputIndex;
    bytes32[] outputHashesSiblings;
}

interface IApp {
    function executeOutput(bytes calldata output, OutputValidityProof calldata proof) external;
    function validateOutput(bytes calldata output, OutputValidityProof calldata proof) external view;
    function wasOutputExecuted(uint256 outputIndex) external view returns (bool);
}

contract ExecuteOutputTest is Test {
    uint256 constant TX_GAS_CAP = 1 << 24; // EIP-7825 per-transaction gas limit (Ethereum mainnet since Fusaka)
    uint256 constant TX_BASE = 21000;
    uint256 constant STANDARD_TOKEN_COST = 4; // EIP-7623: tokens = zero bytes + 4 * nonzero bytes
    uint256 constant FLOOR_TOKEN_COST = 10; // EIP-7623 calldata floor per token

    string dir;
    address app;

    function _read(string memory name) internal view returns (bytes memory) {
        return vm.readFileBinary(string.concat(dir, "/", name));
    }

    function _index(string memory name) internal view returns (uint64) {
        return uint64(vm.parseUint(vm.readFile(string.concat(dir, "/", name))));
    }

    function _proof(uint64 index) internal view returns (OutputValidityProof memory p) {
        bytes memory s = _read(string.concat("siblings-", vm.toString(index), ".bin"));
        require(s.length == 63 * 32, "setup: siblings file must hold 63 hashes");
        p.outputIndex = index;
        p.outputHashesSiblings = new bytes32[](63);
        for (uint256 i; i < 63; ++i) {
            bytes32 h;
            assembly {
                h := mload(add(add(s, 32), mul(i, 32)))
            }
            p.outputHashesSiblings[i] = h;
        }
    }

    function setUp() public {
        dir = vm.envString("GOAL_DIR");
        bytes memory r = _read("root.bin");
        require(r.length == 32, "setup: root.bin must hold 32 bytes");
        SettledRootValidator v = new SettledRootValidator(bytes32(r));
        vm.etch(address(0xc0ffe), address(new Sink()).code);
        WithdrawalConfig memory wc = WithdrawalConfig(address(0x1234), 0, 0, 0, address(0));
        app = deployCode(
            vm.envString("APPLICATION_ARTIFACT"),
            abi.encode(address(v), address(this), bytes32(0), address(0), address(0), wc)
        );
    }

    /// Gas the execution of `cd` may use inside one transaction under the per-transaction cap, or 0 when the
    /// calldata alone does not fit.
    function _executionBudget(bytes memory cd) internal pure returns (uint256 budget, uint256 tokens) {
        uint256 nz;
        for (uint256 i; i < cd.length; ++i) {
            if (cd[i] != 0) nz++;
        }
        tokens = (cd.length - nz) + 4 * nz;
        uint256 standard = TX_BASE + STANDARD_TOKEN_COST * tokens;
        uint256 floor = TX_BASE + FLOOR_TOKEN_COST * tokens;
        if (standard >= TX_GAS_CAP || floor > TX_GAS_CAP) return (0, tokens);
        budget = TX_GAS_CAP - standard;
    }

    /// Execute output `index` with at most `gasLimit` gas (0 = all gas available); state is rolled back.
    function _execute(uint64 index, uint256 gasLimit) internal returns (bool ok, uint256 used, uint256 cdLength) {
        bytes memory output = _read(string.concat("output-", vm.toString(index), ".bin"));
        OutputValidityProof memory p = _proof(index);
        bytes memory cd = abi.encodeCall(IApp.executeOutput, (output, p));
        cdLength = cd.length;
        uint256 snap = vm.snapshotState();
        uint256 g0 = gasleft();
        if (gasLimit == 0) {
            (ok,) = app.call(cd);
        } else {
            (ok,) = app.call{gas: gasLimit}(cd);
        }
        used = g0 - gasleft();
        if (ok) require(IApp(app).wasOutputExecuted(index), "setup: executed flag not set");
        vm.revertToState(snap);
    }

    /// Control (a failure here is a setup error): both committed vouchers have valid proofs against the settled
    /// root, both execute when gas is not limited, and the small one executes within one capped transaction.
    function test_control() public {
        uint64 big = _index("big.txt");
        uint64 small = _index("small.txt");
        IApp(app).validateOutput(_read(string.concat("output-", vm.toString(big), ".bin")), _proof(big));
        IApp(app).validateOutput(_read(string.concat("output-", vm.toString(small), ".bin")), _proof(small));
        (bool okBig, uint256 usedBig, uint256 cdBig) = _execute(big, 0);
        console.log("large voucher, unlimited gas: success", okBig);
        console.log("  calldata bytes", cdBig, "gas used by the call", usedBig);
        assertTrue(okBig, "setup: executeOutput of the large voucher must succeed with unlimited gas");
        bytes memory cdS = abi.encodeCall(
            IApp.executeOutput, (_read(string.concat("output-", vm.toString(small), ".bin")), _proof(small))
        );
        (uint256 budgetS,) = _executionBudget(cdS);
        (bool okSmall, uint256 usedSmall,) = _execute(small, budgetS);
        console.log("small voucher within the per-transaction cap: success", okSmall, "gas used", usedSmall);
        assertTrue(okSmall, "setup: the small control voucher must execute within one capped transaction");
    }

    /// Requirement (THREAT_MODEL A5): "the referee accepts every output that the settled state commits to,
    /// whenever its valid proof is presented"; section 8 Critical: "An honest proof or transaction that cannot
    /// fit the chain's per-transaction limits". The large voucher must execute within one transaction.
    function test_large_voucher_executes_within_one_transaction() public {
        uint64 big = _index("big.txt");
        bytes memory output = _read(string.concat("output-", vm.toString(big), ".bin"));
        bytes memory cd = abi.encodeCall(IApp.executeOutput, (output, _proof(big)));
        (uint256 budget, uint256 tokens) = _executionBudget(cd);
        console.log("large voucher: output bytes", output.length, "calldata bytes", cd.length);
        console.log("  calldata tokens", tokens, "execution budget under the 2^24 cap", budget);
        assertGt(budget, 0, "A5: the executeOutput calldata of a committed voucher must fit one transaction");
        (bool ok, uint256 used,) = _execute(big, budget);
        (, uint256 usedUnlimited,) = _execute(big, 0);
        console.log("  within the cap: success", ok, "gas used", used);
        console.log("  gas the call needs (unlimited)", usedUnlimited);
        console.log("  total transaction gas it needs", TX_BASE + STANDARD_TOKEN_COST * tokens + usedUnlimited);
        assertTrue(
            ok,
            "A5: executeOutput of a voucher the settled state commits to, with its valid proof, must succeed "
            "within the chain's per-transaction gas limit (2^24)"
        );
    }
}
