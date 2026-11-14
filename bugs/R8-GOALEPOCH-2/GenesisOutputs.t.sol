// R8-GOALEPOCH-2: the deployed referee must accept, from deployment on, an output that the valid
// template commits to, when its valid proof is presented (THREAT_MODEL A5: "A valid template is
// such a state" ... "the referee accepts every output that the settled state commits to, whenever
// its valid proof is presented").
//
// Copied by dave.sh into a throw-away copy of the released Dave v3.0.0-alpha.7
// cartesi-rollups/contracts build of the shared harness, next to the generated
// GenesisOutputsFixture.sol (written by test.lua from a real emulator machine). Not part of Dave.
pragma solidity ^0.8.30;

import {MachineValidityProof} from "cartesi-rollups-contracts-3.0.0/src/common/MachineValidityProof.sol";
import {OutputValidityProof} from "cartesi-rollups-contracts-3.0.0/src/common/OutputValidityProof.sol";
import {WithdrawalConfig} from "cartesi-rollups-contracts-3.0.0/src/common/WithdrawalConfig.sol";
import {IApplication} from "cartesi-rollups-contracts-3.0.0/src/dapp/IApplication.sol";
import {IWithdrawalOutputBuilder} from "cartesi-rollups-contracts-3.0.0/src/withdrawal/IWithdrawalOutputBuilder.sol";
import {LibKeccak256} from "cartesi-rollups-contracts-3.0.0/src/library/LibKeccak256.sol";
import {ConsensusTestUtils} from "cartesi-rollups-contracts-3.0.0/test/util/ConsensusTestUtils.sol";

import {IStateTransition} from "prt-contracts/IStateTransition.sol";
import {ITournament} from "prt-contracts/ITournament.sol";
import {ITournamentFactory} from "prt-contracts/ITournamentFactory.sol";
import {CanonicalTournamentParametersProvider} from "prt-contracts/arbitration-config/CanonicalTournamentParametersProvider.sol";
import {CartesiStateTransition} from "prt-contracts/state-transition/CartesiStateTransition.sol";
import {Tournament} from "prt-contracts/tournament/Tournament.sol";
import {MultiLevelTournamentFactory} from "prt-contracts/tournament/factories/MultiLevelTournamentFactory.sol";
import {Machine} from "prt-contracts/types/Machine.sol";
import {Tree} from "prt-contracts/types/Tree.sol";

import {DaveAppFactory} from "src/DaveAppFactory.sol";
import {IDaveAppFactory} from "src/IDaveAppFactory.sol";
import {IDaveConsensus} from "src/IDaveConsensus.sol";

import {TournamentInspector} from "prt-contracts-test/fixtures/TournamentInspector.sol";

import {GenesisOutputsFixture as F} from "./GenesisOutputsFixture.sol";

using TournamentInspector for ITournament;

contract GenesisOutputsAuditTest is ConsensusTestUtils {
    // Same tournament parameters as Dave's own DaveAppFactory.t.sol (one-minute blocks).
    uint64 constant BLOCK_MILLISECONDS = 60_000;
    uint64 constant CENSORSHIP_SECONDS = 35 minutes;
    uint64 constant INCLUSION_SECONDS = 5 minutes;
    uint256 constant CLAIM_STAGING_PERIOD = 50;

    IDaveAppFactory _daveAppFactory;

    function setUp() external {
        IStateTransition stateTransition = new CartesiStateTransition();
        ITournamentFactory tournamentFactory = new MultiLevelTournamentFactory(
            new Tournament(),
            new CanonicalTournamentParametersProvider(BLOCK_MILLISECONDS, CENSORSHIP_SECONDS, INCLUSION_SECONDS),
            stateTransition
        );
        _daveAppFactory =
            new DaveAppFactory(_contracts.core.inputBox, _contracts.core.applicationFactory, tournamentFactory);
        vm.roll(1_000);
    }

    // ------------------------------------------------------------------ helpers

    function _deploy() internal returns (IApplication app, IDaveConsensus dave) {
        WithdrawalConfig memory wc = WithdrawalConfig({
            guardian: address(0),
            log2LeavesPerAccount: 0,
            log2MaxNumOfAccounts: 0,
            accountsDriveStartIndex: 0,
            withdrawalOutputBuilder: IWithdrawalOutputBuilder(address(0))
        });
        (app, dave) = _daveAppFactory.newDaveApp(
            F.TEMPLATE_HASH, CLAIM_STAGING_PERIOD, address(0), new address[](0), wc, bytes32(0)
        );
        assertEq(app.getTemplateHash(), F.TEMPLATE_HASH);
    }

    function _outputProof() internal pure returns (OutputValidityProof memory p) {
        p.outputIndex = 0;
        p.outputHashesSiblings = F.outputSiblings();
    }

    function _machineValidityProof() internal pure returns (MachineValidityProof memory p) {
        p.iflagsYProof.dataBlock = F.IFLAGS_Y_BLOCK;
        p.iflagsYProof.siblings = F.iflagsYSiblings();
        p.htifTohostProof.dataBlock = F.HTIF_TOHOST_BLOCK;
        p.htifTohostProof.siblings = F.htifTohostSiblings();
        p.txBufferProof.dataBlock = F.TX_BUFFER_BLOCK;
        p.txBufferProof.siblings = F.txBufferSiblings();
    }

    /// @return accepted whether Application.validateOutput accepts the template's output 0
    function _accepts(IApplication app, bytes memory output) internal view returns (bool accepted) {
        try app.validateOutput(output, _outputProof()) {
            return true;
        } catch (bytes memory err) {
            assertEq(
                err,
                abi.encodeWithSelector(IApplication.InvalidOutputsMerkleRoot.selector, F.OUTPUTS_MERKLE_ROOT),
                "unexpected revert reason"
            );
            return false;
        }
    }

    function _joinWithTemplate(ITournament tournament) internal {
        // Epoch 0 has no inputs, so its honest final state is the template itself.
        uint256 h = tournament.tournamentArguments().commitmentArgs.height;
        bytes32[] memory proof = new bytes32[](h);
        for (uint256 i; i < h; ++i) {
            proof[i] = keccak256(abi.encode("sibling", i));
        }
        bytes32 left = proof[h - 1];
        bytes32 right = F.TEMPLATE_HASH;
        for (uint256 i; i + 1 < h; ++i) {
            right = LibKeccak256.hashPair(proof[i], right);
        }
        address submitter = address(0xC1A1);
        uint256 bond = tournament.bondValue();
        vm.deal(submitter, bond);
        vm.prank(submitter);
        tournament.joinTournament{value: bond}(
            Machine.Hash.wrap(F.TEMPLATE_HASH), proof, Tree.Node.wrap(left), Tree.Node.wrap(right)
        );
    }

    function _rollUntilFinished(ITournament tournament) internal returns (uint256 blocks) {
        for (uint256 i; i < 10_000 && !tournament.isFinished(); ++i) {
            vm.roll(vm.getBlockNumber() + 1);
            ++blocks;
        }
        assertTrue(tournament.isFinished(), "tournament did not finish");
    }

    // ------------------------------------------------------------------ controls

    /// The fixture is right: the output proof folds to the template's tx-buffer word, and the
    /// referee's own machine validity proof check derives that root from the template hash.
    function testControlFixtureConsistent() external pure {
        bytes32[] memory sibs = F.outputSiblings();
        bytes32 node = keccak256(F.output());
        for (uint256 i; i < sibs.length; ++i) {
            node = LibKeccak256.hashPair(node, sibs[i]);
        }
        assert(node == F.OUTPUTS_MERKLE_ROOT);
        assert(F.TX_BUFFER_BLOCK == F.OUTPUTS_MERKLE_ROOT);
    }

    /// Once epoch 0 (no inputs) settles on the template, the same proof is accepted, the real machine
    /// validity proof of the template is accepted by stageTournamentResult with the same outputs root,
    /// and a tampered output is refused.
    function testControlAcceptedOnceEpoch0Accepted() external {
        (IApplication app, IDaveConsensus dave) = _deploy();
        (,,, ITournament tournament,,,,) = dave.getCurrentSealedEpoch();
        _joinWithTemplate(tournament);
        _rollUntilFinished(tournament);
        dave.stageTournamentResult(0, _machineValidityProof());
        (,,,, Machine.Hash staged, bytes32 stagedRoot) = dave.canAcceptStagedTournamentResult();
        assertEq(Machine.Hash.unwrap(staged), F.TEMPLATE_HASH, "staged state is not the template");
        assertEq(stagedRoot, F.OUTPUTS_MERKLE_ROOT, "staged outputs root differs from the template's");
        vm.roll(vm.getBlockNumber() + CLAIM_STAGING_PERIOD);
        dave.acceptStagedTournamentResult(0);
        assertTrue(dave.isOutputsMerkleRootValid(address(app), F.OUTPUTS_MERKLE_ROOT));
        assertTrue(_accepts(app, F.output()), "valid proof refused after epoch 0 was accepted");
        bytes memory tampered = F.output();
        tampered[0] = bytes1(uint8(tampered[0]) ^ 1);
        try app.validateOutput(tampered, _outputProof()) {
            revert("tampered output accepted");
        } catch {}
    }

    // ------------------------------------------------------------------ requirement (A5)

    /// A5: the valid template is a settled state; its outputs are accepted whenever their valid proof
    /// is presented, so right after deployment as well.
    function testTemplateOutputAcceptedAtDeployment() external {
        (IApplication app, IDaveConsensus dave) = _deploy();
        bool valid = dave.isOutputsMerkleRootValid(address(app), F.OUTPUTS_MERKLE_ROOT);
        bool accepted = _accepts(app, F.output());
        emit log_named_string("isOutputsMerkleRootValid(template root) at deployment", valid ? "true" : "false");
        emit log_named_string("validateOutput(template output 0) at deployment", accepted ? "accepted" : "REFUSED");
        assertTrue(accepted, "A5: valid proof of a template output refused at deployment");
    }

    /// A5 "whenever": count the checkpoints of epoch 0 (deployment, after the honest join, tournament
    /// finished, staged, last block before the staging period ends) at which the valid proof is refused.
    function testTemplateOutputAcceptedThroughoutEpoch0() external {
        (IApplication app, IDaveConsensus dave) = _deploy();
        uint256 start = vm.getBlockNumber();
        uint256 refused;
        if (!_accepts(app, F.output())) ++refused;
        (,,, ITournament tournament,,,,) = dave.getCurrentSealedEpoch();
        _joinWithTemplate(tournament);
        if (!_accepts(app, F.output())) ++refused;
        _rollUntilFinished(tournament);
        if (!_accepts(app, F.output())) ++refused;
        dave.stageTournamentResult(0, _machineValidityProof());
        if (!_accepts(app, F.output())) ++refused;
        vm.roll(vm.getBlockNumber() + CLAIM_STAGING_PERIOD - 1);
        if (!_accepts(app, F.output())) ++refused;
        uint256 lastRefusedBlock = vm.getBlockNumber();
        vm.roll(vm.getBlockNumber() + 1);
        dave.acceptStagedTournamentResult(0);
        bool after_ = _accepts(app, F.output());
        emit log_named_uint("checkpoints (of 5) before epoch 0 is accepted at which the proof is refused", refused);
        emit log_named_uint("blocks from deployment to the last checkpoint", lastRefusedBlock - start);
        emit log_named_string("after acceptStagedTournamentResult(0)", after_ ? "accepted" : "REFUSED");
        assertTrue(after_, "control: refused even after epoch 0 was accepted");
        assertEq(refused, 0, "A5: valid proof of a template output refused while epoch 0 is pending");
    }
}
