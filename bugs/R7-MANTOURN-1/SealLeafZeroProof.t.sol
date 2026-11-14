// R7-MANTOURN-1: a leaf-level seal at divergence position 0 must not accept an
// agreed-state proof that carries data (THREAT_MODEL R3: trailing data is a log
// validity condition; section 4: proofs are adversarial). Built on Dave's own
// SmallSingleLevelTournament fixture (released v3.0.0-alpha.7 contracts), whose
// testLeafSealEmitsScheduleAndIncrementsCounter seals at leaf 0 with an empty
// proof. Copied next to that fixture by test.sh; not part of Dave.
pragma solidity ^0.8.17;

import {Test} from "forge-std-1.9.6/src/Test.sol";

import {IDataProvider} from "src/IDataProvider.sol";
import {Match} from "src/tournament/libs/Match.sol";
import {Time} from "src/tournament/libs/Time.sol";
import {Machine} from "src/types/Machine.sol";
import {Tree} from "src/types/Tree.sol";

import {InspectableTournament} from "./InspectableTournament.sol";
import {SmallFullTree} from "./SmallFullTree.sol";
import {SmallSingleLevelTournamentFactory} from "./SmallSingleLevelTournament.sol";
import {TournamentInspector} from "test/fixtures/TournamentInspector.sol";

using TournamentInspector for InspectableTournament;

contract SealLeafZeroProofAuditTest is Test {
    using SmallFullTree for SmallFullTree.Data;
    using Tree for Tree.Node;

    uint64 internal constant HEIGHT = 3;
    uint64 internal constant RESPONSE_BUDGET = 5;
    uint64 internal constant MAX_ALLOWANCE = 1_000;
    address internal constant CLAIMER_ONE = address(0xa11ce);
    address internal constant CLAIMER_TWO = address(0xb0b);
    Machine.Hash internal constant INITIAL_STATE =
        Machine.Hash.wrap(bytes32(uint256(0x1234)));

    SmallSingleLevelTournamentFactory internal immutable FACTORY;

    constructor() {
        FACTORY = new SmallSingleLevelTournamentFactory(
            Time.Duration.wrap(RESPONSE_BUDGET),
            Time.Duration.wrap(MAX_ALLOWANCE)
        );
    }

    function setUp() public {
        vm.roll(100);
        vm.deal(CLAIMER_ONE, 100 ether);
        vm.deal(CLAIMER_TWO, 100 ether);
    }

    // Two claims that differ only at leaf `div` (0 or 1); bisect down to height 1
    // at position 0. Commitment one reveals the leaves (HEIGHT is odd).
    function _readyToSeal(uint256 div)
        internal
        returns (InspectableTournament t, Match.Id memory id,
                 Tree.Node leftLeaf, Tree.Node rightLeaf, bytes32[] memory agreeProof)
    {
        t = InspectableTournament(
            address(FACTORY.instantiate(INITIAL_STATE, IDataProvider(address(0))))
        );
        uint256 n = uint256(1) << HEIGHT;
        Tree.Node[] memory a = new Tree.Node[](n);
        Tree.Node[] memory b = new Tree.Node[](n);
        for (uint256 i; i < n; ++i) {
            a[i] = Tree.Node.wrap(keccak256(abi.encode(uint256(0x1111), i)));
            b[i] = a[i];
        }
        b[div] = Tree.Node.wrap(keccak256(abi.encode(uint256(0x2222), div)));
        SmallFullTree.Data memory one = SmallFullTree.buildFromLeaves(a);
        SmallFullTree.Data memory two = SmallFullTree.buildFromLeaves(b);
        uint256 bond = t.bondValue();
        _join(t, one, CLAIMER_ONE, bond);
        _join(t, two, CLAIMER_TWO, bond);
        vm.roll(vm.getBlockNumber() + RESPONSE_BUDGET + 2);
        id = Match.Id(one.root(), two.root());
        (Tree.Node l1, Tree.Node r1) = one.children(HEIGHT, 0);
        (Tree.Node nl1, Tree.Node nr1) = one.children(HEIGHT - 1, 0);
        t.advanceMatch(id, l1, r1, nl1, nr1);
        (Tree.Node l2, Tree.Node r2) = two.children(HEIGHT - 1, 0);
        (Tree.Node nl2, Tree.Node nr2) = two.children(HEIGHT - 2, 0);
        t.advanceMatch(id, l2, r2, nl2, nr2);
        (leftLeaf, rightLeaf) = one.children(HEIGHT - 2, 0);
        if (div > 0) agreeProof = one.proof(div - 1);
        else agreeProof = new bytes32[](0);
    }

    function _junk(uint256 n) internal pure returns (bytes32[] memory junk) {
        junk = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            junk[i] = keccak256(abi.encode("junk", i));
        }
    }

    function _trySeal(InspectableTournament t, Match.Id memory id, Tree.Node l,
                      Tree.Node r, Machine.Hash agree, bytes32[] memory proof)
        internal returns (bool ok)
    {
        (ok,) = address(t).call(
            abi.encodeCall(t.sealLeafMatch, (id, l, r, agree, proof))
        );
    }

    function _join(InspectableTournament t, SmallFullTree.Data memory tree,
                   address claimer, uint256 bond) internal {
        (Tree.Node left, Tree.Node right) = tree.children(HEIGHT, 0);
        vm.prank(claimer);
        t.joinTournament{value: bond}(tree.finalState(), tree.finalProof(), left, right);
    }

    // Control: the honest seal at leaf 0 (empty proof) is accepted.
    function testControlLeafZeroEmptyProofAccepted() public {
        (InspectableTournament t, Match.Id memory id, Tree.Node l, Tree.Node r,
         bytes32[] memory p) = _readyToSeal(0);
        assertTrue(_trySeal(t, id, l, r, INITIAL_STATE, p), "honest leaf-0 seal refused");
        assertEq(t.getLeafMatchSealedCount(), 1);
    }

    // Control: past leaf 0, the honest proof is accepted ...
    function testControlLeafOneHonestProofAccepted() public {
        (InspectableTournament t, Match.Id memory id, Tree.Node l, Tree.Node r,
         bytes32[] memory p) = _readyToSeal(1);
        assertTrue(_trySeal(t, id, l, r, l.toMachineHash(), p), "honest leaf-1 seal refused");
    }

    // ... and the same proof with one trailing word is refused (CommitmentProofWrongSize).
    function testControlLeafOneTrailingWordRejected() public {
        (InspectableTournament t, Match.Id memory id, Tree.Node l, Tree.Node r,
         bytes32[] memory p) = _readyToSeal(1);
        bytes32[] memory q = new bytes32[](p.length + 1);
        for (uint256 i; i < p.length; ++i) q[i] = p[i];
        q[p.length] = keccak256("trailing");
        assertFalse(_trySeal(t, id, l, r, l.toMachineHash(), q), "leaf-1 seal with trailing word accepted");
    }

    // Requirement: at leaf 0 the agreed-state proof has no sibling to hold, so a seal
    // whose proof carries data is a log with trailing data and must be refused.
    function testLeafZeroOneTrailingWordRejected() public {
        (InspectableTournament t, Match.Id memory id, Tree.Node l, Tree.Node r,) =
            _readyToSeal(0);
        assertFalse(_trySeal(t, id, l, r, INITIAL_STATE, _junk(1)),
            "R7-MANTOURN-1: sealLeafMatch at leaf 0 accepted a 1-word junk agreed-state proof");
    }

    function testLeafZeroJunkProofRejected() public {
        (InspectableTournament t, Match.Id memory id, Tree.Node l, Tree.Node r,) =
            _readyToSeal(0);
        assertFalse(_trySeal(t, id, l, r, INITIAL_STATE, _junk(64)),
            "R7-MANTOURN-1: sealLeafMatch at leaf 0 accepted a 64-word junk agreed-state proof");
    }
}
