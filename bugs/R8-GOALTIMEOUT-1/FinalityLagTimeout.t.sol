// R8-GOALTIMEOUT-1: with the released Dave v3.0.0-alpha.7 clock constants, an
// honest root claim that acts only on finalized chain history loses by timeout
// after three forced matches against Sybil claims that answer instantly.
//
// Requirement (THREAT_MODEL.md):
//   A7  "The dispute constants and clocks leave room for the honest claim to
//        play the logarithmic number of matches that a tournament forces on
//        it ... No rule of the referee may make the honest claim lose by
//        timeout while it acts within its own clock."
//   R4  "The honest operator observes the chain and submits its transactions
//        within the dispute clocks."
//   s.4 "The honest operator acts only on history that its policy treats as
//        final, such as finalized blocks."
//
// Everything deployed here is the released build's own bytecode, taken from
// the harness's compiled artifacts (vm.deployCode): Tournament,
// MultiLevelTournamentFactory, CanonicalTournamentParametersProvider with the
// constructor arguments that script/Deployment.s.sol computes for Sepolia
// (chain id 11155111: 12 s blocks, 8 h censorship budget, 5 min inclusion
// budget), and a stub state transition (no leaf match is ever reached).
//
// The honest operator answers each bisection turn LAG blocks after the block
// that opened the turn (the turn becomes final), its transaction landing one
// block later, and claims each timeout as soon as the expiry is final. Sybils
// answer in the next block and abandon on their last turn. Six Sybil claims
// (seven claims in all: ceil(log2 7) = 3 rounds) force three matches on the
// honest claim using only joins before closure and timeout re-pairing.
//
// LAG = 64 blocks is the shortest time after which an Ethereum block can be
// finalized (two 32-slot epochs, every slot filled). The control uses LAG = 4
// (a 4-block confirmation depth, under the 25-block response budget).
// Copied into a throw-away copy of the released build by dave.sh.
pragma solidity ^0.8.17;

import {Test, console} from "forge-std-1.9.6/src/Test.sol";

import {IDataProvider} from "src/IDataProvider.sol";
import {ITournament} from "src/ITournament.sol";
import {IMultiLevelTournamentFactory} from "src/tournament/factories/IMultiLevelTournamentFactory.sol";
import {Match} from "src/tournament/libs/Match.sol";
import {Time} from "src/tournament/libs/Time.sol";
import {Machine} from "src/types/Machine.sol";
import {TournamentParameters} from "src/types/TournamentParameters.sol";
import {Tree} from "src/types/Tree.sol";

interface IScriptProviderArguments {
    function providerArguments() external returns (bytes memory);
}

contract FinalityLagTimeoutAuditTest is Test {
    using Match for Match.Id;

    uint256 internal constant SEPOLIA = 11155111;
    uint256 internal constant LAG_FINALIZED = 64;
    uint256 internal constant LAG_CONTROL = 4;

    struct Claim {
        string name;
        address who;
        bytes32 fin;
        bytes32[] e; // e[h]: the node of height h on the path to the last leaf
    }

    struct Result {
        uint256 matchesWon;
        uint256 honestResponses;
        bool honestLost;
        string lostHow;
        uint64 allowanceAtJoin;
        uint64 allowanceNow;
        ITournament.TournamentStanding standing;
        bytes32 rootWinnerFinal;
    }

    ITournament internal t;
    uint64 internal H;
    uint64 internal G;
    uint64 internal A;
    uint256 internal bond;
    bytes32[] internal z; // z[h]: a subtree of height h whose leaves all agree
    uint256 internal lag;

    //
    // Released deployment
    //

    function _deploy() internal {
        vm.chainId(SEPOLIA);
        vm.roll(1_000);
        IScriptProviderArguments script = IScriptProviderArguments(
            deployCode("out/ScriptProviderArguments.sol/ScriptProviderArguments.json")
        );
        bytes memory providerArgs = script.providerArguments();
        address provider = deployCode(
            "out/CanonicalTournamentParametersProvider.sol/CanonicalTournamentParametersProvider.json",
            providerArgs
        );
        address impl = deployCode("out/Tournament.sol/Tournament.json");
        address stf = deployCode(
            "out/ProofSelectedStateTransition.sol/ProofSelectedStateTransition.json"
        );
        IMultiLevelTournamentFactory factory = IMultiLevelTournamentFactory(
            deployCode(
                "out/MultiLevelTournamentFactory.sol/MultiLevelTournamentFactory.json",
                abi.encode(impl, provider, stf)
            )
        );
        TournamentParameters memory p = factory.tournamentParameters(0);
        H = p.height;
        G = Time.Duration.unwrap(p.responseBudget);
        A = Time.Duration.unwrap(p.maxAllowance);
        (uint64 blockMs, uint64 censorS, uint64 inclS) =
            abi.decode(providerArgs, (uint64, uint64, uint64));
        console.log(
            string.concat(
                "released provider (Sepolia): block ", vm.toString(uint256(blockMs)),
                " ms, censorship ", vm.toString(uint256(censorS)),
                " s, inclusion ", vm.toString(uint256(inclS)),
                " s -> root height ", vm.toString(uint256(H)),
                ", response budget G ", vm.toString(uint256(G)),
                " blocks, root allowance ", vm.toString(uint256(A)), " blocks"
            )
        );

        z = new bytes32[](H + 1);
        z[0] = keccak256("agreed leaf");
        for (uint64 h = 1; h <= H; ++h) {
            z[h] = keccak256(abi.encodePacked(z[h - 1], z[h - 1]));
        }

        t = ITournament(
            address(
                factory.instantiate(
                    Machine.Hash.wrap(keccak256("initial state")),
                    IDataProvider(address(0))
                )
            )
        );
        bond = t.bondValue();
    }

    //
    // Claims: every leaf agrees except the last one (the final state)
    //

    function _claim(string memory name, address who, bytes32 fin)
        internal
        returns (Claim memory c)
    {
        c.name = name;
        c.who = who;
        c.fin = fin;
        c.e = new bytes32[](H + 1);
        c.e[0] = fin;
        for (uint64 h = 1; h <= H; ++h) {
            c.e[h] = keccak256(abi.encodePacked(z[h - 1], c.e[h - 1]));
        }
        vm.deal(who, 100 * bond + 1 ether);
    }

    function _root(Claim memory c) internal pure returns (Tree.Node) {
        return Tree.Node.wrap(c.e[c.e.length - 1]);
    }

    function _n(bytes32 x) internal pure returns (Tree.Node) {
        return Tree.Node.wrap(x);
    }

    function _now() internal view returns (uint256) {
        return vm.getBlockNumber();
    }

    function _rollTo(uint256 b) internal {
        if (b <= _now()) b = _now() + 1;
        vm.roll(b);
    }

    function _join(Claim memory c) internal {
        bytes32[] memory proof = new bytes32[](H);
        for (uint64 i; i < H; ++i) proof[i] = z[i];
        vm.prank(c.who);
        t.joinTournament{value: bond}(
            Machine.Hash.wrap(c.fin), proof, _n(z[H - 1]), _n(c.e[H - 1])
        );
    }

    function _tryAdvance(Match.Id memory id, Claim memory c, uint64 h)
        internal
        returns (bool ok, bytes memory err)
    {
        vm.prank(c.who);
        (ok, err) = address(t).call(
            abi.encodeCall(
                ITournament.advanceMatch,
                (id, _n(z[h - 1]), _n(c.e[h - 1]), _n(z[h - 2]), _n(c.e[h - 2]))
            )
        );
    }

    function _tryWinByTimeout(Match.Id memory id, Claim memory c)
        internal
        returns (bool ok, bytes memory err)
    {
        vm.prank(c.who);
        (ok, err) = address(t).call(
            abi.encodeCall(
                ITournament.winMatchByTimeout,
                (id, _n(z[H - 1]), _n(c.e[H - 1]))
            )
        );
    }

    function _standing(Claim memory c)
        internal
        view
        returns (ITournament.CommitmentStandingView memory)
    {
        return t.commitmentStanding(_root(c));
    }

    function _deadline(Claim memory c) internal view returns (uint256) {
        ITournament.CommitmentStandingView memory s = _standing(c);
        require(s.clockRunning, "setup: expected a running clock");
        return Time.Instant.unwrap(s.clockDeadline);
    }

    function _allowance(Claim memory c) internal view returns (uint64) {
        return Time.Duration.unwrap(_standing(c).clockAllowance);
    }

    function _isDangling(Claim memory c) internal view returns (bool) {
        ITournament.TournamentStandingView memory s = t.tournamentStanding();
        return s.hasCandidate && Tree.Node.unwrap(s.candidate)
            == Tree.Node.unwrap(_root(c));
    }

    function _bisecting(Match.Id memory id) internal view returns (bool) {
        (Match.Phase ph,) = t.bisectingMatch(id.hashFromId());
        return ph == Match.Phase.BISECTING;
    }

    function _reason(bytes memory err) internal pure returns (string memory) {
        if (err.length >= 4) {
            bytes4 sel;
            assembly ("memory-safe") {
                sel := mload(add(err, 32))
            }
            if (sel == ITournament.CannotAdvanceTimedOutClock.selector) {
                return "CannotAdvanceTimedOutClock";
            }
            if (sel == ITournament.MatchCannotBeWonByTimeout.selector) {
                return "MatchCannotBeWonByTimeout";
            }
        }
        return "other revert";
    }

    //
    // One forced match: the Sybil answers in the next block, the honest
    // operator LAG + 1 blocks after the turn opened. The Sybil abandons on its
    // last turn (its last bisection or its seal), so the honest claim never
    // has to seal. Returns false if an honest response is refused.
    //

    function _bisect(
        Match.Id memory id,
        Claim memory one,
        Claim memory two,
        bool honestIsOne,
        Result memory r,
        uint256 matchNo
    ) internal returns (bool) {
        uint256 turnStart = _now();
        uint256 responsesHere;
        for (uint64 h = H; h >= 2; --h) {
            bool oneResponds = (H - h) % 2 == 0;
            Claim memory c = oneResponds ? one : two;
            if (oneResponds != honestIsOne) {
                if (h == 2) break; // Sybil's last bisection turn: abandon
                _rollTo(turnStart + 1);
                (bool ok,) = _tryAdvance(id, c, h);
                require(ok, "setup: Sybil advance refused");
            } else {
                _rollTo(turnStart + lag + 1);
                (bool ok, bytes memory err) = _tryAdvance(id, c, h);
                if (!ok) {
                    r.honestLost = true;
                    r.lostHow = string.concat(
                        "honest advanceMatch refused (",
                        _reason(err),
                        ") in forced match ",
                        vm.toString(matchNo),
                        " at honest response ",
                        vm.toString(responsesHere + 1)
                    );
                    return false;
                }
                ++responsesHere;
                ++r.honestResponses;
                console.log(
                    string.concat(
                        "  match ", vm.toString(matchNo),
                        ", honest response ", vm.toString(responsesHere),
                        " at +", vm.toString(_now() - turnStart),
                        " blocks: allowance ", vm.toString(uint256(_allowance(c)))
                    )
                );
            }
            turnStart = _now();
        }
        return true;
    }

    /// The honest claim takes the abandoned match once the expiry is final.
    function _honestClaims(
        Match.Id memory id,
        Claim memory honest,
        Claim memory sybil,
        Result memory r,
        uint256 matchNo
    ) internal returns (bool) {
        _rollTo(_deadline(sybil) + lag);
        (bool ok, bytes memory err) = _tryWinByTimeout(id, honest);
        if (!ok) {
            r.honestLost = true;
            r.lostHow = string.concat(
                "honest winMatchByTimeout refused (",
                _reason(err),
                ") in forced match ",
                vm.toString(matchNo)
            );
            return false;
        }
        ++r.matchesWon;
        console.log(
            string.concat(
                "honest won forced match ", vm.toString(matchNo),
                " by timeout; allowance after: ", vm.toString(uint256(_allowance(honest)))
            )
        );
        return true;
    }

    /// After an honest failure: the Sybil takes the match by timeout and,
    /// the tournament being closed with no other match, wins the root.
    function _sybilTakesOver(Match.Id memory id, Claim memory honest, Claim memory sybil)
        internal
    {
        if (_standing(honest).clockRunning) {
            _rollTo(_deadline(honest));
            (bool ok,) = _tryWinByTimeout(id, sybil);
            if (ok) console.log("Sybil won the match against the honest claim by timeout");
        }
    }

    function _play(uint256 lag_) internal returns (Result memory r) {
        lag = lag_;
        _deploy();
        uint256 S = _now();

        Claim memory honest = _claim("honest", address(0xa11ce), keccak256("honest final"));
        Claim memory s1 = _claim("S1", address(0xb001), keccak256("sybil 1 final"));
        Claim memory p1a = _claim("P1a", address(0xb002), keccak256("sybil 2 final"));
        Claim memory p1b = _claim("P1b", address(0xb003), keccak256("sybil 3 final"));
        Claim memory p2a = _claim("P2a", address(0xb004), keccak256("sybil 4 final"));
        Claim memory p2b = _claim("P2b", address(0xb005), keccak256("sybil 5 final"));

        // Before the honest operator sees the root: two Sybil pairs and one
        // dangling Sybil. In each pair the first Sybil answers once and the
        // second abandons; the survivors re-enter later by timeout.
        _rollTo(S + 1);
        _join(p1a);
        _join(p1b);
        _join(p2a);
        _join(p2b);
        _join(s1);
        Match.Id memory idP1 = Match.Id(_root(p1a), _root(p1b));
        Match.Id memory idP2 = Match.Id(_root(p2a), _root(p2b));
        _rollTo(S + 2);
        {
            (bool ok1,) = _tryAdvance(idP1, p1a, H);
            (bool ok2,) = _tryAdvance(idP2, p2a, H);
            require(ok1 && ok2, "setup: Sybil pair advances refused");
        }
        require(_isDangling(s1), "setup: S1 should be dangling");

        // The honest operator joins once the root's creation is final.
        _rollTo(S + lag + 1);
        _join(honest);
        r.allowanceAtJoin = _allowance(honest);
        console.log(
            string.concat(
                "honest acts LAG = ", vm.toString(lag),
                " blocks after each enabling block; joined with allowance ",
                vm.toString(uint256(r.allowanceAtJoin))
            )
        );

        // Forced match 1: S1 (one) vs honest (two).
        Match.Id memory idA = Match.Id(_root(s1), _root(honest));
        require(_bisecting(idA), "setup: match 1 not created");
        if (!_bisect(idA, s1, honest, false, r, 1)) {
            _sybilTakesOver(idA, honest, s1);
            return _finish(r, honest);
        }
        // P1 resolves while match 1 waits for S1's expiry: P1a dangles.
        _rollTo(_deadline(p1b));
        require(_deadline(s1) > _now() + 1, "setup: match 1 ended before P1");
        {
            (bool ok,) = _tryWinByTimeout(idP1, p1a);
            require(ok && _isDangling(p1a), "setup: P1a should re-enter dangling");
        }
        if (!_honestClaims(idA, honest, s1, r, 1)) return _finish(r, honest);

        // Forced match 2: P1a (one) vs honest (two).
        Match.Id memory idB = Match.Id(_root(p1a), _root(honest));
        require(_bisecting(idB), "setup: match 2 not created");
        _rollTo(_now() + 1);
        require(_deadline(p2b) <= _now(), "setup: P2b not expired yet");
        {
            (bool ok,) = _tryWinByTimeout(idP2, p2a);
            require(ok && _isDangling(p2a), "setup: P2a should re-enter dangling");
        }
        if (!_bisect(idB, p1a, honest, false, r, 2)) {
            _sybilTakesOver(idB, honest, p1a);
            return _finish(r, honest);
        }
        if (!_honestClaims(idB, honest, p1a, r, 2)) return _finish(r, honest);

        // Forced match 3: P2a (one) vs honest (two).
        Match.Id memory idC = Match.Id(_root(p2a), _root(honest));
        require(_bisecting(idC), "setup: match 3 not created");
        if (!_bisect(idC, p2a, honest, false, r, 3)) {
            _sybilTakesOver(idC, honest, p2a);
            return _finish(r, honest);
        }
        _honestClaims(idC, honest, p2a, r, 3);
        return _finish(r, honest);
    }

    function _finish(Result memory r, Claim memory honest)
        internal
        view
        returns (Result memory)
    {
        r.allowanceNow = _allowance(honest);
        ITournament.TournamentStandingView memory s = t.tournamentStanding();
        r.standing = s.standing;
        r.rootWinnerFinal = Machine.Hash.unwrap(s.finalState);
        console.log(
            string.concat(
                "end: honest responses ", vm.toString(r.honestResponses),
                ", forced matches won ", vm.toString(r.matchesWon),
                ", honest allowance ", vm.toString(uint256(r.allowanceNow))
            )
        );
        if (r.honestLost) console.log(r.lostHow);
        if (s.standing == ITournament.TournamentStanding.ROOT_WINNER) {
            console.log(
                string.concat(
                    "root tournament finished, winner final state ",
                    vm.toString(r.rootWinnerFinal),
                    r.rootWinnerFinal == honest.fin
                        ? " = the honest final state"
                        : " = a FABRICATED (Sybil) final state"
                )
            );
        }
        return r;
    }

    // Control: with a confirmation depth under the response budget the same
    // choreography is played to the end and the honest claim wins the root,
    // never charged for a response.
    function testControlShallowDepthHonestWins() public {
        Result memory r = _play(LAG_CONTROL);
        assertFalse(r.honestLost, r.lostHow);
        assertEq(r.matchesWon, 3, "control: honest should win 3 forced matches");
        assertEq(r.allowanceNow, r.allowanceAtJoin, "control: honest charged");
        assertTrue(
            r.standing == ITournament.TournamentStanding.ROOT_WINNER,
            "control: root not decided"
        );
        assertEq(r.rootWinnerFinal, keccak256("honest final"), "control: wrong winner");
    }

    // Requirement (A7, R4): an honest claim that acts on finalized history
    // only, at the earliest moment that history allows, wins every forced
    // match and the root.
    function testFinalizedHonestSurvivesForcedMatches() public {
        Result memory r = _play(LAG_FINALIZED);
        assertFalse(
            r.honestLost,
            string.concat("R8-GOALTIMEOUT-1 (A7/R4): ", r.lostHow)
        );
        assertEq(r.matchesWon, 3, "R8-GOALTIMEOUT-1: honest did not win 3 forced matches");
        assertEq(
            r.rootWinnerFinal,
            keccak256("honest final"),
            "R8-GOALTIMEOUT-1: root not won by the honest claim"
        );
    }
}
