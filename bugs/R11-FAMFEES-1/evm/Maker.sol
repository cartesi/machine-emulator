// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;
import {Clones} from "@openzeppelin-contracts-5.5.0/proxy/Clones.sol";
import {Tournament} from "prt-contracts/tournament/Tournament.sol";
import {ITournament} from "prt-contracts/ITournament.sol";
import {Commitment} from "prt-contracts/tournament/libs/Commitment.sol";
import {Time} from "prt-contracts/tournament/libs/Time.sol";
import {Machine} from "prt-contracts/types/Machine.sol";
import {Tree} from "prt-contracts/types/Tree.sol";
import {IDataProvider} from "prt-contracts/IDataProvider.sol";
import {IStateTransition} from "prt-contracts/IStateTransition.sol";

contract Maker {
    using Clones for address;
    function make(address impl, uint64 level, uint8 kind, uint64 height, uint64 log2step, uint64 allowance,
        uint64 rb, bytes32 c1, bytes32 s1, bytes32 c2, bytes32 s2) external returns (address) {
        ITournament.TournamentArguments memory args = ITournament.TournamentArguments({
            commitmentArgs: Commitment.Arguments({initialHash: Machine.Hash.wrap(bytes32(uint256(1))), startCycle: 0, log2step: log2step, height: height}),
            level: level, kind: ITournament.TournamentKind(kind),
            startInstant: Time.Instant.wrap(uint64(block.number)),
            allowance: Time.Duration.wrap(allowance), responseBudget: Time.Duration.wrap(rb), commitmentBudget: Time.Duration.wrap(600),
            provider: IDataProvider(address(0)),
            nestedDispute: ITournament.NestedDispute({contestedCommitmentOne: Tree.Node.wrap(c1), contestedFinalStateOne: Machine.Hash.wrap(s1),
                contestedCommitmentTwo: Tree.Node.wrap(c2), contestedFinalStateTwo: Machine.Hash.wrap(s2)}),
            stateTransition: IStateTransition(address(0)), tournamentFactory: address(0)});
        return address(impl).cloneWithImmutableArgs(abi.encode(args));
    }
}
