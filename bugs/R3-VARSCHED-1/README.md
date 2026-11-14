# R3-VARSCHED-1: the bridge preflights a job at the tip's block, so a win valid from the next block is not sent

Component: PRT bridge and transaction journal in `doc/recipes` (`prt-transactions.lua` `methods:submit`,
`prt-bridge.lua` `methods:tick` / `attempt` / `jobs`). Role: Support (AUDIT.md), standing in for the honest
operator's "Submitting transactions".

## Defect

`submit` counts a job as includable when the next block can include it (`tip + 1 >= intent.first`), and `tick`
wakes at `tip = first - 1` for that reason. But the preflight runs `eth_call` at `{blockHash = latest.hash}` and
`eth_estimateGas` at `latest.number`. On anvil (and geth) those calls execute with `block.number = tip`, not
`tip + 1`. An action that becomes valid at block `first` therefore reverts in the preflight at `tip = first - 1`.
Examples are `winMatchByTimeout`, valid from the opponent's `responderDeadline` (a running clock is expired at its
deadline), and `winInnerTournament`, valid from `resultAt`. `attempt` then marks the job rejected for that tip,
and the bridge sends it at `tip = first` at the earliest, so it lands one block late. When the window is one block
long, `[D, D + 1)`, the win is never sent. That happens when the honest winner's paused clock holds one block:
Dave's `_classifySoleSurvivorAt` needs remaining > overdue. In that case the match becomes eliminable.

## What is asserted

`test.lua` has two parts, and both must hold.

1. **Real node.** A private anvil runs on port `VARSCHED_PORT` (default 28631; the test checks that the port is
   free and stops anvil at the end). On it the test deploys a 13-byte contract whose call reverts while
   `block.number < 10`, and moves the tip to block 9. It then drives the real journal (`prt-transactions.lua`),
   RPC client (`prt-rpc.lua`) and signer (`prt-signer.lua`, a cast keystore of anvil account 1). The journal
   submits a job whose window is `[10, 11)` at tip 9. **Required:** it publishes a transaction that block 10
   includes with status 1. **Control** (setup check, exit 2 if it fails): at the same tip, another account sends
   the same call as a transaction, and block 10 includes it with status 1.
2. **Bridge.** The real `bridge.tick` / `attempt` / `jobs` and the real journal run over a mock chain. The mock
   evaluates `eth_call` / `eth_estimateGas` at the requested block's number, which is the semantics part 1 shows on
   anvil (`"pending"` = tip + 1). It includes every published nonce in the next block. Only `refresh` (the
   observation) and `prepare` (calldata) are stubbed, as in `bugs/R1-A8-4`. The honest claim is commitment two of
   a match whose opponent is on turn with `responderDeadline` 20. **Required (B):** with a one-block window
   `[20, 21)`, the honest `winMatchByTimeout` lands in block 20. Scenario A, with window `[20, 26)`, is printed for
   information only: there the win lands one block late but still in time.

Requirement, THREAT_MODEL.md R4: "The honest operator observes the chain and submits its transactions within the
dispute clocks." Section 1 completeness: "The honest operator ... cannot respond in time. If the honest claim is
eliminated, a dishonest claim can win." Section 3 rates a support component: "Medium when it would rate High or
Critical in the role the component stands in for".

A candidate fix was checked in a scratch copy of `prt-transactions.lua` that preflights at `"pending"` (a block
override of `number = tip + 1` would serve as well). With it the test exits 0: part 1 publishes and block 10
includes the call, and A and B both land in block 20. With the same copy, `doc/recipes/prt-bridge-test.lua` still
passes and `bugs/R1-A8-4` still exits 1, as it does without the copy.

## Run

```sh
bugs/run.sh R3-VARSCHED-1        # about 1 s; VARSCHED_PORT=<port> if 28631 is taken
```

## Expected output on audit/prt2 (exit 1)

```
part 1 (anvil): gated call valid from block 10; journal submit at tip 9 for window [10, 11):
  journal returned rejected (preflight revert code 3: execution reverted), nothing sent
  control: the same call sent as a transaction at tip 9 is included in block 10 with status 1
part 2 (bridge over mock chain):
A (informational): next-block inclusion, window [20, 26):
  tip 19: winMatchByTimeout preflight reverted
  tip 20: published winMatchByTimeout at nonce 0
  honest winMatchByTimeout valid in blocks [20, 26): lands in block 21
B: next-block inclusion, one-block window [20, 21):
  tip 19: winMatchByTimeout preflight reverted
  tip 20: published eliminateMatchByTimeout at nonce 0
  honest winMatchByTimeout valid in blocks [20, 21): NEVER lands
VIOLATED: R4 (...): a job valid from the next block must be sent so that the next block includes it (part 1 journal on anvil: not sent; part 2 one-block window: never lands, informational window [20, 26): lands in 21)
run.sh: R3-VARSCHED-1: exit 1 (bug present)
```

In B, the bridge's own cleanup `eliminateMatchByTimeout` of the honest match is the next thing it sends, at tip
20. Block 21, which includes it, is the match's `eliminableAt`.
