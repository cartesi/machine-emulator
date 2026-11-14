# R1-A7-2: the root allowance has no term for executing the sealed epoch

Component: Dave v3.0.0-alpha.7 released contracts (`DaveConsensus.acceptStagedTournamentResult` seals every
pending input up to 2^24 and starts the root tournament at that block; `Tournament.joinTournament` charges the
whole lateness to the joining clock and refuses joins from `startInstant + maxAllowance`;
`ClockBudgets.maxAllowance = C + 2G + (L-1)(T+2G)`). Role: referee model (the deployed referee).

## What the test asserts

`test.lua` runs the released Dave build (`bugs/harness/work/dave/released`) on a private anvil (free port,
chain id 11155111 = the Sepolia registration of the released `Deployment.s.sol`: 12 s blocks, TESTNET C = 8 h,
G = 5 min, T = 120 min, so the root allowance is 3100 blocks; block gas limit 30M):

1. A Dave application is deployed for a bare-metal guest (`spin-accept.c`) that spends 2^30 mcycles on each
   input and then accepts it with the empty outputs root. 2^30 is within imcyclemax (2^48) and within Dave's own
   documented per-input compute contract at the default snapshot gap (2^30.9, `docs/dimensioning.md`).
2. Epoch 0 (no inputs) is joined, closes, and is staged by the honest side as early as possible.
3. An input sender fills the blocks before the earliest possible `acceptStagedTournamentResult` with
   `addInput` calls, batched through `Flood.sol` (one block-filling transaction per block, about 30.6k gas per
   input, so 976 inputs per 30M-gas block): 50,000 inputs over 52 blocks (`FLOOD_INPUTS` overrides). The honest side then calls
   `acceptStagedTournamentResult` itself in the first block the contract allows (the most favourable choice for
   the honest operator). All 50,000 inputs are sealed into epoch 1, whose root tournament starts at that block.
4. The honest operator is modelled with generous assumptions: it runs each sealed input as soon as the
   input's block starts (it reads the mempool), sequentially, at Dave's own reference emulator speed of 1.1 ns
   per mcycle (`docs/dimensioning.md`, "about 1.1 ns per big cycle"; about 2.3 times faster than this host),
   with no per-input overhead, no hashing, no snapshot and zero inclusion latency. The mcycle count per input
   is measured in the test by running one input on the emulator (deterministic: 1,073,741,999).
5. The test mines to the first block at which that operator can have its root commitment (whose last leaf
   is the state after the last sealed input) and sends the honest `joinTournament`.

Required: THREAT_MODEL A7, "The dispute constants and clocks leave room for the honest claim to play the
logarithmic number of matches that a tournament forces on it, at the worst-case costs of R12, while the honest
operator also processes the inputs of later epochs. No rule of the referee may make the honest claim lose by
timeout while it acts within its own clock", and R4, "The honest operator defends every epoch whose dispute is
open, including while it processes the inputs of later epochs." The test exits 1 if the referee refuses the
honest join, 0 if it accepts it.

On audit/prt2 the join lands 4,867 blocks (16.2 h) after the seal, the root closed after 3,100 blocks,
and `joinTournament` reverts with `TournamentIsClosed()` (0xac57beef): no honest claim can enter epoch 1, so
any claim that joined within the window wins the root. The result does not depend on wall-clock time: the
printed threshold says the root closes first for any emulator slower than about 2.25e9 mcycles/s on this
guest (Dave's reference: 9.1e8; this host: about 3.8e8, printed as information only). More inputs widen
the margin (80,000 inputs: 2.25e9, also exit 1, but about 12 minutes because anvil slows down as its state grows).

Control: `FLOOD_INPUTS=3000 bugs/run.sh R1-A7-2` exits 0 (the join is accepted, its clock reduced by the full
lateness, with no credit for the sealed inputs).

## Notes for the reviewer

- The honest operator's commitment content is not computed (it would need 50,000 x 2^30 mcycles); the join uses
  a commitment whose leaves all equal one hash. The root join checks only that the final state is the last leaf
  of the commitment, and the clock and closure do not depend on the claim, so this does not change the outcome.
- Dave's `docs/dimensioning.md` ("Aggregate throughput, the second per-app contract") documents this
  behaviour and puts the burden on the application (it must price inputs so the node keeps up). Whether
  THREAT_MODEL's "correctly designed application ... the total stays within what the deployment was sized
  for" covers an input count the adversary chooses decides the rating; the test only shows the behaviour.
- The scenario uses a testnet registration (C = 8 h). With a cheaper application the needed flood grows; with
  C = 1 week (MAINNET) the same guest needs roughly 530k inputs (~1.6e10 gas), which this test does not run.

Expected output on audit/prt2 (abridged):

```
epoch 1: inputs [0, 50000) = 50000 inputs; 0x0 left pending for epoch 2
root tournament: start block 3118, allowance 3100 blocks, closes at block 6218
honest work: 1073741999 mcycles/input (guest), 1.181 s/input at 1.1 ns/mcycle (...)
honest root commitment ready at block 7985 at the earliest (4867 blocks = 16.2 h after the seal)
closure happens first while the reference speed is slower than 1.42e+09 mcycles/s (Dave reference 9.09e+08, ...)
honest joinTournament in block 7985: REVERTED "0xac57beef" = TournamentIsClosed()
VIOLATED: A7/R4: the honest claim must be able to join the root tournament ...
run.sh: R1-A7-2: exit 1 (bug present)
```

## Files and run

```sh
bugs/run.sh R1-A7-2                 # about 4.5 minutes; prints the scenario and the verdict
FLOOD_INPUTS=3000 bugs/run.sh R1-A7-2   # control, exits 0
./build-guest.sh                    # rebuild spin-accept.bin (pinned bare-metal toolchain, docker)
./build-flood.sh                    # rebuild Flood.bin (solc 0.8.30)
```

`spin-accept.c`/`spin-accept.bin` (2 KB guest), `Flood.sol`/`Flood.bin` (batching input sender), `test.lua`.
Needs the in-tree emulator, the released Dave build and foundry (`anvil`) from `bugs/harness`.
