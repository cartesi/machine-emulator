# R1-A3-1: PRT player misses the input backlog deferred past the per-epoch input limit

## What is asserted

The pinned DaveConsensus (`_nextInputIndexUpperBound`, `acceptStagedTournamentResult`) seals epoch N as
`[lo, lo + min(pending, 2^24))` and leaves the rest pending for epoch N+1. Those deferred inputs were added to
the InputBox **before** epoch N's seal block. `doc/recipes/crisium.lua` (`open_epochs`) opens epoch N+1's
listener with `first_input_block = previous_seal.log.blockNumber`, and `doc/recipes/prt-epoch.lua` fetches
InputAdded logs only from that block, so the deferred inputs are never fetched.

`test.lua` drives the real `prt-epoch.lua` listener against a fake chain (logs honour `fromBlock`), a fake ABI
and a recording player, with `first_input_block` computed by the very expression crisium.lua passes (extracted
from its source and evaluated). Epoch 0 is sealed at block 100 with `[0, 2^24)`; input `2^24` was added at
block 50. Two scenarios:

1. backlog input `2^24` (block 50) plus input `2^24+1` (block 120), epoch 1 sealed with `[2^24, 2^24+2)`;
2. backlog input only, epoch 1 sealed with `[2^24, 2^24+1)`.

It asserts that epoch 1's listener delivers offsets `0, 1, ...` for every input of `[lower, upper)`, accepts the
epoch-1 seal (`epoch_sealed(n)`) and opens the dispute. A control run of each scenario with
`first_input_block = first_block` must pass (otherwise exit 2: fake chain inconsistent). The test also checks
(setup, exit 2 otherwise) that the pinned DaveConsensus source still caps seals at `MAX_INPUTS_PER_EPOCH`.
The dispute bridge is stubbed: it is outside the defect.

Since crisium rebuilds the listener with the same `first_input_block` after a relaunch by `prt-supervise.sh`,
the same failure repeats on every restart.

## Requirement

THREAT_MODEL.md R4: "The honest operator defends every epoch whose dispute is open, including while it processes
the inputs of later epochs. It assigns inputs to epochs exactly as the referee does, including the input limit
per epoch (A3)." Trigger: input senders ("any bytes, any count", section 4; section 7 "Send any number of inputs
the deployment accepts") add more than 2^24 inputs while an epoch is open. Component: PRT player/bridge in
`doc/recipes` (support, standing in for the honest operator).

## How to run

```sh
bugs/run.sh R1-A3-1
```

Runs in well under a second; no chain, no machine.

## Expected output on audit/prt2

```
[backlog input + one input after the seal] crisium first_input_block = 100 (...)
[backlog input + one input after the seal] fetched InputAdded/EpochSealed from block(s) 100,100; poll ok=false error: .../prt-epoch.lua:73: input stream has a gap or duplicate; delivered offsets {}; epoch_sealed {}
[backlog input only] ... poll ok=false error: .../prt-epoch.lua:96: sealed input count mismatch; ...
VIOLATED: R4: ...
run.sh: R1-A3-1: exit 1 (bug present)
```

Exit 0 once epoch N+1's listener fetches from a block at or before the first input of its range (for example
the consensus deployment block, or the block of input `inputIndexLowerBound`).
