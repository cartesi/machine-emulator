# R1-R8-2: vg.lua honest player keeps every output payload and stops on an outputs-root mismatch

Component: the verification-game recipe `doc/recipes/vg.lua`, honest player (Support: an implementation of an
operator that no deployment runs).

## What is asserted

The test builds a small bare-metal guest (`guest.c`, built at test time with `bugs/harness/baremetal/build.sh` into a
temp dir) and stores its initial machine (at a manual yield with the accepted reason) under its hash, where vg.lua's
players load it. It then drives `vg.new_player` with `event_handler.input_added` / `epoch_sealed` / `commit_claim`,
as the referee's runner does.

- **Check A (root mismatch).** Input `W`: the guest emits no outputs and accepts with a tx-buffer root that is not
  the root of its outputs (an application that breaks the rollup interface, or a subverted guest). Asserted:
  `input_added` returns and the committed claim equals the root hash after that input, computed independently with
  the Lua API. Observed: `input_added` raises `vg.lua:429: outputs Merkle root mismatch`
  (`flush_pending_outputs`), so no claim is computed.
- **Check B (memory).** Input `O`+N: the guest emits N outputs of 2 MiB (the full tx buffer), then accepts with the
  correct root. With a fresh player for N = 1 and N = 16, the test measures the growth of the player's Lua heap
  (`collectgarbage("count")` after full collections) across `input_added` and asserts that the N = 16 growth exceeds
  the N = 1 growth by less than one output (2 MiB). Observed: 2.00 MiB vs 32.00 MiB (every payload is kept in
  `pending_outputs`, then `self.outputs`, for the epoch). Deterministic counts, no timing.

The test exits 1 if check A fails. Reviewer repair: check B is printed but no longer asserted, because section 8
says "Keeping outputs to prove them later is not on the honest operator's path" (the payloads are kept for
`prove_output`), so the exit status depends on check A only. A copy of vg.lua whose `flush_pending_outputs` reports (instead of asserting) a root mismatch exits
0; pushing only leaf hashes into the frontier would also make check B pass.

## Requirements quoted (THREAT_MODEL.md)

- R12: "The memory and storage the honest operator needs to defend its claims do not grow with the number of
  outputs."
- R4: "This holds for every guest, whether or not its application is correctly designed (section 8) ..."
- Section 8: "An application that breaks the rollup interface may leave its outputs unprovable, but it must never
  stop the honest operator from computing claims or producing proofs. Development tools may instead stop and report
  the violation."

Scope questions left to the reviewer: whether vg.lua's honest player is an operator implementation or a
development tool (the last sentence above), and section 8's "Keeping outputs to prove them later is not on the
honest operator's path" for check B (vg.lua keeps the payloads in the same process that computes the claim).

## Run

```sh
bugs/run.sh R1-R8-2
```

Needs docker (guest build with the pinned toolchain) and `lua-posix`. Runs in a few seconds.

## Expected output on audit/prt2

```
check A: input_added raised: .../doc/recipes/vg.lua:429: outputs Merkle root mismatch; claim none; reference 0xb40f...f78d
check B: heap growth across input_added: 1 outputs -> 2.00 MiB, 16 outputs -> 32.00 MiB (difference 30.00 MiB; one output is 2.00 MiB)
VIOLATED: R4/section 8: an accepted input whose outputs root does not match its outputs must not stop the honest player from computing its claim
note (not asserted): the honest player's Lua heap grows with the number of outputs it keeps for prove_output; section 8 puts keeping outputs to prove them later off the honest operator's path
run.sh: R1-R8-2: exit 1 (bug present)
```
