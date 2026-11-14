# R2-DFOUTPUT-1: the stored PRT player refuses a valid non-genesis template

## What is asserted

`test.lua` builds a valid template whose tx buffer already commits to an output, then follows the honest
operator's path with the recipe player (`doc/recipes/prt.lua`):

1. It loads the harness `baremetal-template` configuration (`emit-output.bin`, stored at its first rx-accepted
   yield with the empty outputs root). It delivers one advance-state input and runs to the next manual
   rx-accepted yield. The guest emits one output and writes the outputs Merkle root of that output to the tx
   buffer. The test recomputes that root from the emitted output (keccak leaf, height-63 frontier), checks the
   uarch is pristine, and stores the machine as the template. The machine was created from a configuration and
   changed only by running it and delivering inputs.
2. It calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(11), checkpoints/epoch-0, frontier)`.
   This is the only way the recipes create the epoch-0 checkpoint that `crisium.lua` (`open_epochs`) and
   `prt-demo.lua` require. The function currently takes three arguments, so it ignores the fourth (the
   template's outputs frontier, passed in case a fix accepts one).
3. Required: the call succeeds. Then the checkpoint must be the template, and a `prt.new_stored_player`
   started from it must seal an empty epoch 0 at the template hash and build the epoch-0 mcycle tree (the
   claim). Whether the checkpoint carries the template's output history (frontier root equal to the tx-buffer
   root, one leaf) and whether `outputs_merkle_root_mismatch` is reported are printed as `note:` lines only
   (reviewer repair: they concern output proofs and diagnostics, not R4).

On audit/prt2 step 2 raises `prt.lua:2759: template machine has an output history`. The function builds the
outputs frontier with `new_outputs_frontier()`, which always returns the empty tree, and asserts that the
template's tx-buffer word equals that root. The test then exits 1.

Requirements quoted (THREAT_MODEL.md):

- Section 2, **Valid template**: "Its tx buffer holds the outputs Merkle root of every output that the application
  accepted before it, which at genesis is the root of the empty outputs tree."
- Section 2, **Honest operator's path**: "Obtaining its valid template." and "Computing claims."
- R4: "From any reachable state, at the position where it is reached, the honest operator can always compute the
  claim".
- The manual documents non-genesis templates (doc/README.md, "Rolling Cartesi Machine templates"): "For a
  non-genesis template, use `--assert-rolling-template=outputs_merkle_root:<filename>`".

## Run

```sh
bugs/run.sh R2-DFOUTPUT-1
```

It takes about 1 s and needs only the in-tree emulator and the `baremetal-template` harness configuration. It
writes only to a `mktemp -d` directory and removes it at the end.

## Expected output on audit/prt2

```
template 2c90bc70...1307 commits to 1 earlier output, outputs root 216f25b9...921d
store_first_epoch_checkpoint raised: .../doc/recipes/prt.lua:2759: template machine has an output history
VIOLATED: valid template (tx buffer holds the outputs root of every output accepted before it): the honest operator must obtain it and compute the epoch-0 claim (R4)
run.sh: R2-DFOUTPUT-1: exit 1 (bug present)
```

Exit 1 in every run (3 of 3).

Check of the fixed path: a scratch copy of `prt.lua` was changed so that `store_first_epoch_checkpoint` takes an
optional fourth argument, seeds the frontier with `new_outputs_frontier(previous_outputs_frontier)`, and writes
`output_count` from it. The scratch copy was not committed. With it, all checks pass and the test exits 0 (about
4 s).
