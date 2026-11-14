# R3-VARSPEC-4: `--print-mcycle-root-hashes` prints the rejecting machine's content hash for the rejection boundary

Component: `cartesi-machine` CLI (`src/cartesi-machine.lua`), role Support. The `--print-mcycle-root-hashes=`
handler turns on `--initial-hash` and `--final-hash`. `print_root_hash` prints both of them in the same
`<mcycle>: <hash>` format as the series, and so does the `start:` line in `mcycle_root_hashes_runner_run`. Each of
these lines prints `machine:get_root_hash()`. When the machine stands at an rx-rejected manual yield, that value is
the content hash of the rejecting machine, not the canonical hash. The library (`collect_mcycle_root_hashes`)
returns the revert root hash for that boundary, and that line is correct. The result is that one mcycle gets two
different hashes in the printed series, and the last one is not canonical.

## Requirement (THREAT_MODEL.md)

Section 2, "Canonical hash":

> At the mcycle boundary that ends the rejecting instruction, transitions obtain it from the revert root hash.

R4: "After a rejection, every hash the honest operator commits to follows R6, however it is computed."
R6: "Every path that produces a hash for a claim, a node or a proof applies the rejection exception of the
canonical state (section 2)."

## What the test does

1. Loads `baremetal-template` (the `emit-output` guest at an accepted manual yield) and records its root hash `h0`,
   which becomes the revert root hash. It then delivers payload `R`, which the guest rejects, and runs 30 mcycles.
2. Stores the machine twice in a `mktemp -d` directory: once mid-input, and once at the rejected yield (mcycle
   `rej`).
3. Runs `cartesi-machine --load=<dir> --print-mcycle-root-hashes=...` in three ways:
   - a window from the mid-input machine (`0,start:<rej-3>`) that ends at the rejection;
   - the machine stored at the rejected yield with `0,start:<rej>`;
   - the same machine with `0` and no `start:`.
4. Collects every `<rej>: <hash>` line and asserts that each one equals `h0`, the canonical hash. The test exits 1
   while any of those lines differs from `h0`, and exits 0 when they all match. A fix that labels the
   initial/final diagnostics differently, or prints the canonical hash, makes it pass. It exits 2 on setup errors,
   including when no `<rej>:` line is printed at all.

## Run

```sh
bugs/run.sh R3-VARSPEC-4      # about 3 s
```

## Expected output on audit/prt2 (exit 1)

```
rejecting mcycle 3526406
  canonical (revert root hash) 428a6bb8...ac75
  rejecting machine content  737e2f9a...933a
[window ending at the rejection]            line 1 canonical, line 2 REJECTING MACHINE CONTENT HASH
[stored at the rejected yield, start:<rej>] lines 1, 2, 4 content hash, line 3 canonical
[stored at the rejected yield, no start]    lines 1, 3 content hash, line 2 canonical
non-canonical '3526406: <hash>' lines printed: 6
VIOLATED: section 2 / R4 / R6: ...
run.sh: R3-VARSPEC-4: exit 1 (bug present)
```
