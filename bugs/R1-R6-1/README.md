# R1-R6-1: `--print-uarch-cycle-root-hashes` prints made-up uarch hashes after a rejection

Component: `cartesi-machine` CLI (`src/cartesi-machine.lua`, `uarch_cycle_root_hashes_runner_run`), role Support.

## Defect

The runner passes `fake_revert_uarch_tail = { revert_root_hash, revert_root_hash }` to
`collect_uarch_cycle_root_hashes`. Its comment says a rejected manual yield "never happens outside cmio mode", but
the CLI's default `iyield` allows manual yields, so any guest can reject without cmio options. When the window
includes the rejecting instruction, the period after it is printed as the revert root hash twice, instead of
the uarch trajectory from the canonical state (the machine the rejected input was delivered to).

## Requirement (THREAT_MODEL.md, R6)

> From the rejecting instruction until the next delivery that changes the state, the uarch-level hashes are content
> hashes of these states.
> - In the mcycle of the rejecting instruction, before the closing reset, states of the rejecting machine.
> - In every later mcycle, the uarch trajectory that starts from the canonical state.

## What the test does

1. Loads `baremetal-template` (the `emit-output` guest waiting at an accepted manual yield) and computes the uarch
   trajectory of one mcycle from it, `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` (44 hashes: uarch cycles,
   halt, reset).
2. Delivers payload `R` (the guest rejects it), runs 30 mcycles, stores the machine in a `mktemp -d` directory,
   and finds the rejecting mcycle on the in-memory machine.
3. Runs `cartesi-machine --load=<stored> --print-uarch-cycle-root-hashes=<n>,start:<mcycle>` over a window that
   includes the rejection, and parses the hashes printed after `<rej>: <revert root hash>`.
4. Asserts that they are the trajectory from step 1. Exit 1 while they differ, 0 when they match, 2 on setup
   errors.

A check outside the test confirmed that the same chunked `collect_uarch_cycle_root_hashes` calls on the stored
machine, given the real tail, return exactly the step-1 trajectory after the rejection reset, so a CLI that
passes the real tail would make the test exit 0.

## Run

```sh
bugs/run.sh R1-R6-1      # about 1 s
```

## Expected output on audit/prt2

```
rejecting mcycle 3526406; revert root hash 428a6bb8...
required: 44 uarch-level hashes for mcycle 3526406 (trajectory from the canonical state), first a6f7bf8f...
printed:  2 hashes after the rejection:
  3526406,1: 428a6bb8...
  3526407: 428a6bb8...
first difference at entry 1 (3526406,1): printed 428a6bb8..., required a6f7bf8f...
VIOLATED: R6: ...
run.sh: R1-R6-1: exit 1 (bug present)
```
