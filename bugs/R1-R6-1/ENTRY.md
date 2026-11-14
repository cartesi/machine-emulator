## R1-R6-1

**Title.** `cartesi-machine --print-uarch-cycle-root-hashes` prints made-up uarch hashes for the mcycle after a
rejection: it passes a fake revert uarch tail made of the revert root hash twice.

**Severity.** Medium (Low under the reading that treats the printer as diagnostics; see Rating).

### Problem

When the window of `--print-uarch-cycle-root-hashes` contains a rejecting instruction, the CLI prints, for the mcycle
that follows it, two hashes labelled `<rej>,1` and `<rej+1>`, both equal to the revert root hash. R6 requires the
uarch-level hashes of every mcycle after the rejecting instruction to be "the uarch trajectory that starts from the
canonical state", that is, the per-uarch-cycle state hashes of the machine to which the rejected input was delivered
(44 hashes in the test, the first `a6f7bf8f...`). The first printed hash claims to be the state after uarch cycle 1
and is not; the uarch trajectory is collapsed to a single cycle.

The cause is that the runner hands `collect_uarch_cycle_root_hashes` a fabricated `revert_uarch_tail`
`{ revert_root_hash, revert_root_hash }`. The library documents that this tail is "the state root hashes after each
uarch cycle of the machine corresponding to the revert root hash", which the caller must obtain by running the same
function on that machine, and at a rejected manual yield it emits that tail as the extra period. The library itself is
correct: given the real tail, the same chunked calls return the required trajectory. The code comment justifying the
fake tail ("which never happens outside cmio mode") is false: the CLI's default yield settings allow manual yields, so
any guest that rejects stops the run there, with or without cmio options.

Threat to the goal: none directly, because the CLI is not run by a deployment. The tool's output is exactly the set of
uarch-level hashes (or, with bundling, the subtree roots) that a uarch-level computation hash is built from. A user who
computes or checks uarch-level claims with it after a rejection gets a wrong trajectory, which in the honest-operator
role would be a completeness failure (wrong uarch-level claim).

### Component, role and area

`cartesi-machine` CLI, role Support (AUDIT.md: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI,
and the Lua helper libraries ... | Support. No production deployment runs the player, the bridge or the CLI."). Area:
the `--print-uarch-cycle-root-hashes` runner. The library function `collect_uarch_cycle_root_hashes` (role Honest
operator) does not show the defect.

### Location

`src/cartesi-machine.lua`, `uarch_cycle_root_hashes_runner_run` (lines 4053-4061 on audit/prt2):

```lua
-- The revert uarch tail only matters when the run stops at a rejected manual yield, which
-- never happens outside cmio mode. ...
local revert_root_hash = m:read_revert_root_hash()
local fake_revert_uarch_tail = { revert_root_hash, revert_root_hash }
...
self.runner:collect_uarch_cycle_root_hashes(chunk_end, self.log2_bundle, fake_revert_uarch_tail)
```

Contract of the tail: `src/cm.h`, documentation of `cm_collect_uarch_cycle_root_hashes` (`revert_uarch_tail`, and the
paragraph on the rejected manual yield).

### Evidence and test

`bugs/R1-R6-1/` contains `test.lua` and `README.md`. Run with `bugs/run.sh R1-R6-1` (about 1 s). The test:

1. loads the shared `baremetal-template` configuration (the `emit-output` guest waiting at an accepted manual yield)
   and computes the uarch trajectory of one mcycle from it with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)`
   (44 hashes; the last equals the template's root hash);
2. delivers the advance-state payload `R` (the guest rejects it), runs 30 mcycles, stores the machine in a
   `mktemp -d` directory, and finds the rejecting mcycle on the in-memory machine;
3. runs `cartesi-machine --load=<stored> --print-uarch-cycle-root-hashes=8,start:3526402`, checks that the hash
   printed for the reset of the rejecting mcycle is the revert root hash, and collects the hashes printed after it;
4. exits 1 if any printed hash differs from the trajectory of step 1, 0 otherwise, 2 on setup errors.

On audit/prt2 it exits 1 on every run (three runs by the prover, three by the reviewer), printing:

```
rejecting mcycle 3526406; revert root hash 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
required: 44 uarch-level hashes for mcycle 3526406 (trajectory from the canonical state), first a6f7bf8f8873acb46fd11c6fdbfdde23c49fde9a9bc3cc03257645c26fb53425
printed:  2 hashes after the rejection:
  3526406,1: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
  3526407: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
first difference at entry 1 (3526406,1): printed 428a6bb8..., required a6f7bf8f...
VIOLATED: R6: in every later mcycle, the uarch-level hashes printed by --print-uarch-cycle-root-hashes are the uarch trajectory that starts from the canonical state
run.sh: R1-R6-1: exit 1 (bug present)
```

The reviewer ran the test against a scratch copy of the CLI whose only change is to pass the real tail (computed with
`collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on the template); it printed the 44-hash trajectory
(`3526406,1: a6f7bf8f...`, `3526406,2: a05f14b2...`, ...) and the test exited 0. The reviewer also relaxed the test so
that printing fewer hashes after the rejection, or none, is accepted (only a printed hash that differs from the
required one fails), so that a fix that declines to print the period instead of computing it passes rather than ending
in a setup error. Found by the R6 hunter, proved and reviewed in campaign round 1.

### Trigger and reachability

A trusted CLI user runs `--print-uarch-cycle-root-hashes` over a window that contains a rejecting instruction. Any
guest that rejects an input reaches it; the test reaches it from the shared valid bare-metal template by delivering an
advance-state input, running, and storing the machine, all documented operations. No untrusted party is involved
beyond the input sender choosing a payload that the guest rejects.

### Rating

1. Out of scope: no. The trigger is a guest rejection of an input, reachable from a valid template, followed by a
   documented CLI option. It needs no "deliberate state change made through the machine API", no untrusted caller of
   the machine API, no violation of A1 to A8, and no non-guaranteed directory (the loaded directory was stored and
   not shared). The application is correctly designed (it yields with the rejected reason as the rollup interface
   allows).
2. Role: the `cartesi-machine` CLI, Support per the AUDIT.md table quoted above; that clause names the CLI, so it
   covers this component. Section 3: "A defect that only a support component shows is Medium when it would rate High
   or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an
   operator or a tool that computes claims." The printer computes the per-uarch-cycle state hashes and, with
   `log2_bundle_uarch_cycle_count`, their subtree roots, which are the leaves and parts of uarch-level computation
   hashes ("A computation hash can be built whole or in parts", section 3). It therefore stands in for the honest
   operator. The honest-operator library it calls (`collect_uarch_cycle_root_hashes`) does not share the defect: the
   wrong hashes come only from the tail the CLI fabricates, and the real tail yields the correct output.
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." In the
   honest-operator role the defect would be Critical (step 4), so section 3 rates it Medium.
4. Critical (for the role it stands in for): R4, "After a rejection, every hash the honest operator commits to follows
   R6, however it is computed", and R6, "In every later mcycle, the uarch trajectory that starts from the canonical
   state." The printed `<rej>,1` hash is not a state of that trajectory, at a reachable state.

Second reading: the example "a defect in a tool's diagnostics" under Low could be read to cover the CLI's printing
options, which the manual presents as a way to "see" state hashes. Under that reading the class is Low. The deciding
fact is whether `--print-uarch-cycle-root-hashes` counts as a tool that computes claims; its output is the claim
material itself (state hashes and bundle roots), not a diagnostic message about it, which is why Medium is the reading
taken here.

### Possible solution and risks

Pass the real tail: let the user supply the machine to which the rejected input was delivered (for example a
`--revert-machine=<dir>` option, or the snapshot the CLI itself takes before each cmio delivery) and compute the tail
with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on it, checking that its last entry equals the recorded revert
root hash. When no such machine is available, stop printing at the reset of the rejecting mcycle and say that the
following period needs the reverted machine, instead of printing fabricated hashes. Risk: low; it changes only the
CLI's output after a rejection, and scripts that parse that output would see the extra (correct) period or a message
in its place.

### Risk of not fixing it

No deployment runs the CLI, so the goal is not affected. Developers, auditors or operators who use the printer to
compute, compare or debug uarch-level claims after a rejected input get a wrong trajectory, labelled as real state
hashes, and could build or trust a wrong uarch-level commitment, or misdiagnose a correct implementation. Mitigation
outside the code: do not use the printer across a rejection; compute the period after it with
`collect_uarch_cycle_root_hashes` on the pre-delivery machine.
