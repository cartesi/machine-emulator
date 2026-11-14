# R1-A6-2: the PRT player's version check compares only the pristine uarch hash, never `CM_MARCHID`

## What is asserted

At start-up, `doc/recipes/crisium.lua` (the PRT player) checks the deployed verifier against its own build in one
way only. It compares `CartesiStateTransition.UARCH_PRISTINE_STATE_HASH()` with `cartesi.UARCH_PRISTINE_STATE_HASH`
(lines 126-131). `prt-deploy.lua` makes the same single check. The pristine hash covers the uarch RAM image and the
pristine uarch registers. It does not cover the verifier's step, reset and delivery code (`UArchStep.sol`,
`UArchReset.sol`, `SendCmioResponse.sol`) or the verifier's `CM_MARCHID`. R13 makes `CM_MARCHID` change with every
version. The verifier publishes it "so a claimer can compare it with its own emulator before joining", but nothing
reads it.

`test.lua` does the following.

1. It compiles Dave's `CartesiStateTransition.sol` (from the harness's patched Dave tree) over the untouched
   machine-solidity-step v0.17.0-test1 sources (`bugs/harness/work/solidity-step/released/src`). This gives
   `CM_MARCHID` 22, the step code without the TLB index check, and the old halt/overflow order. It builds two
   variants with `forge` (about 2 s each):
   - **released**: unchanged, with pristine hash `0x558f...3926`.
   - **other**: the same, except that `UARCH_PRISTINE_STATE_HASH` is this build's (`0x89ae...43d7`). This models a
     deployment of another released version whose uarch program equals this build's. Only its step code and its
     `CM_MARCHID` differ.
2. It starts its own anvil, on a free port from 18700 up, and makes three full Dave deployments with
   `doc/recipes/prt-deploy.lua`:
   - **ours**: the harness's patched Dave build, which uses the step regenerated from this branch.
   - **other**.
   - **released**.

   `deploy.lua` gives prt-deploy the deployed verifier's own constants, so that the deployment stands for a
   deployer whose emulator matches its verifier.
3. It shows that *other* implements a different transition function than this build. This build's emulator logs a
   uarch step with the uarch cycle at `UARCH_CYCLE_MAX`, made with `write_reg` on `baremetal-minimal`. *ours*
   accepts that log with the emulator's after-hash. *other* rejects it with
   `InvalidAccessLogProofLength(consumed 1920, provided 3840)`, because v0.17.0-test1 returns on the cycle limit
   before it reads the halt flag. This witness only shows that the two verifiers differ. It is not a soundness
   claim.
4. It starts the real `crisium.lua` (`run-crisium.sh`: sentinel mode, no checkpoints) against each application.
   ACCEPTED means that the player passed its start-up checks and wrote its first status file. REFUSED means that
   it exited before that.
   - Control: *ours* must be ACCEPTED.
   - Control: *released* must be REFUSED (`emulator and Solidity pristine uarch hashes differ`).
   - **Assertion**: *other* must be REFUSED.

Exit codes:

- **1** if the player accepts *other*.
- **0** if the player refuses it.
- **2** on setup errors, including:
  - a missing Dave build, step sources, config or tool;
  - either control failing;
  - the witness failing to show a difference.

A sketch of a fix was checked out of tree: a copy of `crisium.lua` that also compares `CM_MARCHID()` with
`cartesi.MARCHID`. With it, the test exits 0. In that run *ours* is accepted, and *other* is refused with
"marchid differ".

## Requirement

THREAT_MODEL.md R13: "Every version that changes the state transition function changes the machine-identification
registers in the hashed state. The honest operator must be able to detect and refuse a mismatch between its build
and a deployment. The check must refuse every pairing of its build with a deployment of another released version."
A6: "Every verifier, the uarch program fixed on-chain, and every honest operator in a deployment implements the same
state transition function (R13)."

Role (AUDIT.md): the PRT player in `doc/recipes` is Support. It stands in for the honest operator's version check.

Scope note: the pairing that slips through is modeled. No released machine-solidity-step is known to share this
build's pristine hash. v0.16.0 and v0.17.0-test1 both have `0x558f...`, and the *released* control shows that the
check refuses them. The test shows that the check does not consult the one value R13 guarantees to differ between
versions. It accepts any other-version verifier whose uarch image is unchanged, such as a version that changes only
`uarch-step.cpp` (as afd5f9d and 4310fa3 did on this branch).

## How to run

```sh
bugs/run.sh R1-A6-2
```

It needs the harness's `work/dave/patched` build, `work/solidity-step/released`, `work/configs/baremetal-minimal`,
forge/anvil/cast and solc 0.8.30 (offline, from svm). It runs in about 10 s and leaves nothing behind: its temp dir
and its anvil are removed at exit.

## Expected output on audit/prt2

```
  this build: MARCHID 23, pristine 0x89ae34ba...43d7; deployed 'ours' CM_MARCHID 23
  deployed 'other': CM_MARCHID 22, pristine 0x89ae34ba...43d7
  witness step (uarch cycle at its limit): the deployment of this build's version accepts the emulator's log, 'other' refuses it: InvalidAccessLogProofLength(consumed 1920, provided 3840)
  player vs 'ours': ACCEPTED
  player vs 'released': REFUSED
    lua5.4: .../doc/recipes/crisium.lua:128: emulator and Solidity pristine uarch hashes differ
  player vs 'other': ACCEPTED
VIOLATED: R13: the player must refuse a deployment of another version (CM_MARCHID 22, v0.17.0-test1 step code) even when its pristine uarch hash equals this build's (MARCHID 23)
run.sh: R1-A6-2: exit 1 (bug present)
```
