## R1-A6-2

**Title.** The PRT player and deployer check a deployment's version only by its pristine uarch hash, never by
`CM_MARCHID`, so they accept a verifier of another version whose uarch image is unchanged.

**Severity.** Medium (preferred reading). Low under the reading that R13's check only has to refuse the versions
released so far (see Rating).

### Problem

Before it plays, `doc/recipes/crisium.lua` (the PRT player) checks the deployed `CartesiStateTransition` against its
own emulator in one way only. It compares `UARCH_PRISTINE_STATE_HASH()` with `cartesi.UARCH_PRISTINE_STATE_HASH`.
`doc/recipes/prt-deploy.lua` makes the same single check when it deploys. The pristine hash covers the uarch program
image and the uarch state that a reset produces. It does not cover the verifier's step, reset and delivery code
(`UArchStep.sol`, `UArchReset.sol`, `SendCmioResponse.sol`, generated from `uarch-step.cpp`,
`uarch-reset-state.cpp` and `send-cmio-response.cpp`). Those decide R13's "accesses each logged transition makes,
and their order", which are part of the protocol. The verifier also publishes `CM_MARCHID`, "so a claimer can
compare it with its own emulator before joining". R13 makes the machine-identification registers change with every
version that changes the transition function. No recipe reads `CM_MARCHID`. `doc/recipes/prt-lua-bridge.md`
presents the pristine comparison as the version check ("A matching `CM_MARCHID` does not guarantee that, which is
why each player compares the deployed verifier's pristine hash with the emulator's before playing").

A version that changes only uarch-step, reset or delivery code keeps the pristine hash. This branch's history has
such a change: 4310fa3 ("fix!: report a uarch that halts on its last cycle as halted") says "Root hashes are
unchanged, but a logged step at the cycle limit now also reads the halt flag, so the Solidity step must be
regenerated". afd5f9d (TLB index check) also changed only `src/uarch-step.cpp`. Against a deployment of such a
version, the player starts and plays with a verifier that implements another transition function than its own
emulator. R13 asks the opposite: "The honest operator must be able to detect and refuse a mismatch between its
build and a deployment. The check must refuse every pairing of its build with a deployment of another released
version." A mixed deployment breaks A6. Proofs the honest operator logs may then be rejected on-chain (the test
shows one), which is a completeness failure of section 1.

### Component, role and area

The PRT player and deployer in `doc/recipes` (`crisium.lua`, `prt-deploy.lua`). AUDIT.md component table: "The PRT
player and bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the
CLI." The area is the start-up and deployment version check. The player is an implementation of an operator, so it
stands in for the honest operator.

### Location

- `doc/recipes/crisium.lua`, lines 128-132: the only start-up check of the deployed verifier
  (`UARCH_PRISTINE_STATE_HASH()` vs `cartesi.UARCH_PRISTINE_STATE_HASH`).
- `doc/recipes/prt-deploy.lua`, lines 44-48: the same check at deployment.
- `doc/recipes/prt-lua-bridge.md`, lines 193-196: documents the pristine check as the version check.
- Dave `prt/contracts/src/state-transition/CartesiStateTransition.sol` (v3.0.0-alpha.7): `CM_MARCHID` and
  `UARCH_PRISTINE_STATE_HASH`, published for this comparison.

### Evidence and test

`bugs/R1-A6-2/` contains `test.lua` (the test), `run-crisium.sh` (starts the real `doc/recipes/crisium.lua` in
sentinel mode against one application and prints ACCEPTED once it passes its start-up checks and writes its first
status file, REFUSED if it exits before), `deploy.lua` (deploys a Dave build with the real `prt-deploy.lua`, with
the deployer's constants set to the deployed verifier's own), `foundry.toml` (build settings for the variant
verifiers) and `README.md`.

The test compiles Dave's `CartesiStateTransition.sol` over the untouched machine-solidity-step v0.17.0-test1 sources
(`CM_MARCHID` 22, step code without the TLB index check and with the old halt/overflow order) twice: "released" as
is (pristine `0x558f...3926`), and "other" with only `UARCH_PRISTINE_STATE_HASH` set to this build's
(`0x89ae...43d7`). It starts its own anvil on a free port from 18700 up and makes three full Dave deployments:
"ours" (the harness's patched Dave build over the step regenerated from this branch, `CM_MARCHID` 23), "other" and
"released". As a witness that "other" implements another transition function, it logs a uarch step with this
branch's emulator at `uarch_cycle = UARCH_CYCLE_MAX`: "ours" accepts it with the emulator's after-hash, "other"
rejects it. It then runs the player against each: the controls require "ours" ACCEPTED and "released" REFUSED, and
the assertion requires "other" REFUSED.

Run: `bugs/run.sh R1-A6-2` (about 10 s; needs `work/dave/patched`, `work/solidity-step/released`,
`work/configs/baremetal-minimal`, forge/anvil/cast). It removes its temp dir and stops its anvil. Output on
audit/prt2 (reviewer re-ran it twice, identical):

```
  this build: MARCHID 23, pristine 0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7; deployed 'ours' CM_MARCHID 23
  deployed 'other': CM_MARCHID 22, pristine 0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7
  witness step (uarch cycle at its limit): the deployment of this build's version accepts the emulator's log, 'other' refuses it: InvalidAccessLogProofLength(consumed 1920, provided 3840)
  player vs 'ours': ACCEPTED
  player vs 'released': REFUSED
    lua5.4: /home/user/machine-emulator/doc/recipes/crisium.lua:128: emulator and Solidity pristine uarch hashes differ
  player vs 'other': ACCEPTED
VIOLATED: R13: the player must refuse a deployment of another version (CM_MARCHID 22, v0.17.0-test1 step code) even when its pristine uarch hash equals this build's (MARCHID 23)
run.sh: R1-A6-2: exit 1 (bug present)
```

The reviewer also ran an out-of-tree copy of the test with a copy of `crisium.lua` that also compares
`CM_MARCHID()` with `cartesi.MARCHID`: "ours" ACCEPTED, "released" REFUSED, "other" REFUSED ("emulator and Solidity
marchid differ"), exit 0. Found, proved and reviewed on Opus 5.5 (no fallback).

### Trigger and reachability

Trigger: an operator starts the player (or deploys with `prt-deploy.lua`) against a deployment whose verifier was
generated from a version with the same uarch image as its own build but different step, reset or delivery code. No
adversary action is needed beyond publishing or pointing at such a deployment. The pairing in the test is modeled:
the released machine-solidity-step versions in the harness (v0.16.0 at fb00a32 and v0.17.0-test1 at 6f91eb9) both
have `CM_MARCHID` 22 and pristine `0x558f...`, which the player refuses. What makes the pairing realistic is that
versions that change only uarch-step code keep the pristine hash, as 4310fa3 and afd5f9d show on this branch; a
later release made of such changes would pair with this build's release and pass the check in both directions.

### Rating

1. Out of scope: not excluded. The exclusion "Defects that need the deployment to violate one of A1 to A8" does not
   apply, because the defect is the missing detection, which section 8 rates even with no mismatch present ("A node
   that cannot detect a version mismatch, while every node in fact runs the deployment's version"), and R13 puts the
   detection on the honest operator. No other exclusion of section 8 fits.
2. Role: Support (AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support"). Section 3: "A defect that
   only a support component shows is Medium when it would rate High or Critical in the role the component stands in
   for, such as ... the honest operator for an implementation of an operator". This clause covers the player, an
   implementation of an operator. No component in another role shares the defect in this campaign (the emulator
   exposes `MARCHID`; production nodes are out of scope).
3. High and Medium cases: in the stood-in honest-operator role it matches High, "A node that cannot detect a version
   mismatch, while every node in fact runs the deployment's version" (and would be Critical by R13/A6 with a
   mismatch present). Hence the Medium case "A defect that only a support component shows, when section 3 rates it
   Medium". Section 8 step 2: "A defect that only a support component shows is never above Medium."
4. Critical: not applicable (support component). The rule violated is R13: "The honest operator must be able to
   detect and refuse a mismatch between its build and a deployment. The check must refuse every pairing of its build
   with a deployment of another released version."

Two readings. If "another released version" includes versions released after this build (the check runs for the
build's lifetime, and R13 names the machine-identification registers as what every version changes), the check
fails R13 by construction and the rating is Medium. If it covers only versions already released, the check refuses
every existing pairing today (both known releases have a different pristine hash) and the defect is Low (a latent
design gap that violates no rule yet). Deciding facts: whether any released or planned version shares this build's
pristine hash with a different `CM_MARCHID` or step code, and whether R13's check is meant to hold against future
releases. The reviewer prefers the first reading.

### Possible solution and risks

In `crisium.lua` and `prt-deploy.lua`, also compare `CM_MARCHID()` with `cartesi.MARCHID` and refuse on mismatch,
keeping the pristine comparison (the marchid alone does not change within a release cycle or between pre-releases,
as `prt-lua-bridge.md` notes). Update `prt-lua-bridge.md` to say that both are checked. Risk: a deployment built
from a step whose `CM_MARCHID` was not regenerated with the emulator would be refused; that is the intended effect.
Neither value covers every protocol element (for example a step change released without a marchid bump), so the
check still relies on R13's discipline of bumping the machine-identification registers.

### Risk of not fixing it

An operator who uses the recipes as the model for its node's version check can join a deployment of another version
whose uarch image matches its own, and fail to have its proofs verified on-chain, losing its claim. The production
nodes are out of scope here and may check `CM_MARCHID` themselves. Mitigation outside the code: compare the
deployed verifier's `CM_MARCHID` with the emulator's `MARCHID` by hand before joining.
