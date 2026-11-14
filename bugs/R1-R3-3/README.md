# R1-R3-3: referee model accepts state-transition proofs carrying superfluous logs

**Component:** `doc/recipes/prt.lua` `validate_state_transition_response` (the same body is in `doc/README.md`).
AUDIT.md gives it the referee-model role. `doc/recipes/prt-ethereum.lua` `verify_transition` (support) has the same
shape but is not asserted here.

## What is asserted

The model reads `response.send_cmio_log` only when `state_transition_offset == 0`, `input_period_offset == 0` and the
slot holds an input. It reads `response.reset_uarch_log` only when `uarch_cycle == UARCH_CYCLE_MAX`. In every other
case the field is ignored and the proof is accepted. The deployed referee (Dave v3.0.0-alpha.7
`CartesiStateTransition.transitionState`) concatenates the logs into one `proofs` buffer and calls
`_requireAccessLogProofFullyConsumed`, so it reverts the same proof with `InvalidAccessLogProofLength` (trailing
data).

The test gets the real closure from the loaded `prt` module (by walking upvalues, because the function is local) and
calls it on a bare-metal rolling template (`baremetal-template` config) with honest logs from the emulator:

- 4 controls: the honest proof is accepted with the right after-hash for each transition form (plain step,
  mid-mcycle step in an input slot, delivery+step, step+reset). If a control fails, the test exits 2.
- 6 proofs with one extra log that was produced validly: a reset log on a plain step (uarch cycle 0 and 3), a reset
  log on delivery+step, a send_cmio log on a plain step in a slot with no input, a send_cmio log on a step at uarch
  cycle 3 in a slot that holds an input, and a send_cmio log on a closing step+reset in period 1. The test requires
  each of them to be rejected (the function raises an error).

Requirement (THREAT_MODEL.md, R3): "Conditions on the log are validity conditions. A log that fails one must be
rejected. Examples are wrong order, wrong address, wrong size, duplicate, missing, or trailing data, ..." Also
section 3: "a disagreement between the two on what a referee verifies or derives is a defect in one of them", and
section 5: "Any other disagreement between a deployed referee and the model is a defect in one of the two."

## Run

```sh
bugs/run.sh R1-R3-3      # about 2 s; needs the in-tree build and bugs/harness/work/configs/baremetal-template
```

## Expected output on audit/prt2

Every control line prints `control OK`. Each of the 6 superfluous-log proofs prints `VIOLATED: ... accepted,
after-hash X (honest after-hash X)`, and the run ends with
`VIOLATED: R3: ... the referee model accepted 6 of 6 such proofs` and `exit 1 (bug present)`.

With a fix, the test exits 0. One example fix requires `(response.send_cmio_log ~= nil) == (delivery position with
input)` and `(response.reset_uarch_log ~= nil) == (uarch_cycle == UARCH_CYCLE_MAX)`. This was checked by loading a
patched copy of `prt.lua` ahead on `LUA_PATH`: all 6 proofs were rejected and the controls still passed.
