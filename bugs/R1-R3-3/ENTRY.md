## R1-R3-3

**Title.** The PRT referee model's `validate_state_transition_response` accepts a state-transition proof that carries
a log its transition form does not use (a `reset_uarch_log` on a non-closing step, a `send_cmio_log` away from an
input delivery), ignores it, and returns the honest after-hash. The deployed referee (Dave) rejects the same proof as
trailing data.

**Severity.** Medium (preferred reading). Low under the reading that the response's named fields are a message
schema, so an unused field is not part of the proof (see Rating).

### Problem

R3 makes the shape of a log a validity condition: "Conditions on the log are validity conditions. A log that fails
one must be rejected. Examples are wrong order, wrong address, wrong size, duplicate, missing, or trailing data". The
referee model in `doc/recipes/prt.lua` chooses which logs of the `ProveStateTransition` response to verify from the
position alone. It reads `response.send_cmio_log` only when `state_transition_offset == 0`, `input_period_offset == 0`
and the slot holds an input. It reads `response.reset_uarch_log` only when `uarch_cycle == UARCH_CYCLE_MAX`. It never
checks that the other fields are absent. A response with an extra, validly produced log is therefore accepted, and
the extra log is silently dropped.

The deployed referee, Dave v3.0.0-alpha.7 `CartesiStateTransition.transitionState`, receives the same logs
concatenated in one `proofs` buffer and calls `_requireAccessLogProofFullyConsumed` after the last log of the form, so
it reverts with `InvalidAccessLogProofLength` (its comment: "exact consumption rejects both trailing data and
truncated proofs"). The model and the deployed referee thus disagree on what a referee verifies, which section 5
calls "a defect in one of the two". The PRT bridge (`doc/recipes/prt-ethereum.lua` `transition_proof`) already
enforces the exact shape when it encodes a response for Dave ("transition has the wrong reset shape", "unexpected
input-delivery proof"); the model does not.

The after-hash is not affected: every accepted response still yields the canonical after-hash, because the ignored
log is not applied. The goal of section 1 is not broken. The defect is the acceptance of trailing data that does not
affect the result, which R3 forbids and section 8 lists as Medium for a referee.

### Component, role and area

`doc/recipes/prt.lua`, the PRT referee model in `doc/recipes`. AUDIT.md: "The PRT referee model in `doc/recipes` |
Referee model". The area is the referee's leaf-level verification of a state transition
(`settle_uarch_state_hash` calls `validate_state_transition_response`). The manual reproduces the same function in
`doc/README.md`. `doc/recipes/prt-ethereum.lua` `verify_transition` (support, an off-chain native check) has the same
shape and is not asserted.

### Location

- `doc/recipes/prt.lua`, `validate_state_transition_response` (lines 265-293), called from
  `settle_uarch_state_hash` (around line 424).
- `doc/README.md`, the same function in "The state transition function" (line 9465) and in the full recipe listing
  (line 10874).
- For comparison: Dave `prt/contracts/src/state-transition/CartesiStateTransition.sol` `transitionState` and
  `_requireAccessLogProofFullyConsumed` (pinned under `bugs/harness/work/dave/released/`);
  `doc/recipes/prt-ethereum.lua` `transition_proof` (lines 168-189).

### Evidence and test

`bugs/R1-R3-3/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-R3-3` (about 2 s; needs the in-tree build
and the harness config `bugs/harness/work/configs/baremetal-template`).

The test loads the real `prt` module and finds the local closure `validate_state_transition_response` by walking the
upvalues of the module's exported functions, so it runs the code the referee runs. It uses the bare-metal rolling
template (waiting at a manual yield with the accepted reason) and logs produced by the emulator itself
(`log_step_uarch`, `log_send_cmio_response`, `log_reset_uarch`).

- Four controls: the honest response is accepted with the correct after-hash for each transition form (plain step at
  uarch cycle 0 of a slot without input, step at uarch cycle 3 of a slot with an input, delivery plus step, closing
  step plus reset in period 1). A failed control exits 2.
- Six responses with one extra validly produced log: a reset log on the plain step (uarch cycle 0 and uarch cycle
  3), a reset log on delivery plus step, a send_cmio log on the plain step in a slot without input, a send_cmio log on
  the step at uarch cycle 3 of a slot with an input, and a send_cmio log on the closing step plus reset. The test
  requires each to be rejected (the function raises an error).

On audit/prt2 every control prints `control OK: ...`, each of the six prints
`VIOLATED: <case>: accepted, after-hash X (honest after-hash X)` with X equal to the honest after-hash, and the run
ends with `VIOLATED: R3: a referee must reject a state-transition proof with superfluous (trailing) logs, as Dave's
CartesiStateTransition does; the referee model accepted 6 of 6 such proofs` and `run.sh: R1-R3-3: exit 1 (bug
present)`. The reviewer re-ran it twice with identical output and exit 1. The prover reports that a patched copy of
`prt.lua` that checks the response shape made the test exit 0 with the controls still passing. Found, proved and
reviewed with `claude-opus-5-5`; no fallback was used.

### Trigger and reachability

Any claimant in a leaf match answers `ProveStateTransition` with the honest logs of the form plus an extra log. Section
4 lets dishonest claimants send "any logs, any proofs", and section 7 lets the adversary "Hold any claim, including the
honest one, and answer for it". Any position and any reachable before-state work, including the valid template
itself; no special state is needed. The honest player never sends an extra log, so the honest claim is not harmed.

### Rating

1. Out of scope: no. The trigger is a dishonest claimant's proof, which section 4 places in the adversary's power. None
   of the exclusions of section 8 applies; in particular the A1-A8 exclusion does not, since no obligation is
   violated by the deployment ("unless an implementation of the referee model is what violates it").
2. Role: referee model (AUDIT.md: "The PRT referee model in `doc/recipes` | Referee model"). Section 3: "A defect in
   what it accepts or derives is rated as if a deployed referee had it." The clause covers this component and this
   defect, which is in what the model accepts. The defect is in the model's own dispatch of logs, not inherited from
   the off-chain verifiers it calls (each of `verify_step_uarch`, `verify_send_cmio_response` and
   `verify_reset_uarch` correctly checks the log it is given), so the AUDIT.md rule that a defect shown "only through
   them is rated as theirs" does not apply.
3. High and Medium cases: Medium, "A referee verifier that accepts trailing data that does not affect its result
   (R3)." A deployed referee with the model's behaviour is exactly that: in Dave's encoding the extra log is bytes
   after the last consumed log of the form, which Dave rejects for that reason, and the accepted after-hash is the
   honest one. The case speaks of a referee verifier; it covers the model through the section 3 clause above. No High
   case fits: there is no wrong or second after-hash and no unreachable-state behaviour.
4. Critical: not reached. Every accepted response yields the canonical after-hash, so R3's first sentence ("Every log
   that a verifier accepts must then yield the same after-hash, and that after-hash must be the canonical hash") holds;
   only R3's log-validity condition is violated.

Two readings. Preferred (Medium): the `ProveStateTransition` response is the proof. The manual presents the function
as "a representation of what the blockchain uses to validate a state transition", the blockchain receives one
concatenated buffer, and the bridge enforces the exact shape. An unused log is then trailing (or duplicate) data of
the proof. Alternative (Low, or no defect): the response is a table of independently verified logs and an unused
named field is like an unknown key of a message, not part of any log; the model then matches the manual's own model
line for line, and the disagreement with Dave is only an encoding difference that affects no claim. The fact that
would decide is whether the manual's referee model treats the response as the exact proof; the manual does not state
an exactness requirement on the response shape, and its own listing has the same behaviour, so a fix belongs in both
`prt.lua` and `doc/README.md`.

### Possible solution and risks

In `validate_state_transition_response` (and the copy in `doc/README.md`), require the shape of the response to match
the transition form before verifying: `assert((response.send_cmio_log ~= nil) == (state_transition_offset == 0 and
input_period_offset == 0 and input_data ~= nil), ...)` and `assert((response.reset_uarch_log ~= nil) == (uarch_cycle ==
UARCH_CYCLE_MAX), ...)`, and optionally reject any other key of `response`. The honest player's
`prove_state_transition` already produces exactly these shapes, so the honest path is unaffected. The risk is low: a
player that adds an unneeded field would now be rejected, which matches Dave. The same check could be added to
`prt-ethereum.lua` `verify_transition` for consistency.

### Risk of not fixing it

No settled state or output changes: the extra log is ignored and the after-hash stays canonical. What remains is a
referee model that is more permissive than R3 and than the deployed referee, so tests and demonstrations run against
the model can accept proofs that Dave reverts, and a referee implemented from the manual's listing would accept
trailing proof data. Only a claimant who sends a malformed proof can trigger it, and it gains nothing beyond what the
honest proof gives.
