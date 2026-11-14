# R1-R11-1: MetaStep counter-to-form map (does NOT reproduce)

**Candidate.** `MetaStep.step(counter, logs)` of machine-solidity-step v0.17.0-test1 (regenerated from
`audit/prt2`) was said to map positions to transition forms differently from the manual's
`validate_state_transition_response` and Dave's `CartesiStateTransition`. The claim was that it runs the uarch reset
after uarch cycle 0 instead of the last cycle, refuses the honest closing step+reset, and has no delivery form.

**Why it is refuted.** The hunter passed `counter` = index of the before-state, which is Dave's convention. The
pinned `MetaStep.sol` documents a different one. The file is byte-identical in `released/`, `regenerated/` and
Dave's `machine/step/src`:

> `counter` Number of meta-steps performed, counting this one. It is also the index of the state this meta-step
> produces [...] The uarch reset runs on meta-steps whose counter is a multiple of the uarch span, which produce the
> last leaf of each span. Callers that instead number transitions by their source state must pass counter as that
> number plus one.

With that convention (`counter` = before-index + 1), MetaStep resets exactly when
`(before-index & UARCH_CYCLE_MASK) == UARCH_CYCLE_MASK`. That is the same as Dave and the manual ("The last uarch
cycle allocated to each mcycle is also special: it resets the uarch right after executing the step"). MetaStep takes
no input parameters and documents only step and step+reset. The delivery form ("At the start of an input slot that
holds an input, the delivery of that input followed by a uarch step", THREAT_MODEL section 2) uses a separate
verifier path (SendCmioResponse then UArchStep), which is the one Dave uses. Pinned Dave never calls MetaStep.

**What the test asserts.** The requirement is R3: "Every log that a verifier accepts must then yield the same
after-hash, and that after-hash must be the canonical hash that the state transition function defines". The test
runs the regenerated `StepVerifier.metaStep` on a private anvil, called with the documented counter, on the
`baremetal-minimal` configuration:

- uarch cycle 0, at counters 1 and SPAN+1:
  - the honest step-only log is accepted, with the native after-hash;
  - a step+reset log is rejected.
- last uarch cycle, at counters SPAN and 2·SPAN:
  - the honest step+reset log is accepted, with the native step+reset hash (checked against `stepThenReset`);
  - a step-only log is rejected.

The hunter's observations are printed as INFO lines and are not asserted:

- with counter 0, a step+reset log is accepted;
- with counter SPAN-1, the honest step+reset log is rejected.

**Run.** `bugs/run.sh R1-R11-1`. It needs the shared EVM harness artifact
`bugs/harness/work/evm/out/StepVerifier.sol/StepVerifier.json`. It starts its own anvil on a random port between
30000 and 39999, and stops it afterwards.

**Expected on audit/prt2.** Exit 0 (not reproduced). Every assertion prints `ok`, and the last line is
`OK: R3: ... 0 failure(s)`. This was observed on two runs, each taking under 1 s.

What remains is documentation only. The library README calls `MetaStep.step` "the top-level state transition
function ... from state s[i] to state[i + 1]", but it does not mention input delivery.
