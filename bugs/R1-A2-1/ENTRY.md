## R1-A2-1

**Title.** The PRT referee model in `doc/recipes/prt.lua` seals an epoch with its whole input record and never caps it at the input limit per epoch (2^24), so inputs past the grid fall out of the verified history.

**Severity.** Critical (preferred reading: rated as a deployed referee, per section 3). Low under the alternative reading in which the model's input files are the trusted referee operator's configuration.

### Problem

The model's dapp contract takes every input path it is given as the epoch's input record
(`inputs = map(input_paths, fs.read_file)`) and checks neither their count nor their size. `run_epoch` announces every
input with `input_added` (offsets 0..n-1) and seals the epoch with `epoch_sealed(#dapp_contract.inputs)`. Nothing caps
n at the input limit per epoch, 2^`ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH` = 2^24. The deployed referee does cap it:
`DaveConsensus.sol` seals at most `MAX_INPUTS_PER_EPOCH = 1 << ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH` inputs per
epoch (`lowerBound + pendingInputs.min(MAX_INPUTS_PER_EPOCH)`) and leaves the rest pending for later epochs.

The dispute grid that the model derives addresses only 2^24 input slots. For the model's geometry
(`new_geometry(10)`), `mcycle_height = 24 + 48 - 10 = 62` and `periods_per_input = 2^38`.
`validate_state_transition_response` only ever looks up `dapp_contract.inputs[epoch_input_offset + 1]` with
`epoch_input_offset < 2^24`. An input at offset 2^24 or later is therefore part of the sealed epoch, but no transition
form delivers it. The referee settles a state that leaves it out, and it is never carried into a later epoch. The model's
honest player applies the limit and stops on that input (`assert(epoch_input_offset < 1 << LOG2_MAX_ADVANCE_STATES_PER_EPOCH,
"input offset past the epoch's input limit")` in `add_pending_input`). It then never posts its claim, so any claim can win.
That is a completeness failure in the sense of section 1. The cap the honest operator applies is what R4 requires, so
the player is not at fault.

This breaks deployment obligation A3, which section 5 says "breaks the goal even when the emulator is correct". The
manual's list of the model's simplifications ("The model simplifies the PRT contracts in a few ways", doc/README.md)
does not mention dropping the limit. The recipes' verification-game model `vg.lua` does enforce it
(`#input_paths <= INPUTS_PER_EPOCH` in its `new_dapp_contract`). The manual itself states "the maximum number of inputs per epoch
(2<sup>24</sup>)". The manual shows the same `run_epoch` code, so the manual's model has the same gap.

### Component, role and area

The PRT referee model in `doc/recipes`, role **Referee model** (AUDIT.md: "The PRT referee model in `doc/recipes` |
Referee model"). The area is the model's input record and epoch sealing: the dapp contract and the simulated blockchain
publication of the epoch. The honest player's assert is the expected reaction of a support component, not a defect.

### Location

- `doc/recipes/prt.lua` `new_dapp_contract` (around lines 851-861): `inputs = map(input_paths, fs.read_file)`, with no bound.
- `doc/recipes/prt.lua` `run_epoch` (around lines 806-811): one `input_added` per path, then
  `epoch_sealed({ #dapp_contract.inputs })`.
- `doc/recipes/prt.lua` `new_geometry` (around line 831) and `validate_state_transition_response` (around lines 266-292):
  the grid covers 2^24 input slots.
- `doc/recipes/prt.lua` `add_pending_input` (around line 2211): the honest player's assert.
- The manual (`doc/README.md`, around line 9419) reproduces the same `run_epoch`.
- For comparison, `DaveConsensus.sol` (pinned Dave v3.0.0-alpha.7, `bugs/harness/work/dave/released/...`, lines 39 and
  472) has the cap.

### Evidence and test

`bugs/R1-A2-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A2-1`. The test writes a one-byte input
file and calls the model's exported `prt.new_dapp_contract(hash, paths)` with 2^24 + 1 copies of its path, so the model
really reads the file 2^24 + 1 times. It then runs `prt.new_referee(contract):run(server)` against a stand-in for the
referee server. The stand-in counts the `input_added` events, records the count passed to `epoch_sealed`, and stops the
run there, before any tournament starts. A control run with 3 inputs checks that the stand-in reaches the seal. The test
exits 0 if the referee seals the epoch with at most 2^24 inputs or refuses the oversized record, 1 if it seals the epoch
with more, and 2 on a setup error.

On audit/prt2 it prints:

```
control: 3 inputs -> 3 input_added, epoch_sealed(3)
building the referee's dapp contract from 16777217 input paths...
referee published 16777217 input_added events (offsets 0..16777216, ordered=true) and epoch_sealed(16777217)
dispute grid: 16777216 input slots (mcycle_height 62, periods_per_input 2^38); the input at offset 16777216 has no position
VIOLATED: A3: the input record assigns no more inputs to an epoch than the input limit per epoch (16777216); the referee model sealed the epoch with 16777217 inputs
run.sh: R1-A2-1: exit 1 (bug present)
```

The reviewer re-ran it twice. Both runs exited 1 with identical output, in about 26 s each and about 800 MB peak RSS (the
prover reports 3 identical runs). The test asserts A3 directly, and either correct fix (cap at 2^24, or refuse the
record) makes it exit 0. Found, proved and reviewed on Opus 5.5, with no fallback model.

### Trigger and reachability

The trigger is whoever fills the model's input record: a Lua caller of the exported `new_dapp_contract` /
`new_referee`, with more than 2^24 inputs for one epoch. Through the `prt.lua referee` command line, the same record
would need 2^24 + 1 path arguments, which exceeds the exec argument limit. In the model, the record is the referee
process's configuration, which the manual describes as files that "represent the inputs posted to the blockchain".
Rated as a deployed referee (section 3), the record is filled by input senders, whom section 4 makes untrusted with "any
bytes, any count". Section 7 lets the adversary "Send any number of inputs the deployment accepts". 2^24 + 1 inputs in
one epoch are then within the adversary's power. No machine state is involved, so no reachability argument about states
is needed.

### Rating

1. Out of scope: no. The candidate exclusion is "Defects that need the deployment to violate one of A1 to A8, unless ...
   an implementation of the referee model is what violates it (section 3)". Here the model's own `run_epoch` is what
   seals the over-limit epoch, so the exception applies and the exclusion does not. Section 5 also says that the
   manual's listed simplifications are not normative, and that "Any other disagreement between a deployed referee and
   the model is a defect in one of the two". Dave caps the epoch, the model does not, and that difference is not listed.
2. Role: the PRT referee model in `doc/recipes`, role Referee model (AUDIT.md). Section 3 says: "A defect in what it
   accepts or derives is rated as if a deployed referee had it." The model accepts the record and derives the epoch's
   input count, so this clause covers the component and this defect. Where the manual's model shares the gap, section 3
   says "then the manual is the defect, rated as a defect of the referee model", which gives the same rating. This is
   not a defect that "only changes how long a claim may take to respond, or only crashes or stalls the model".
3. High and Medium cases: none fits. The defect is not a verifier misbehaving on unreachable states, a crash in a
   component in the honest-operator role, or a constant-factor cost increase.
4. Critical: A3 is violated: "The input record assigns no more inputs to an epoch than the input limit per epoch". With
   R4, the honest operator "assigns inputs to epochs exactly as the referee does, including the input limit per epoch
   (A3)", which is impossible against this referee. Section 8 says: "violating any rule or obligation at a reachable
   state, or anywhere on the honest operator's path, is critical".

Alternative reading: the model's referee is "one trusted process" (manual), and its input files are its operator's
configuration of "the epoch's input files". Nothing untrusted fills them, and the CLI cannot even carry 2^24 + 1 paths.
Supplying an over-limit epoch would then be "a failure that needs misuse of an API by its trusted caller", which is
**Low**. The deciding fact is whether section 3's "rated as if a deployed referee had it" makes the model's input files
stand for a sender-filled on-chain input record (Critical), or whether they stay trusted configuration (Low). The
reviewer prefers the first reading. It follows section 3, the referee-model exception to the A1-A8 exclusion, section 5's
rule that unlisted disagreements with the deployed referee are defects, and section 4's untrusted input senders.

### Possible solution and risks

Enforce the limit where the model builds or seals the epoch. The model has a single epoch, so `new_dapp_contract` (or
`run_epoch`) should either refuse a record of more than `1 << LOG2_MAX_ADVANCE_STATES_PER_EPOCH` inputs with an error,
or seal only the first 2^24 inputs and leave the rest unannounced, the way DaveConsensus leaves them pending. The same
place could also enforce A3's second clause (no input whose honest delivery proof would exceed the per-transaction
limits). The manual's copy of `run_epoch` should match, or the manual should list this as a simplification and state
that the operator must keep the record within the limit. Risks: none for records at or below the limit. A truncating
fix must keep `input_added` and `epoch_sealed` consistent, so the honest player's "sealed input count mismatch" assert
still holds. The sibling verification-game model already does the first option: `vg.lua`'s `new_dapp_contract` has
`assert(#initial_state_hash == 32 and #input_paths <= INPUTS_PER_EPOCH, "invalid epoch")`. The PRT model lacks this
check.

### Risk of not fixing it

The model is a demonstration and no deployment runs it as its referee. But it is the normative stand-in documented next to
the manual, and code derived from it would inherit a referee that assigns inputs to an epoch beyond what the grid can
dispute. Such a referee silently drops inputs from the verified history and stops an honest operator that applies the
limit. In the model itself, triggering it needs a Lua-level caller that supplies more than 2^24 inputs. The deployed
Dave contracts already cap the epoch, which mitigates the risk for real deployments.
