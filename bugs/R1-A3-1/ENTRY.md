## R1-A3-1

**Title.** The PRT player never fetches the inputs DaveConsensus defers past an epoch's input limit, so it crash-loops and stops defending the next epoch.

**Severity.** Medium

### Problem

The pinned DaveConsensus seals each epoch as `[lo, lo + min(pending, 2^24))` (`_nextInputIndexUpperBound`) and leaves
the rest of the pending inputs for the next epoch. Every input it defers in this way was added to the InputBox at or
before the block of epoch N's `EpochSealed` log. That is the condition for it to be pending when the seal ran.

`crisium.lua` (`open_epochs`) opens epoch N+1's listener with
`first_input_block = previous_seal and eth.small(previous_seal.log.blockNumber) or first_block`. The listener in
`prt-epoch.lua` then fetches InputAdded logs only from that block on (`history:get_logs(address, self.first_input_block,
...)`). It never sees the deferred inputs that were added in blocks before epoch N's seal. The next input it does see
fails the `index == self.input_begin + #self.inputs` check ("input stream has a gap or duplicate", prt-epoch.lua:73). If
no later input arrives, epoch N+1's seal fails `"sealed input count mismatch"` (prt-epoch.lua:96). The assertion
propagates out of `pass()`, so crisium dies. `prt-supervise.sh` relaunches it, and it rebuilds the listener with the same
`first_input_block`. The same failure therefore repeats on every restart. The player cannot compute or defend its claim
for epoch N+1, or for any later epoch.

In the role the player stands in for, this is a completeness failure (section 1: the honest operator "cannot respond in
time. If the honest claim is eliminated, a dishonest claim can win"). It also breaks R4 directly, because the player does
not assign inputs to epochs as the referee does once the input limit binds.

### Component, role and area

The PRT player in `doc/recipes`: `crisium.lua` (how it opens each epoch's listener) and `prt-epoch.lua` (the epoch
input/seal listener). AUDIT.md table: "The PRT player and bridge in `doc/recipes`, ... | Support. No production
deployment runs the player, the bridge or the CLI." Area: observing the chain (fetching the on-chain input record) and
assigning inputs to epochs.

### Location

- `doc/recipes/crisium.lua`, `open_epochs`, line 267: `first_input_block = previous_seal and
  eth.small(previous_seal.log.blockNumber) or first_block`. The comment above it only considers inputs "logged in the
  previous seal's block".
- `doc/recipes/prt-epoch.lua`, `methods:poll`, line 37 (fetch from `self.first_input_block`), line 73 (gap assert),
  lines 96-99 (sealed count assert). `M.new` lines 165-167 document the "only from the block that sealed the previous
  epoch on" choice.
- Referee behavior relied on: `bugs/harness/work/dave/released/cartesi-rollups/contracts/src/DaveConsensus.sol`,
  `_nextInputIndexUpperBound` (lines 470-472) and the seal at lines 270-271. `prt-contracts.patch` does not change it.

### Evidence and test

`bugs/R1-A3-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A3-1`. It needs no chain and no machine,
and it runs in under a second.

The test loads the real `prt-epoch.lua`, with the dispute bridge stubbed because the bridge is outside the defect. It
drives the listener against a fake chain whose `logs()` honours `fromBlock`, a fake ABI and a recording player. It
computes `first_input_block` by extracting the expression crisium.lua passes to `epoch.new` from crisium's source and
evaluating it. As a setup check, it confirms that the pinned DaveConsensus source still contains the
`min(MAX_INPUTS_PER_EPOCH)` cap. Epoch 0 is sealed at block 100 as `[0, 2^24)`. Input `2^24` was added at block 50.

The test has two scenarios:
1. The backlog input plus input `2^24+1` at block 120, with epoch 1 sealed as `[2^24, 2^24+2)`.
2. The backlog input only, with epoch 1 sealed as `[2^24, 2^24+1)`.

For each scenario, the test asserts that epoch 1's listener delivers offsets `0..n-1`, accepts the seal and opens the
dispute. A control run of each scenario with `first_input_block = first_block` must pass, or the test exits 2.

On audit/prt2 it prints the following and exits 1 (reproduced twice by the reviewer):

```
[backlog input + one input after the seal] crisium first_input_block = 100 (epoch 0 sealed at block 100, deferred input 16777216 added at block 50)
[backlog input + one input after the seal] fetched InputAdded/EpochSealed from block(s) 100,100; poll ok=false error: .../doc/recipes/prt-epoch.lua:73: input stream has a gap or duplicate; delivered offsets {}; epoch_sealed {}
[backlog input only] ... poll ok=false error: .../doc/recipes/prt-epoch.lua:96: sealed input count mismatch; delivered offsets {}; epoch_sealed {}
VIOLATED: R4: 'It assigns inputs to epochs exactly as the referee does, including the input limit per epoch (A3)' - ...
run.sh: R1-A3-1: exit 1 (bug present)
```

The reviewer ran the test against a copy of crisium.lua whose expression was changed to `first_input_block =
first_block` (with `RECIPES_DIR` pointed at the copy). Both scenarios then passed and the test exited 0.

Limitation: the test evaluates crisium's expression with only `previous_seal`, `next_epoch`, `first_block`, `eth` and
`math` in scope. A fix that computes the block elsewhere, or that uses other crisium locals, makes the test exit 2
(setup error) rather than 0, so the test's extraction must be updated together with such a fix.

Opus 5.5 found, proved and reviewed it. No fallback model was used.

### Trigger and reachability

An input sender triggers it. More than 2^24 inputs for the application must be pending (added since epoch N's lower bound)
when DaveConsensus seals epoch N. That seal happens when epoch N-1's tournament settles, so inputs accumulate for the
whole length of a dispute. Section 4 lists "input senders (any bytes, any count)" as untrusted, and section 7 lets the
adversary "Send any number of inputs the deployment accepts". The InputBox accepts them, and the consensus defers the
excess exactly as A3 requires ("The input record assigns no more inputs to an epoch than the input limit per epoch"). An
honest application with heavy traffic reaches the same state with no adversary. No guest state is involved. The state is
a chain history that every deployment admits.

### Rating

1. Out of scope: no. The trigger is an input flood, which is an adversary capability (section 7), not an exclusion. The
   deployment meets A3: the referee caps each epoch at the limit, so "Defects that need the deployment to violate one of
   A1 to A8" does not apply. The trigger is not a reorganization, a host fault, a snapshot, an O1/O2 case or an
   application that is not correctly designed. The player is not one of AUDIT.md's excluded items. Those are the
   validator nodes, `prt-dishonest.lua`, and the `*-test.lua` and `*-test.sh` harnesses.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player". Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical
   in the role the component stands in for, such as ... the honest operator for an implementation of an operator or a
   tool that computes claims." This clause covers crisium/prt-epoch, which is an implementation of the honest operator
   that no deployment runs. No component in another role shares the defect: the emulator and the referee are correct
   here, and the validator nodes are out of scope.
3. High and Medium cases: in the stood-in honest-operator role, no High case fits. The state is reachable, not
   "demonstrably unreachable". The data is the on-chain input record, which the honest operator "must process"
   (section 4), not data it "may decline". So the stood-in rating falls through to step 4. For the support component
   itself, the Medium case "A defect that only a support component shows, when section 3 rates it Medium" fits.
4. Critical (stood-in role): R4: "The honest operator defends every epoch whose dispute is open, including while it
   processes the inputs of later epochs. It assigns inputs to epochs exactly as the referee does, including the input
   limit per epoch (A3)." Section 8 Critical: "violating any rule or obligation at a reachable state, or anywhere on the
   honest operator's path, is critical", and "A crash ... caused by data from other parties that the honest operator
   must process." Observing the chain is on the honest operator's path. Critical in the stood-in role makes it Medium for
   the support component.

Another reading: someone could argue that a flood of more than 2^24 inputs (about 16.8 million InputBox transactions within
one dispute) is impractical. However, section 4 ("any count") and section 7 admit it, and heavy honest traffic also
reaches it. The model does not price input submission, so the class stays Medium. A reader who treated the player as
standing in for nothing would get Low ("Any other support defect is Low"). The section 3 clause about "implementations of
an operator that no deployment runs" rules that out.

### Possible solution and risks

Epoch N+1's listener must fetch from a block at or before the block of input `inputIndexLowerBound` of its range. One
option is for epoch N's listener, which already receives inputs past its limit in its own log stream, to record the block
of the first input with index at least `input_begin + 2^24` and hand it to epoch N+1. That value must be persisted in the
checkpoint so it survives a restart. Another option: when the previous seal was full (`upper - lower == 2^24`), carry
forward the previous epoch's `first_input_block` instead of the seal block.

Fetching from `first_block` (the consensus deployment block) is correct but conflicts with R12: the operator's work
"must not grow with the application's age, with the number of past epochs". The fix must also keep the restart path (O2)
working and keep the "input logged in the previous seal's block" case working.

### Risk of not fixing it

The PRT recipes and demonstration break once an application receives more than 2^24 inputs during one dispute. The player
then crash-loops forever and stops defending every later epoch. Any input sender can trigger it, given enough
transactions. Production validator nodes are out of scope, but a node modelled on these recipes would inherit a
completeness failure that lets a dishonest claim win by timeout. One mitigation outside the code is to restart the player
by hand with a `first_input_block` at or before the backlog, but the code exposes no option for that.
