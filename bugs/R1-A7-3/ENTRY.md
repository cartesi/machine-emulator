## R1-A7-3

**Title.** The stored PRT player runs a later epoch's whole input in one idle step, so crisium cannot see or answer the sealed epoch's dispute until that input finishes (up to 2^48 mcycles).

**Severity.** Medium

### Problem

`crisium.lua` reads the chain tip only between steps. When the tip has not changed, it calls `idle()`, and that call
runs `player.event_handler.idle` once for every listener. For a stored player with a pending input,
`stored_event_handler.idle` calls `event_handler.idle`, which calls `run_next_input`. That function calls
`run_to_input_mcycle_offset(..., MAX_MCYCLES_PER_ADVANCE_STATE)` and runs the input to its fixed point in one call, with
no way to stop partway. Only after it returns does the loop read the tip again, run `pass()`, and tick the sealed
epoch's dispute bridge.

So one input of the open epoch e+1 delays every observation of, and every answer in, the dispute of the sealed epoch
e. The delay is as long as that input runs, and the per-input limit allows up to 2^48 mcycles. The recipe's own comment
at `stored_event_handler` claims the opposite: "A stored player only records its inputs and runs them in idle time, so
an open epoch never delays a response in a sealed epoch's dispute." The agreed-pair path has the same structure.
`stored_event_handler.idle` calls `advance_agreed_pair`, which runs `run_to_epoch_input_offset` over one whole input per
step. The test does not exercise that path.

The deployed clock model (`ClockBudgets.sol` in the pinned Dave release) charges each honest response one inclusion
time, plus a censorship budget for the whole commitment. A level-0 match has a tree height of 54, so the honest claim
can be on turn up to 54 times in each match, across a logarithmic number of matches. If every one of those turns waits
for a full later-epoch input, the delay comes out of the honest claim's allowance. Once the per-input run time is
large compared with that allowance divided by the number of turns, the honest claim loses by timeout. Then a dishonest
claim can win, which is the completeness failure of section 1. This is the scenario that R4 rules out: "The honest
operator defends every epoch whose dispute is open, including while it processes the inputs of later epochs."

### Component, role and area

The PRT player (`doc/recipes/prt.lua`, the stored player's idle scheduling) and the crisium main loop
(`doc/recipes/crisium.lua`). Role, from the AUDIT.md table: "The PRT player and bridge in `doc/recipes` ... | Support.
No production deployment runs the player, the bridge or the CLI." The component stands in for the honest operator. The
area is the scheduling of later-epoch work against the defense of a sealed epoch.

### Location

- `doc/recipes/crisium.lua`: the main loop (`while true do ... elseif not idle() then`, around lines 361-382) and
  `idle()` (around lines 336-343).
- `doc/recipes/prt.lua`:
  - `stored_event_handler` and its comment (around lines 2180-2186).
  - `event_handler.idle` (around line 2189).
  - `player_meta.__index:run_next_input` (around line 2243), which calls `run_to_input_mcycle_offset` with
    `MAX_MCYCLES_PER_ADVANCE_STATE`.
  - `player_meta.__index:run_to_input_mcycle_offset` (around line 2066).
  - `stored_player_methods:advance_agreed_pair` (around line 2984), through `run_to_epoch_input_offset`.
  - `stored_event_handler.idle` (around line 3021).

### Evidence and test

`bugs/R1-A7-3/` contains these files.

- `test.lua`: the test.
- `guest.c`: a correctly designed bare-metal rollup guest. It reads a little-endian iteration count from the first 8
  bytes of the rx buffer, spins that many times at 2 instructions per iteration, and accepts with the empty outputs
  root.
- `guest.bin`: the built guest.
- `build-guest.sh`: rebuilds `guest.bin` with the harness bare-metal builder.
- `README.md`: notes on the test.

The test builds a template from the guest at its first accepted manual yield. It opens two stored players with the
recipe unchanged: epoch 0 is sealed (`epoch_sealed`) and epoch 1 is open. It adds one input to epoch 1 through
`input_added`, which only records it. Then it runs exactly one crisium `idle()` step, newest listener first, as
`crisium.lua` does, and reads the epoch machine's `mcycle` before and after.

- The control is a 2^19-iteration input (at least 2^20 mcycles).
- The assertion uses a 2^26-iteration input (at least 2^27 mcycles). One idle step must not run it whole: the machine
  must advance fewer mcycles than the input needs, and the input must still be pending or partly done.

Run it with `bugs/run.sh R1-A7-3`. During this review the root volume was full, so the test was run with
`TMPDIR=/dev/shm/...`. The test puts its temporary files under `$TMPDIR` and removes them. On `audit/prt2` it exits 1
on every run (two runs by the reviewer, three by the prover) and prints:

```
short input (needs >= 1048576 mcycles): one idle step advanced 1048797 mcycles in 0.11 s CPU, ran it whole: true
long input (needs >= 134217728 mcycles): one idle step advanced 134217948 mcycles in 2.93 s CPU, ran it whole: true
per-step work ratio long/short: 128.0 (input length ratio 128); at the same rate, one step of an input at the 2^48-mcycle limit would take about 71 days
VIOLATED: R4: the honest operator observes the chain within the dispute clocks while it processes later epochs' inputs; one idle step (between two tip observations of crisium.lua) must not run a later epoch's whole input of 134217728 mcycles (advanced 134217948)
run.sh: R1-A7-3: exit 1 (bug present)
```

The verdict depends only on mcycle counts, which are deterministic. The CPU times and the day estimate vary from run
to run. The test is a proxy for R4. A 3-second input does not break any clock by itself. What the test shows is that
the work of one step grows linearly with the input's length (ratio 128 for a length ratio of 128), so nothing bounds
the step. A fix whose slice is at least 2^27 mcycles would still fail this test. A fix with a smaller time or mcycle
slice passes it. All agents ran on claude-opus-5-5, with no fallback model.

### Trigger and reachability

Two parties combine to trigger it.

1. An input sender adds to the open epoch e+1 an input that a correctly designed application processes for a long
   time, within its own per-input bound.
2. While that input runs, the adversary puts the honest claim on turn in the dispute of the sealed epoch e. It can do
   this by posting claims and moves, timed for when the input starts.

Both are adversary capabilities in section 7: "Send any number of inputs the deployment accepts, with payloads chosen
to maximize the honest operator's cost (R12)", "Steer the dispute to any position of the honest computation, and force
the honest claim through a logarithmic number of matches", and "Race and reorder transactions within the chain's
rules". The state is reachable: the test reaches it from a valid template, using only input delivery and the recipe as
written. Whether a timeout follows depends on how long each input runs compared with the clock allowance, as set out
under Rating.

### Rating

1. Out of scope: no. The trigger is an input sequence and dispute moves, not a machine API call by an untrusted party,
   a snapshot that was not written by the emulator, a reload outside O2, or a host fault. "An application that is not
   correctly designed" does not apply, because the guest bounds its mcycles per input and accepts. "Average-case
   performance that does not change the worst-case cost of any operation listed in R12" does not apply either. The
   defect is the worst-case latency of the honest response, which grows with the input's length. "Defects that need
   the deployment to violate one of A1 to A8" does not apply: a deployment that meets A7 would budget the honest
   operator's costs, not one input run of scheduling delay for every turn.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player, the bridge or the CLI." Section 3: "A defect that only a support component shows is Medium when it would
   rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". This clause covers the player and the crisium loop, which implement an operator. No
   honest-operator component in the AUDIT.md table (interpreter, hash tree, log producers, input delivery, storing and
   loading) shows the defect. It lies in the player's scheduling.
3. High and Medium cases: section 8 lists "A defect that only a support component shows, when section 3 rates it
   Medium." Section 3 rates it Medium if it would be High or Critical in the honest-operator role, so step 4 decides
   that.
4. In the honest-operator role, R4 is violated at a reachable state: "The honest operator observes the chain and
   submits its transactions within the dispute clocks." and "The honest operator defends every epoch whose dispute is
   open, including while it processes the inputs of later epochs." A component in that role that does not observe the
   chain for as long as one later input runs can miss the dispute clocks. That would be Critical, so the support rating
   is Medium.

There are two readings.

- Reading A, preferred: R4's clause on later epochs is a requirement on the operator's implementation. A defense that
  stalls for one later-epoch input on every turn violates it, so the stood-in rating is Critical, and the support
  rating is Medium.
- Reading B: A7 says the clocks "leave room for the honest claim to play the logarithmic number of matches ... while
  the honest operator also processes the inputs of later epochs." The extra delay is then a bounded constant factor:
  at most one input run per turn, with at most 54 turns per match at level 0. In the honest-operator role that would
  be the High case "multiply the worst-case cost ... by a constant factor". That still rates Medium for a support
  component.

Only a reading under which response latency is entirely the deployment's sizing problem, and not a defect of the
operator, would make this Low. The facts that decide are the following.

- The per-input run time that a deployment is sized for. The pinned constants size an inner commitment at
  `COMMITMENT_BUDGET = 120 minutes`.
- How that run time compares with the honest allowance divided by the number of turns. The allowance is censorship
  plus inclusions and refills in `ClockBudgets.maxAllowance`.
- Whether A7 must budget an implementation's scheduling latency. The clock model budgets one inclusion per response.

### Possible solution and risks

Make idle work preemptible.

1. Run a pending input (and an agreed-pair replay) in bounded slices, for example up to an mcycle target that is a
   multiple of the sampling period or a time budget, through the existing `run_to_stop` with an intermediate
   `mcycle_end`. Keep the epoch builder and the pair's revert snapshot across slices.
2. Return to the crisium loop after each slice, so that it reads the tip between slices.
3. Alternatively, run later-epoch work in a separate process from the dispute bridge.

The risks are these. Slicing an input splits `run_to_input_mcycle_offset` across calls. The computation-hash builder,
the pending outputs, the rejection revert, `pair:commit()`, and the restart state that O2 guarantees then have to stay
consistent at every slice boundary. A crash between slices must resume from the last committed input boundary, not
from a half-run input. `check_backlog` and `input_count` bookkeeping need the same care.

### Risk of not fixing it

The player is not run in production, so no deployed node is exposed. Anyone who uses the recipe or the crisium loop as
an operator, or as the model for one, inherits the latency. In that setting, an input sender plus a claimant can time a
long, legitimately bounded input to delay every honest response in the sealed epoch's dispute. When each input runs
long enough compared with the clock allowance, that can eliminate the honest claim by timeout. The recipe's comment
asserts the opposite, which hides the issue. Outside the code, a deployment can limit how long the application runs
each input, or run the dispute of each sealed epoch in its own process.
