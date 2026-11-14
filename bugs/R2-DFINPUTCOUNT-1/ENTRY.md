## R2-DFINPUTCOUNT-1

**Title.** The PRT stored player keeps only 32 input boundaries per epoch, so every per-match unit replays a number of inputs that grows linearly with the epoch's input count (up to about n/16).

**Severity.** Medium

### Problem

The stored player in `doc/recipes/prt.lua` (the one the bridge and `crisium.lua` run) retains machines at input
boundaries in a cache of `STORED_MACHINE_CACHE_CAPACITY = 32` entries. When the cache is full,
`machine_cache_methods:consider` evicts an entry closer than `input_gap` to its predecessor, and if there is none it
doubles `input_gap`. Entry zero is always kept. So with `n` inputs in the epoch the retained boundaries end up
`input_gap/2` to `input_gap` apart, with `input_gap` about `n/16`.

Every unit of work the player does for a match starts from a machine at an exact input boundary, which it gets from
`new_machine_pair_at_epoch_input_offset`. That covers the leaf proof (`event_handler.prove_state_transition`), opening
an mcycle bundle during a bisection (`collect_mcycle_bundle`), building a uarch claim
(`build_uarch_cycle_computation_hash`) and opening a uarch bundle (`collect_uarch_cycle_bundle`). The function forks
the nearest retained entry not past the target (`find_nearest_entry`), and `run_to_epoch_input_offset` then replays
every input between that entry and the target: delivery, a run to the fixed point (up to the mcycle limit per input),
and a stored-pair commit for each. The worst replay is therefore about `n/16` complete inputs per unit. At the
pinned input limit of 2^24 inputs per epoch that is about 2^20 inputs, each of which may legitimately use up to the
application's per-input mcycle budget.

The stored player's agreed pair (`advance_agreed_pair`) does not remove this cost. It walks a machine forward one
input per idle step from the start of the cache gap that holds the dispute interval, so the same replay is done in
idle time while the match's clock runs. It serves only the current bisection and is dropped when a match lies
elsewhere. The per-match replay distance is unchanged.

The code's own comment states the intent that this violates: "The stored player, which the bridge runs, keeps more
input boundaries, so reaching a disputed input replays only a few inputs." (`prt.lua:899-901`).

In the role the player stands in for, this breaks R12. The cost of reaching the position of a per-match operation is
no longer bounded by the application's per-input usage, but by `n/16` times it. An adversary that sends many inputs
and steers each of the logarithmic number of matches to a position just before a retained boundary multiplies the
honest operator's per-match work by a factor that grows with the input count. If the deployment sized the clocks for
the R12 bound (A7), the honest claim can then run out of time. That is a completeness failure (section 1: the honest
operator "cannot respond in time. If the honest claim is eliminated, a dishonest claim can win").

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, stored player). AUDIT.md component table: "The PRT player and bridge in
`doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs
the player, the bridge or the CLI." It stands in for the honest operator. Area: the machine cache of input
boundaries and the replay that every per-match unit starts with.

### Location

- `doc/recipes/prt.lua:901`: `local STORED_MACHINE_CACHE_CAPACITY = 32` (used by the stored cache at ~1336).
- `doc/recipes/prt.lua:1217-1245`: `machine_cache_methods:consider` (eviction and `input_gap` doubling).
- `doc/recipes/prt.lua:1247-1258`: `find_nearest_entry`.
- `doc/recipes/prt.lua:2055-2060`: `player_meta.__index:new_machine_pair_at_epoch_input_offset`, and the stored
  override at `3040-3052` (agreed-pair shortcut).
- `doc/recipes/prt.lua:2150-2172`: `run_to_epoch_input_offset` (the replay loop).
- Callers: `event_handler.prove_state_transition` (1956-1977), `collect_mcycle_bundle` (2296),
  `build_uarch_cycle_computation_hash` (2315), `collect_uarch_cycle_bundle` (2334).
- `doc/recipes/prt.lua:2984-3018`: `advance_agreed_pair` (walks one input per idle step inside one cache gap).

The manual (`doc/README.md`, verification-game section on the machine cache) documents the bounded cache for
`vg.lua` ("maintains at most a fixed number of machines spread throughout the epoch ... It uses bounded memory") and
says the PRT player offers each completed input boundary "to the same machine cache the verification game uses". It
does not state a bound on the replay; it does not list the sparse cache as an accepted cost of the honest operator.

### Evidence and test

`bugs/R2-DFINPUTCOUNT-1/` contains `test.lua` and `README.md`. The test uses the emulator's Lua API and the real
`prt.lua` module (`require("prt")`), with no chain. It:

1. builds in a temporary directory a small rolling template: the harness bare-metal guest `accept.bin` (accepts every
   request with the empty outputs root), 4 MiB of RAM, stored at its first rx-accepted manual yield;
2. opens `prt.new_stored_player` on it (geometry `prt.new_geometry(10)`);
3. delivers N1 = 128 empty-payload inputs through `stored_event_handler.input_added` and `idle`;
4. for the input just before each retained boundary (and the last input) calls
   `player:new_machine_pair_at_epoch_input_offset(k)` and counts the completed inputs replayed, by wrapping
   `run_to_input_mcycle_offset` on the player instance;
5. grows the epoch to N2 = 512 inputs, seals it with `epoch_sealed(512)`, and repeats the measurement with the leaf
   proof of a match, `stored_event_handler.prove_state_transition(player, k, 0, 0)` (delivery and step at input `k`;
   that path does not call `run_to_input_mcycle_offset` itself, so every counted call is a replayed input);
6. requires `worst_replay(N2) <= max(worst_replay(N1), 1)`: the replay to reach a disputed input must not grow with
   the epoch's input count. It measures counts, not time.

Run: `bugs/run.sh R2-DFINPUTCOUNT-1` (about 50-70 s). On audit/prt2 it prints, identically on every run:

```
N=128 inputs: 32 retained boundaries (input_gap 4); worst replay 5 inputs (k=66)
N=512 inputs: 32 retained boundaries (input_gap 16); worst replay 23 inputs (k=270)
VIOLATED: R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's input count (per-match cost bounded by the application's per-input usage); observed 5 at 128 inputs and 23 at 512 inputs
run.sh: R2-DFINPUTCOUNT-1: exit 1 (bug present)
```

The reviewer re-ran it twice (exit 1 both times, same output) and ran a control: the same unmodified test against an
out-of-tree copy of `prt.lua` whose only change is `STORED_MACHINE_CACHE_CAPACITY = 1 << 20` (every boundary
retained). The control reports 0 replayed inputs at both sizes and exits 0, so the test fails for the cache policy and
passes once the replay is bounded. Found by the DFINPUTCOUNT hunter, proved and reviewed on Opus 5.5; no fallback.

### Trigger and reachability

Any input sender triggers it by sending inputs: the replay grows with the number of inputs in the disputed epoch,
whatever their payloads (the test uses empty payloads on an application that accepts everything, a correctly
designed application). Section 7 lets the adversary "Send any number of inputs the deployment accepts" and "Steer the
dispute to any position of the honest computation, and force the honest claim through a logarithmic number of
matches", so it can choose a disputed input just before a retained boundary in each match. No unreachable state is
involved: the state is an ordinary epoch of a valid template with many inputs.

### Rating

1. Out of scope: no. The trigger is the number of inputs and the dispute position, both adversary capabilities of
   section 7. The exclusion "An application that tries to exhaust the honest operator through the number of its
   outputs or yields" covers outputs and yields, not inputs. "Average-case performance that does not change the
   worst-case cost of any operation listed in R12" does not apply, because the worst-case cost of reaching a disputed
   position grows. No obligation A1 to A8 has to be violated, and the application is correctly designed.
2. Role: the component is the PRT stored player, Support by the AUDIT.md table ("The PRT player and bridge in
   `doc/recipes` ... | Support"). Section 3: "A defect that only a support component shows is Medium when it would
   rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The player is an implementation of an operator, so it is rated as the honest
   operator would be and capped at Medium.
3. High and Medium cases, in the honest-operator role: the High case "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor"
   does not fit: the trigger is the input count, not the guest or host load, and the factor grows with `n`. The
   Critical list's "An operation listed in R12 whose worst-case cost a guest can make unbounded ..." is guest-driven
   and does not fit either. Section 8 Medium, "A defect that only a support component shows, when section 3 rates it
   Medium", is the case that applies to the component itself.
4. Critical, in the honest-operator role: R12, "Each is measured from a machine at its starting position. Reaching
   that position costs at most the mcycles from the nearest retained input boundary, which the application's
   per-input usage bounds. A7 must cover that cost a bounded number of times for every match, at either level, that
   the tournaments force on the honest claim." Here reaching the position costs up to about `n/16` inputs' worth of
   mcycles, which the per-input usage does not bound. Section 8: "violating any rule or obligation at a reachable
   state, or anywhere on the honest operator's path, is critical." Critical for an honest operator, so Medium for the
   support player.

Second reading. R12 says "the nearest retained input boundary" without saying which boundaries an operator must
retain. If that phrase is read as leaving retention to the operator, with the deployment sizing its clocks for
whatever gap the operator keeps, then the sparse cache is a sizing matter and not a rule violation: Low (no rule
violated). If instead the growth is read as the High constant-factor case (the factor is bounded by the input limit,
up to about 2^20), the honest-operator rating is High, and the support rating is still Medium. The preferred reading
is the first one above: the relative clause "which the application's per-input usage bounds" makes the distance to
the nearest retained boundary bounded by one input's usage, and R12's last paragraph lets the operator's storage
grow with the inputs of open epochs, so retaining every boundary is what the model expects. What would decide is
whether the maintainers intend "retained input boundary" to mean every input boundary of an open epoch.

### Possible solution and risks

Retain every input boundary of an open or disputed epoch in the stored player (stored machines are reflink clones in
the recipes' setup, and R12 allows storage that grows with the inputs of open epochs), or at least cap `input_gap` at
a constant and let the cache grow with `n`. Risks: disk use grows with the input count (a stored Linux machine is
hundreds of MB without reflinks, so the recipes' reflink mount becomes a requirement), the stored state file that
lists the entries grows, and `remove_evicted`/reopen logic must still clean up after a stop (O2). The default fork-based
cache of `vg.lua` can keep its bounded design since it is a demonstration; the manual's statement about the PRT
player sharing that cache should then be updated.

### Risk of not fixing it

The player is support, so no production deployment is exposed directly. But it is the reference that shows how to
defend a claim, and it understates the cost of doing so: a node that copies its cache policy would let any input
sender, by filling an epoch with inputs, make each match's replay grow linearly with the epoch's input count, up to
about 2^20 inputs per unit at the pinned limit, and lose by timeout under clocks sized for R12. Mitigation outside the
code: run it only on epochs with few inputs, or size the clocks for the replay of `n/16` inputs per unit.
