## R3-VARGROWTH-1

**Title.** The PRT forked player (prt.lua `honest` role run without an epoch directory) keeps only 8 input boundaries per epoch, so every per-match unit replays a number of inputs that grows linearly with the epoch's input count (about n/5).

**Severity.** Medium

### Problem

The forked player in `doc/recipes/prt.lua` is the player that prt.lua's `honest` role runs when it gets no epoch
directory. It is also the mode the manual's PRT walk-through runs (`lua5.4 prt.lua honest 127.0.0.1:8094 "0x..."`,
`doc/README.md` around line 11093). It keeps machines at input boundaries in a cache from `new_forked_machine_cache`.
That cache has `DEFAULT_MACHINE_CACHE_CAPACITY = 8` entries and starts with `DEFAULT_MACHINE_CACHE_INPUT_GAP = 1`.
When the cache is full, `machine_cache_methods:consider` evicts an entry that is closer than `input_gap` to its
predecessor. If it finds none, it doubles `input_gap`. Entry zero is always kept. So with `n` inputs in the epoch, the 8
retained boundaries end up about `n/8` to `n/4` apart.

Every unit of work the player does for a match starts from a machine at an exact input boundary. It gets that machine
from `new_machine_pair_at_epoch_input_offset`. The units are:

- the leaf proof, `event_handler.prove_state_transition`;
- opening an mcycle bundle during a bisection, `collect_mcycle_bundle`;
- building a uarch claim, `build_uarch_cycle_computation_hash`;
- opening a uarch bundle, `collect_uarch_cycle_bundle`.

`new_machine_pair_at_epoch_input_offset` forks the nearest retained entry that is not past the target
(`find_nearest_entry`). `run_to_epoch_input_offset` then replays every input between that entry and the target. Each
replayed input is delivered and run to its fixed point, which can take up to the mcycle limit per input. The forked
player has no agreed pair or other shortcut. The worst replay is therefore about `n/5` complete inputs per unit.

In the role the player stands in for, this breaks R12. The cost of reaching the position of a per-match operation is
no longer bounded by the application's per-input usage. It is bounded by about `n/5` times that usage. An adversary can
send many inputs and steer each of the logarithmic number of matches to a position just before a retained boundary.
That multiplies the honest operator's per-match work by a factor that grows with the input count. If the deployment
sized its clocks for the R12 bound (A7), the honest claim can run out of time. That is a completeness failure.
Section 1 says the honest operator "cannot respond in time. If the honest claim is eliminated, a dishonest claim can
win".

This has the same root cause as R2-DFINPUTCOUNT-1: a fixed cache capacity plus doubling of `input_gap` in the shared
`consider`. The site and constant differ. R2-DFINPUTCOUNT-1 covers the stored player and
`STORED_MACHINE_CACHE_CAPACITY = 32`, and the fix BUGS.md gives for it changes only the stored player. The forked
player's constant `DEFAULT_MACHINE_CACHE_CAPACITY = 8` makes the replay about three times longer, and a fix to the
stored cache leaves it in place. `vg.lua`'s player has the same policy (`DEFAULT_MACHINE_CACHE_CAPACITY = 8`,
`vg.lua:27`, `new_machine_cache` at 237-295). That is a secondary site, which this test does not exercise.

### Component, role and area

The component is the PRT player in `doc/recipes` (`prt.lua`), in forked mode. The AUDIT.md component table says: "The
PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No
production deployment runs the player, the bridge or the CLI." The player stands in for the honest operator. The area
is the forked machine cache of input boundaries and the replay that every per-match unit starts with.

### Location

- `doc/recipes/prt.lua:897-898`: `DEFAULT_MACHINE_CACHE_CAPACITY = 8`, `DEFAULT_MACHINE_CACHE_INPUT_GAP = 1`.
  Lines 899-901 hold the comment "The stored player, which the bridge runs, keeps more input boundaries, so reaching a
  disputed input replays only a few inputs."
- `doc/recipes/prt.lua:1177-1190`: `new_forked_machine_cache`.
- `doc/recipes/prt.lua:1217-1245`: `machine_cache_methods:consider`, which evicts entries and doubles `input_gap`.
- `doc/recipes/prt.lua:1247-1265`: `find_nearest_entry` and `nearest_not_past_epoch_input_offset`.
- `doc/recipes/prt.lua:2055-2060`: `player_meta.__index:new_machine_pair_at_epoch_input_offset`.
- `doc/recipes/prt.lua:2150-2172`: `run_to_epoch_input_offset`, the replay loop.
- Callers: `event_handler.prove_state_transition` (1956-1977), `collect_mcycle_bundle` (2296-2297),
  `build_uarch_cycle_computation_hash` (2315-2316) and `collect_uarch_cycle_bundle` (2334-2335).
- `doc/recipes/prt.lua:3185-3193`: `new_forked_player`.
- `doc/recipes/prt.lua:3315-3321`: role dispatch. `honest` without an epoch directory calls `new_forked_player`.
- The manual (`doc/README.md`, "The player" under PRT) says the PRT player "offers each completed input boundary to
  the same machine cache the verification game uses". It describes that cache as one that "maintains at most a fixed
  number of machines spread throughout the epoch" and says "It uses bounded memory". It states no bound on the replay.
- Secondary site, not exercised by the test: `doc/recipes/vg.lua:27-28` and `237-295`.

### Evidence and test

`bugs/R3-VARGROWTH-1/` contains `test.lua` and `README.md`. The test uses the emulator's Lua API and the real `prt.lua`
module (`require("prt")`). It needs no chain. It does the following:

1. It builds a small rolling template in a temporary directory: the harness bare-metal guest `accept.bin`, which
   accepts every request with the empty outputs root, with 4 MiB of RAM, stored at its first rx-accepted manual yield.
2. It opens `prt.new_forked_player(dapp_contract, "honest")` with `prt.new_geometry(10)`. This is the constructor that
   the `honest` role uses without an epoch directory. It spawns a JSON-RPC machine server and forks it for each cache
   entry.
3. It delivers N1 = 128 empty-payload inputs through `event_handler.input_added` and `idle`.
4. It calls `player:new_machine_pair_at_epoch_input_offset(k)` for the input just before each retained boundary and for
   the last input. It counts the completed inputs replayed by wrapping `run_to_input_mcycle_offset` on the player
   instance.
5. It grows the epoch to N2 = 512 inputs and seals it with `epoch_sealed(512)`.
6. It repeats the measurement with the leaf proof of a match, `event_handler.prove_state_transition(player, k, 0, 0)`.
   That is a delivery and a step at input `k`. That path does not call `run_to_input_mcycle_offset` for the target
   input, so every counted call is a replayed input.
7. It requires `worst_replay(N2) <= max(worst_replay(N1), 1)`: the replay to reach a disputed input must not grow with
   the epoch's input count. It measures counts, not time.

Run it with `bugs/run.sh R3-VARGROWTH-1`. It takes about 6 s. On audit/prt2 it prints the following, identically on
every run (the prover ran it 3 times and the reviewer 2 times, exit 1 each time):

```
N=128 inputs: 8 retained boundaries {0,19,39,55,79,95,111,127} (input_gap 16); worst replay 23 inputs (k=78)
N=512 inputs: 8 retained boundaries {0,79,159,223,319,383,447,511} (input_gap 64); worst replay 95 inputs (k=318)
VIOLATED: R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's input count (per-match cost bounded by the application's per-input usage); the forked player replayed 23 inputs at 128 inputs and 95 at 512 inputs
run.sh: R3-VARGROWTH-1: exit 1 (bug present)
```

Control, run by the reviewer: the same unmodified test against an out-of-tree copy of `prt.lua` whose only change is
`DEFAULT_MACHINE_CACHE_CAPACITY = 1 << 20`, so every boundary is retained. It reports 129 and 513 retained boundaries,
0 replayed inputs at both sizes, and exits 0. So the test fails because of the cache policy, and it passes once the
replay is bounded. A fix that caps `input_gap` at a constant `c` would give a worst replay of `c - 1` at both sizes, so
it would also pass.

Hunter: VARGROWTH. Prover and reviewer: Opus 5.5. No fallback was used.

### Trigger and reachability

Any input sender triggers it by sending inputs. The replay grows with the number of inputs in the disputed epoch,
whatever their payloads. The test uses empty payloads on an application that accepts everything, which is a correctly
designed application. Section 7 lets the adversary "Send any number of inputs the deployment accepts" and "Steer the
dispute to any position of the honest computation, and force the honest claim through a logarithmic number of
matches". So in each match it can choose a disputed input just before a retained boundary. No unreachable state is
involved: the state is an ordinary epoch of a valid template with many inputs.

### Rating

1. Out of scope: no. The trigger is the number of inputs and the dispute position, and both are adversary capabilities
   in section 7. The exclusion "An application that tries to exhaust the honest operator through the number of its
   outputs or yields" covers outputs and yields, not inputs. "Average-case performance that does not change the
   worst-case cost of any operation listed in R12" does not apply, because the worst-case cost of reaching a disputed
   position grows. No obligation A1 to A8 has to be violated, and the application is correctly designed.
2. Role: the component is the PRT forked player. It is Support by the AUDIT.md table ("The PRT player and bridge in
   `doc/recipes` ... | Support"). Section 3 says: "Examples are ... implementations of an operator that no deployment
   runs ... A defect that only a support component shows is Medium when it would rate High or Critical in the role the
   component stands in for, such as ... the honest operator for an implementation of an operator". The forked player
   implements the honest operator, since it is the `honest` role. It is rated as the honest operator would be, capped
   at Medium. The clause covers this component. Being the demonstration mode does not change the role: the clause
   exists for operator implementations that no deployment runs.
3. High and Medium cases, in the honest-operator role: the High case "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor" does
   not fit. The trigger is the input count, not the guest or host load, and the factor grows with `n`. For the
   component itself, the section 8 Medium case "A defect that only a support component shows, when section 3 rates it
   Medium" applies.
4. Critical, in the honest-operator role: R12 says "Each is measured from a machine at its starting position. Reaching
   that position costs at most the mcycles from the nearest retained input boundary, which the application's per-input
   usage bounds. A7 must cover that cost a bounded number of times for every match, at either level, that the
   tournaments force on the honest claim." Here, reaching the position costs up to about `n/5` inputs' worth of
   mcycles, which the per-input usage does not bound. Section 8: "violating any rule or obligation at a reachable
   state, or anywhere on the honest operator's path, is critical." That is Critical for an honest operator, so the
   support player is Medium.

Second reading. R12 says "the nearest retained input boundary" without saying which boundaries an operator must keep.
The manual also documents the bounded cache, and the code comment at 899-901 says only the stored player aims for a
short replay. If "retained" leaves the choice to the operator, with the deployment sizing its clocks for whatever gap
the operator keeps, then the sparse cache is a sizing matter, not a rule violation, and the rating is Low. The first
reading is preferred, and it is the reading under which this campaign confirmed R2-DFINPUTCOUNT-1. Two facts support
it. The relative clause "which the application's per-input usage bounds" limits the distance to the nearest retained
boundary to one input's usage. And R12's last paragraph lets the operator's records grow with the inputs of open
epochs. The deciding fact is whether the maintainers mean "retained input boundary" to be every input boundary of an
open epoch, or at most a constant number of inputs apart. If they accept the forked player and `vg.lua` as bounded-memory
demonstrations whose replay R12 does not govern, the rating is Low.

### Possible solution and risks

Make the replay to a disputed input independent of `n` in the forked player. One way is to cap `input_gap` at a small
constant in `machine_cache_methods:consider` and let the cache grow with the inputs of the open epoch. That would also
cover the stored player, as R2-DFINPUTCOUNT-1 needs. Another way is to give the forked player the stored player's
capacity policy when it is meant to defend a claim. If the bounded cache is kept on purpose for the demonstration, the
manual and the code comment should say that the forked player's per-match replay grows with the input count and that
it is not a model of an honest operator's cost.

Risks: each forked entry is a separate machine server process with copy-on-write memory, so one entry per few inputs
means process count and memory that grow with the input count. At the pinned 2^24 inputs per epoch that is not
feasible with forks. The forked mode may then have to switch to stored entries, which need reflinks, or document its
limit. Changing the shared `consider` also changes the stored cache's eviction pattern and the cache file it persists,
which the stored player reloads after a restart (O2).

### Risk of not fixing it

The player is support, so no production deployment is exposed directly. But the forked player is what the manual runs
to show how an honest player defends a claim, and its cache understates the cost of doing so. A node that copies its
cache policy would let any input sender, by filling an epoch with inputs, make each match's replay grow linearly with
the epoch's input count, up to about 2^24/5 inputs per unit at the pinned limit. Under clocks sized for R12, it would
then lose by timeout. Mitigation outside the code: run the forked player only on epochs with few inputs, or use the
stored player once R2-DFINPUTCOUNT-1 is fixed.
