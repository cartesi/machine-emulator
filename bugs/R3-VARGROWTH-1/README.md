# R3-VARGROWTH-1: the PRT forked player replays more inputs per match as the epoch's input count grows

Component: the PRT forked player in `doc/recipes/prt.lua` (support; it stands in for the honest operator). This
is the player that prt.lua's `honest` role runs when it gets no epoch directory: the role dispatch calls
`new_forked_player`. It keeps its machines at input boundaries in `new_forked_machine_cache`, which has
`DEFAULT_MACHINE_CACHE_CAPACITY = 8` entries and `DEFAULT_MACHINE_CACHE_INPUT_GAP = 1`. When the cache is full,
`machine_cache_methods:consider` doubles `input_gap`. So with `n` inputs the 8 retained boundaries end up `n/8` to
`n/4` apart.

Every per-match unit that needs a machine at input `k` goes through `new_machine_pair_at_epoch_input_offset`:
`prove_state_transition`, `collect_mcycle_bundle`, `build_uarch_cycle_computation_hash` and
`collect_uarch_cycle_bundle`. That function forks the nearest retained entry, and `run_to_epoch_input_offset`
then replays every input between that entry and `k`. The forked player has no agreed pair. The stored player
(R2-DFINPUTCOUNT-1, 32 entries) has the same root cause, but its fix covers only `STORED_MACHINE_CACHE_CAPACITY`.

vg.lua's player has the same cache policy (capacity 8, gap 1). It is a secondary site and this test does not
exercise it.

## Requirement

THREAT_MODEL.md R12: "Each is measured from a machine at its starting position. Reaching that position costs at
most the mcycles from the nearest retained input boundary, which the application's per-input usage bounds. A7
must cover that cost a bounded number of times for every match, at either level, that the tournaments force on
the honest claim."

## What the test asserts

`test.lua` uses the emulator's Lua API and the real `prt.lua` module (`require("prt")`):

1. In a temp dir it builds a tiny rolling template: bare-metal `accept.bin`, 4 MiB of RAM, stored at its
   first rx-accepted yield.
2. It opens `prt.new_forked_player(dapp_contract, "honest")` with `new_geometry(10)`. This spawns a JSON-RPC
   machine server and forks it for each cache entry.
3. It delivers N1 = 128 identical empty-payload inputs through `event_handler.input_added` + `idle`.
4. For the input just before each retained boundary, and for the last input, it calls
   `player:new_machine_pair_at_epoch_input_offset(k)`. It counts the inputs the player replays by wrapping
   `run_to_input_mcycle_offset` on the player instance.
5. It grows the same epoch to N2 = 512 inputs and seals it (`epoch_sealed(512)`).
6. It repeats the measurement with the leaf proof of a match,
   `event_handler.prove_state_transition(player, k, 0, 0)`, which is a delivery followed by a step at input `k`.
7. It requires `worst_replay(N2) <= max(worst_replay(N1), 1)`. In other words, the replay needed to reach a
   disputed input must not grow with the number of inputs in the epoch. The test measures counts, not time.

Exit codes: 1 = the replay grows with N (bug present), 0 = bounded, 2 = setup error. `N1` and `N2` can be
overridden through the environment.

## Run

```sh
bugs/run.sh R3-VARGROWTH-1        # about 6 s
```

## Expected output on audit/prt2

```
N=128 inputs: 8 retained boundaries {0,19,39,55,79,95,111,127} (input_gap 16); worst replay 23 inputs (k=78)
N=512 inputs: 8 retained boundaries {0,79,159,223,319,383,447,511} (input_gap 64); worst replay 95 inputs (k=318)
VIOLATED: R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's input count (per-match cost bounded by the application's per-input usage); the forked player replayed 23 inputs at 128 inputs and 95 at 512 inputs
run.sh: R3-VARGROWTH-1: exit 1 (bug present)
```

The worst replay is about n/5.4, which is 4x the replay for 4x the inputs.

Control (not tracked): the same test, run against an out-of-tree copy of `prt.lua` with
`DEFAULT_MACHINE_CACHE_CAPACITY = 1 << 20`, keeps every boundary. It reports 0 replayed inputs at both sizes and
exits 0.

Note for the reviewer: the manual describes vg.lua's cache, which PRT reuses, as bounded by design ("It uses
bounded memory"). Whether R12's "nearest retained input boundary" allows an operator to retain this few
boundaries is a reading question for the rating. The test only shows that the replay count grows with `n`.
