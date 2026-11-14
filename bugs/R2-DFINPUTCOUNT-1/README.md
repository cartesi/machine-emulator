# R2-DFINPUTCOUNT-1: the PRT stored player replays more inputs per match as the epoch's input count grows

Component: the PRT stored player in `doc/recipes/prt.lua` (support; it stands in for the honest operator). It
keeps at most `STORED_MACHINE_CACHE_CAPACITY = 32` machines at input boundaries per epoch. When the cache is
full, `machine_cache_methods:consider` doubles `input_gap`. Every per-match unit that needs a machine at
input `k` gets one through `new_machine_pair_at_epoch_input_offset`. That covers `prove_state_transition`,
`collect_mcycle_bundle`, `build_uarch_cycle_computation_hash` and `collect_uarch_cycle_bundle`. The function
forks the nearest retained entry (`find_nearest_entry`), and `run_to_epoch_input_offset` then replays every
input between that entry and `k`. With `n` inputs the entries end up `n/32` to `n/16` apart, so the worst
replay grows linearly with `n`.

## Requirement

THREAT_MODEL.md R12: "Each is measured from a machine at its starting position. Reaching that position costs at
most the mcycles from the nearest retained input boundary, which the application's per-input usage bounds. A7
must cover that cost a bounded number of times for every match". R12 also says: "The honest operator's own work
outside the emulator ... has a bounded cost per input, per yield, and per match".

## What the test asserts

`test.lua` uses the emulator's Lua API and the real `prt.lua` module, loaded with `require("prt")`:

1. In a temp dir it builds a tiny rolling template: bare-metal `accept.bin`, 4 MiB of RAM, stored at its
   first rx-accepted yield.
2. It opens `prt.new_stored_player` on that template.
3. It delivers N1 = 128 identical empty-payload inputs through `stored_event_handler.input_added` + `idle`.
4. For the input just before each retained boundary, it calls
   `player:new_machine_pair_at_epoch_input_offset(k)` and counts the completed inputs the player replays. It
   counts them by wrapping `run_to_input_mcycle_offset` on the player instance.
5. It grows the same epoch to N2 = 512 inputs and seals it with `epoch_sealed(512)`.
6. It repeats the measurement with the leaf proof of a match,
   `stored_event_handler.prove_state_transition(player, k, 0, 0)` (delivery + step at input `k`).
7. It requires `worst_replay(N2) <= max(worst_replay(N1), 1)`. In other words, the replay needed to reach a
   disputed input must not grow with the number of inputs in the epoch. The test measures counts, not time.

There is no bisection in the test, so the stored player's single "agreed pair" is never set up. That pair only
moves the same replay into idle time, one input per idle step. It serves only the latest bisection and is
dropped when another match lies elsewhere. It does not change the per-match replay count.

Exit codes: 1 = the replay grows with N (bug present), 0 = bounded, 2 = setup error. `N1`/`N2` can be overridden
through the environment.

## Run

```sh
bugs/run.sh R2-DFINPUTCOUNT-1        # about 50 s
```

## Expected output on audit/prt2

```
N=128 inputs: 32 retained boundaries (input_gap 4); worst replay 5 inputs (k=66)
N=512 inputs: 32 retained boundaries (input_gap 16); worst replay 23 inputs (k=270)
VIOLATED: R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's input count (per-match cost bounded by the application's per-input usage); observed 5 at 128 inputs and 23 at 512 inputs
run.sh: R2-DFINPUTCOUNT-1: exit 1 (bug present)
```

Control, not tracked: the same test run against an out-of-tree copy of `prt.lua` with
`STORED_MACHINE_CACHE_CAPACITY = 1 << 20` keeps every boundary. It reports 0 and 0 replayed inputs and exits 0.
