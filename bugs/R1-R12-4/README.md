# R1-R12-4: bundle collectors pay per repeated fixed-point hash

**Asserted.** `collect_uarch_cycle_bundle` and `collect_mcycle_bundle` should cost a bounded amount per run
of repeated fixed-point hashes, not one unit per position. The test measures the peak-RSS growth (VmHWM) of
one call in its own child process (`measure.lua`), using the harness's bare-metal `halt` guest. It compares
that growth with a control that does the same work without the repeated tail:

| pair | control | bundle |
|---|---|---|
| uarch | `collect_uarch_cycle_root_hashes(mcycle+1, 0, tail)`: the same mcycle, one hash per executed uarch cycle | `collect_uarch_cycle_bundle(0, 20, tail)`: the whole mcycle, where the uarch-halted hash repeats to position 2^20 |
| mcycle | `collect_mcycle_root_hashes(MCYCLE_MAX, 0, 0, 0)`: runs to the halt (114 mcycles) | `collect_mcycle_bundle(0, 0, 20)`: the same run, padded with the halt fixed-point hash to 2^20 entries |

A pair passes when the bundle's growth is at most max(16 MiB, 32 x the control's growth).

**Requirement** (THREAT_MODEL.md R12): "Where a computation hash repeats the hash of a fixed point, the
repetitions cost a bounded amount per run of them, not per cycle."

**Run:** `bugs/run.sh R1-R12-4` (about 5 s).

**Expected output on audit/prt2** (exit 1, the same in every run):

```
  uarch: control 645 entries / 0.2 MiB, bundle 1048576 entries / 267.2 MiB, limit 16.0 MiB (1103x the control)
VIOLATED: R12: collect_uarch_cycle_bundle must cost ... (peak RSS growth 267.2 MiB <= 16.0 MiB)
  mcycle: control 114 entries / 0.1 MiB, bundle 1048576 entries / 267.3 MiB, limit 16.0 MiB (2138x the control)
VIOLATED: R12: collect_mcycle_bundle must cost ... (peak RSS growth 267.3 MiB <= 16.0 MiB)
run.sh: R1-R12-4: exit 1 (bug present)
```

**Context for the reviewer** (facts only, no rating):
- The code is in `src/machine.cpp`. `collect_uarch_cycle_bundle` calls `hashes.reserve(2^log2)` and then
  `insert(halt_count, halt_root_hash)`. `collect_mcycle_bundle` calls `reserve(2^count)` and then
  `resize(.., fixed_point_root_hash)`. The C, Lua and JSON-RPC bindings pass the result as JSON with base64
  entries.
- The documented result in `src/cm.h` (`cm_collect_uarch_cycle_bundle`) is "a JSON array of
  2^log2_bundle_uarch_cycle_count base64-encoded state root hashes". So the expanded list is the documented
  result of this API.
- The PRT recipe's player (`doc/recipes/prt.lua`) does not call `machine:collect_uarch_cycle_bundle`. It
  collects with `collect_uarch_cycle_root_hashes(.., 0, ..)` and pushes the halted tail into a frontier forest
  as a run. It calls `machine:collect_mcycle_bundle` only with `LOG2_BUNDLE_MCYCLE_COUNT = 4` (16 entries).
  Only `prt-dishonest.lua` and `prt-test.lua` call the machine bundle APIs directly.
- The test exits 0 if a fix changes the result to a bounded representation, for example a run-length tail.
