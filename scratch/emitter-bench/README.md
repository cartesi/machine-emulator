# Emitter emission-rate comparison

Measures how fast each candidate emitter turns guest instructions into host
code, to price the RVVM always-compile policy (no hotness, compile every
executed pc) for the copy-and-patch replacement plan in copy-patch-rvvm.md.

## Method

Three microbenchmarks emit 20,000 independent traces of the same
16-guest-instruction integer mix (ALU ops, one mid-trace guard branch, one
trace-ending guard), single-threaded, on the M3 Max:

- `rvjit-bench.c`: RVVM's rvjit, linked from the prebuilt
  /private/tmp/rvvm-source release.darwin.arm64 objects. Each trace is
  finalized into the code heap through the same linkage path the emulator
  uses (same-page pending links patched as successors compile, icache
  flush per block).
- `lightning-bench.c`: bundled GNU lightning 2.2.3, mirroring the real
  backend's per-trace pattern (one jit_state per trace, jit_prolog +
  jit_tramp(0), entry guard, guest registers loaded at entry and stored at
  exit, jit_emit into executable memory).
- `copypatch-bench.c`: the copy-and-patch ceiling. One 28-byte stencil copy
  per guest instruction plus 12 masked scalar patches per trace into a
  MAP_JIT heap, with pthread_jit_write_protect_np toggles and
  sys_icache_invalidate per trace. A bound, not a stencil-selection
  simulation.

The end-to-end pipeline figure comes from the real backend
(compete-jit-ctx256-fpfix, TC_ONLINE_STATS + EXEC_STATS + DETAILS, int64
393 ops): compile-ms 23 over ~270 compile attempts averaging 18.5
instructions, so ~5,000 guest instructions compiled.

Caveat: two unrelated bench.lua int64 runs were consuming one core each
during these measurements. The microbenchmarks are single-threaded, ran on
a mostly idle machine otherwise, and reproduced within 10% across repeats.

## Results (2026-08-20)

| emitter | ns / guest insn | throughput | vs rvjit |
|---|---:|---:|---:|
| lightning (library alone) | ~910 | ~12 MB/s | 26x slower |
| current pipeline (staging + discovery + lightning) | ~4600 | -- | ~130x slower |
| rvjit (RVVM) | ~35 | ~470 MB/s | 1x |
| copy-and-patch bound | ~10-14 | 2.0-2.7 GB/s | ~3x faster |

Projection onto the always-compile volume (RVVM trace maps: ~39,000
traces, ~375k guest instructions, 17 MB per boot plus workload):

| emitter | compile time per boot+workload |
|---|---:|
| current pipeline | ~1.7 s (about 4x RVVM's entire run) |
| rvjit | ~13 ms |
| copy-and-patch bound | ~4-5 ms |

The in-situ cross-check: RVVM emits its 17 MB inside a total run of ~0.47 s
wall, so its compile cost is bounded well under that; the microbenchmark's
13 ms is consistent.

Conclusion: the always-compile policy is unaffordable with the lightning
pipeline and free at copy-and-patch rates. Even if a real stencil emitter
runs 3-5x above its memcpy bound for selection and register-variant lookup,
one boot compiles in ~20 ms, invisible against a multi-second boot.
