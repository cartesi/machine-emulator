# RVVM-policy copy-and-patch tracing JIT

## Goal

Replace the online tracer and the GNU Lightning backend in one change. The replacement is a tracing JIT that ports
RVVM's policies and emits code by copy-and-patch. No element of the current trace selection, retention, side-exit,
promotion, or linking policy survives. What survives is the instruction semantics, the interpreter's hot/cold snippet
factoring, the machine's verified TLB machinery, and the determinism gates.

This is not a hybrid and not an incremental migration of the tracer. The old backend is not modified. It remains
buildable, unchanged, as the comparison baseline until the new backend passes the gates, and is deleted afterwards
together with the bundled GNU Lightning.

The porting rule, in both directions:

- Do not port a mechanism from the current tracer because it exists. Keep a Cartesi mechanism over the RVVM analog
  only when it is simpler, already gated, or required by an invariant. The keep list is short and closed: the hot
  TLB probe, the typed fast pc, the per-trace code-page mapping validation, and the write-hook store invalidation.
- Do not add a policy RVVM does not have. Its answer to every coverage question is "compile the pc when it executes",
  and that answer replaces hotness detection, exact-head admission, side-exit counters, side traces, blacklists,
  penalties, demotion, publication floors, and chase budgets.

## Why (measured, not assumed)

- RVVM completes the fixed-work AArch64 board in 0.70-0.73x the time of the current JIT. Its largest wins (int64
  4.4x, matrixprod 2.7x, qsort 2.0x, zlib 2.2x) are exactly the rows where the current tracer's coverage collapses.
- The current backend's own decomposition shows coverage, not code quality, is the frontier. Wherever coverage
  exceeds 95% it already retires 1.2-2.5 Ginsn/s and is competitive. Register quality bound only regs, priced at a
  1.6x ceiling, last in payoff order.
- The last major increment of tracer policy complexity (transactional side traces) bought 1.1% aggregate.
- RVVM's policy compiles everything it executes. One boot plus workload compiles about 39,000 traces, 17 MB of
  code, 375k guest instructions, with heavy overlap and no deduplication. Measured head to head on the same
  16-instruction integer mix (scratch/emitter-bench), lightning emits at ~910 ns per guest instruction (~12 MB/s),
  the full current pipeline at ~4.6 us, RVVM's rvjit at ~35 ns (~470 MB/s), and the copy-and-patch memcpy+patch
  bound at ~10-14 ns (2+ GB/s). At those rates the always-compile volume costs ~1.7 s per boot through the current
  pipeline, ~13 ms through rvjit, and ~5 ms at the copy-and-patch bound. The policy is unaffordable with lightning
  and free with copy-and-patch.
- The current backend beats RVVM 2x on double through hard-float coverage. The FP snippets and their guards are
  kept for that reason.

## Sources of truth

1. The committed interpreter defines RISC-V semantics and the hot/cold snippet factoring: hot TLB probe, ALU bodies
   with the RISC-V corner cases, branch guards, side-exit materialization, the cross-page translation node, and the
   helper bridges with the by-value ABI. These become the stencils.
2. The downloaded RVVM sources define the policies: formation, linking, invalidation, retention, and the
   register-cache lifecycle. Port the behavior, do not redesign it from memory.
3. The copy-and-patch paper and tutorial define stencil generation, extraction, concatenation, and patching. No
   runtime assembler.

When these disagree, Cartesi Machine semantics and determinism win.

## Policy specification (RVVM analogs)

RVVM is a tracing JIT with a block-cache lifecycle. Formation follows execution, like our recorder always has.
Everything around formation is where the simplification lives.

- Detection: none. No hot counters, thresholds, penalties, blacklists, probation, demotion, or publication floors.
  A direct-mapped pc-to-trace cache is probed on the fast path, backed by the exact trace table. On a table miss the
  interpreter starts compiling immediately at the current pc, first execution, boot included.
- Formation: tracing, as the interpreter executes. While compiling, each executed instruction appends its stencil.
  Taken branches and JAL are inlined behind direction guards and the trace continues along the executed path, so
  small loops unroll until the size cap and a trace whose successor is its own head closes into a native loop.
  The trace ends at JALR, at an uncompilable instruction, or at a fixed emitted-size cap. Overlapping traces are
  expected and never deduplicated: branchy code gets covered by a union of traces starting at every entry point
  that execution reaches, not by side-trace machinery.
- Guard exits: a failed direction guard materializes the architectural state and returns to the interpreter.
  Nothing records the exit and nothing is penalized. The off-path pc compiles its own trace the next time it
  executes. This is the mechanism that replaces the entire side-exit world.
- Linking: two mechanisms only. A same-page direct successor gets a patched jump, installed when either end
  compiles (pending links keyed by successor pc, a patchable return until then). Every other tail, including
  cross-page, JALR, and returns, ends in one inline lookup stencil that probes the pc-to-trace cache and enters the
  next trace through its validated entry without returning to the interpreter.
- Invalidation: stores invalidate generated code through the existing write hook, page-granular, dropping the
  page's traces lazily. No per-trace lifetime tracking. Self-modifying code must pass the existing coherency tests.
- Retention: keep everything until the fixed code cache fills, then flush all and start over. No LRU, no eviction,
  no second chances. The cache is sized for the measured volume (tens of MB), allocated at machine creation.
- Registers: RVVM's block-local lazy cache. Map a guest register on first use, track dirty, write back only dirty
  values, evict by RVVM's actual age policy, materialize fully at exits and around helpers. Placement is selected
  from offline-enumerated stencil variants, never patched into register fields at runtime.

## What is kept from the current machine

- The hot TLB. It mirrors the shadow TLB, which is hashed state, so its geometry and behavior are machine spec.
  Memory stencils reproduce the committed context-indexed probe, tag check, access-size check, extension, dirty
  handling, and store invalidation, with a failed check branching to the existing outlined slow path.
- The typed fast pc in host_addr. It is the interpreter contract the generated code rides, it makes in-trace
  fallthrough and same-page transfers free, and every exit leaves through the interpreter's fetch tail. The
  cross-page tail re-encodes it through the existing verified hot code-TLB path only (the translation node
  stencil). A miss leaves the successor pc encoded for the old page and falls into the normal fetch continuation.
- The per-trace code-page mapping validation at entries, as call_fn performs today. RVVM's analog is a jtlb flush
  on MMU events; ours validates the recorded mapping against the hot code TLB at entry and falls back cleanly, is
  stronger, and is already gated.
- Cycle exactness. A trace entry guard proves the body fits before the tick end, and every exit materializes the
  exact pc and pending mcycle. Pending counts are per-exit patch constants. Traces containing mcycle-writing steps
  are rejected at formation.
- FP rides the hard-float snippets and their guards.
- The normal interpreter, record, replay, collect, uarch, proof logging, hashing, and verification paths are
  untouched. No verification or state-access check may be weakened.

## Stencils

Express the existing hot snippets as C++ stencil functions compiled offline by the same compiler that builds the
emulator (clang on AArch64, GCC on Linux/x86-64, both providing preserve_none and musttail), with function sections
and the documented copy-and-patch attributes and barriers. The stencil object and the code entering generated code
must come from the same compiler: preserve_none conventions differ between compilers past six x86-64 argument
registers. An offline generator extracts code bytes and
patch metadata into checked descriptor tables. The generator must:

- Reject unexpected instructions, relocations, section layouts, register encodings, or patch-field masks, and fail
  the build on any deviation.
- Verify every register-placement variant, including repeated operands and the x0 source, and check that every
  declared patch is in-bounds and non-overlapping.
- Emit deterministic output and a readable manifest of each stencil's size, clobbers, continuations, and patch
  fields.

Use distinct stencil shapes when an operand changes instruction selection: zero versus nonzero constants, encodable
versus materialized immediates, shift boundaries, word versus doubleword results. Cold paths stay outlined as calls
to the existing helpers, synchronized with the register cache according to their exact read/write contracts.
Runtime work is stencil selection, copy, and patch. Nothing else.

## Build integration

The new backend lives in its own translation unit, selected by a `copy_patch=yes` Makefile switch, mutually
exclusive with `lightning=yes`. The old tracer file is not edited. Makefile targets drive stencil compilation,
extraction, builds, tests, formatting, and linting. Stencil sources, the generator, checked expectations, and tests
are committed. Generated headers, descriptor tables, and extracted fragments are ignored.

The backend introduces no emulator-visible API and no architectural-state changes.

## Validation

- Stencil tests: every placement variant against a C++ reference over deterministic random and adversarial
  operands, RISC-V division and overflow corner cases, both outcomes of every guard, and the extractor's negative
  cases (malformed layouts, relocations, masks, overlapping patches).
- Build-level differential gates: the stock, lightning, and copy-patch builds must retire identical cycles and
  produce identical root hashes and guest exits on the fixed-cycle validation workloads, and pass all machine
  tests. Cover hot TLB hits and misses, context changes, faults, dirty-page transitions, self-modifying code,
  interrupts, and cycle/tick boundaries.
- Report trace counts, emitted bytes, compile time, cache flushes, and coverage counters with every result.

On macOS, prefix local build and test invocations with `PATH=/opt/local/bin:$PATH`. Run formatting, format checks,
linting, and Lua static checks through `toolchain-exec` or the corresponding Makefile-managed toolchain target.

## Performance gates

Measured on the fixed-work board protocol, identical binaries except the backend, interleaved repetitions, medians:

- Compile cost must be invisible: boot time within noise of the stock interpreter despite always-compile.
- Aggregate not worse than the lightning backend outside a 2% noise band, with the expectation of large wins on the
  coverage-collapse rows (int64, matrixprod, qsort, zlib, syscall).
- The comparison target is the committed RVVM board column.

If a result contradicts the design expectation, keep the measurement and investigate it. Do not adjust policy by
intuition.

## Removal

After the gates pass, delete the lightning backend, the online recorder and its policy machinery, and the bundled
GNU Lightning dependency.

## Non-goals

- No hotness heuristics, trace trees, side-trace formation, or promotion machinery of any kind.
- No new RISC-V semantic implementation and no second decoder.
- No runtime assembler and no runtime register-field rewriting for placement.
- No inlining of paths the interpreter deliberately outlines.
- No tuning passes before the replacement gates are green.
