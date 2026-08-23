# Copy-and-patch implementation notes

Working notes for the copy-patch-rvvm.md implementation. Status and verified
facts, updated as the work proceeds.

## Statistical profiles (2026-08-21)

macOS `sample(1)` profiles at 1 ms, attributed to exact generated-code
stencils and byte offsets with an emission ledger, split the remaining losses
into two different mechanisms:

- `branch`, after a 1 Gi-mcycle warmup and over the next 4 Gi mcycles: 6,140
  samples under `cm_run`, of which 3,325 (54.2%) were in generated code.
  `cp_call_probe` and `cp_tick_guard` accounted for 2,049 samples, 61.6% of
  generated-code samples and 33.4% of all `cm_run` samples. Another 45.8% of
  `cm_run` samples were outside generated code. Most samples in both entry
  stencils landed at offset zero. That associates the cost with entry,
  validation, and fragmented execution, but does not prove that the patched
  immediate instruction at offset zero is itself expensive. This supports an
  entry/continuity A/B and provides no evidence for the JIT-heap placement
  hypothesis.
- `regs`, after a 1 Gi-mcycle warmup and over the next 64 Gi mcycles: 6,129
  samples under `cm_run`, of which 5,521 (90.1%) were in generated code. LD
  and SD offset `+0x18` accounted for 2,130 samples, 38.6% of generated-code
  samples and 34.8% of all `cm_run` samples. Disassembly identifies that exact
  instruction as `ldr x9, [x9]`, the hot-TLB virtual-address tag load, before
  the tag comparison. The memory probe is therefore a measured in-trace
  hotspot for `regs`, unlike `branch`.

There were no unmapped generated-code samples. `CP_STATS` showed that the heap
flush counts did not change during either sampled interval (`branch` remained
at two, `regs` at one), so the final emission map is valid for the steady-state
PCs despite addresses having older mappings before warmup. The profiling path
is opt-in through `CP_PROFILE_MAP`; recording is an emission-time in-memory
append, the map is written at machine teardown after sampling, and generated
code does no profiling work. `bench-harness/profile.lua` supplies fixed-work
warmup and sampling windows, and `tools/cp-profile-report.lua` parses the
profiler call graph and attributes JIT PCs using Lua patterns.

### Exact compete-matrix profiles

The matrix was then re-profiled with its exact static musl stress-ng, fixed
`ops.json` workloads, Linux image, rootfs, and boot arguments. The harness is
`bench-harness/compete/profile.lua`; each macOS `sample(1)` run used a 1 ms
interval and the same generated-PC ledger. Twelve usable rows had one heap
epoch and zero unmapped JIT samples. The exact `branch` run crossed three heap
epochs, so its reused PCs cannot be attributed to a unique final stencil and
are deliberately excluded below. Branch is not a qemu/rvvm loss in this
matrix.

    workload    cm_run   JIT   JIT share   leading measured costs
    nop           3284  1536     46.8%     tick 41.0%, bne 21.0%
    regs          2120  1674     79.0%     LD/SD tag loads 35.8%, li 5.2%
    tree          3596  1717     47.7%     entry/lookup, loads, branches
    qsort         4315  3901     90.4%     lookup 18.8%, call entry 27.1%
    memcpy        3321  2035     61.3%     memory tag loads >=59.2%, tick 19.6%
    zlib          3839  2105     54.8%     byte/half tag loads 21.5%, entry
    hash          3647  2102     57.6%     memory tag loads >=34.5%, li 10.3%
    syscall       2961  1847     62.4%     entry/lookup, memory probes, li 10.4%
    double        3617    62      1.7%     interpreted FP execution
    sieve         3843  3584     93.3%     LW/SW tag loads 48.1%, tick 14.4%
    int64         3298  3070     93.1%     entry/lookup, li 15.3%, memory probes
    matrixprod    3044  1425     46.8%     memory tag loads 22.9%, li 14.9%

The exact musl `regs` rerun therefore resolves the earlier caveat: it is not
the rootfs stressor's old slot-eviction problem, but it is again a data-memory
probe problem. LD/SD `+0x18`, the hot-TLB virtual-page tag loads, received 599
samples: 35.8% of JIT samples and 28.3% of all `cm_run` samples.

The broadest remaining cost is the per-memory-operation TLB probe, but the
previous memoization experiment already showed that adding captures inside
the loop is not a low-risk win. The smallest profile-backed next experiment
is immediate-folded integer ALU stencils. Formation currently implements
every `reg2i` as `cp_li` into a scratch slot followed by a register-register
stencil. `cp_li` is 15.3% of JIT samples in int64, 14.9% in matrixprod, and
about 10% in hash and syscall (7.0% across the twelve usable profiles). This
is a ceiling because `cp_li` also serves true constant loads and address
formation. Classifying each sampled `cp_li` by its immediately following
stencil leaves immediate-capable ALU ceilings of 11.2% of JIT samples in
int64, 8.6% in matrixprod, 8.5% in hash, and 6.0% in syscall. A direct
register-immediate family removes both the materialization and its scratch-slot
pressure without introducing new runtime state. FP arithmetic
coverage is separately well-supported for double -- only 1.7% of its samples
are in generated code -- but is a larger semantic and validation project, not
the low-hanging experiment.

### Outside-JIT attribution for the competitive losses

The worst RVVM losses and the material qemu losses were sampled again at 1 ms
without `CP_PROFILE_MAP`. This removes the emission-ledger append from trace
formation. Generated code is still identified exactly for this purpose: it is
the `<unknown binary>` direct child of `cm_run`, while every outside-JIT sample
has a host symbol. Percentages in the final column use non-JIT time as their
denominator; the sample count and JIT coverage use all `cm_run` time.

    workload    cp/rvvm cp/qemu samples   JIT   non-JIT   non-JIT breakdown
    regs           2.63    1.88    1866   78.9%   21.1%   dispatch 50.9%, form 17.3%,
                                                           slow memory 15.3%, handlers 13.5%
    memcpy         2.58    0.72    2973   60.5%   39.5%   handlers 37.3%, dispatch 26.5%,
                                                           code fetch 24.2%, form 7.1%
    int64          2.21    0.34    3304   93.1%    6.9%   form 32.8%, dispatch 24.5%,
                                                           slow memory 21.8%, handlers 14.9%
    zlib           1.89    0.99    3438   55.6%   44.4%   handlers 58.8%, dispatch 20.8%,
                                                           slow memory 8.1%, code fetch 6.0%
    matrixprod     1.43    0.52    2990   47.1%   52.9%   handlers 48.8%, dispatch 41.7%,
                                                           form 4.9%, slow memory 3.2%
    tree           1.33    0.62    3101   48.2%   51.8%   slow memory 46.9%, handlers 30.6%,
                                                           dispatch 15.4%, form 5.7%
    sieve          1.16    1.22    3811   93.5%    6.5%   form 28.1%, dispatch 25.2%,
                                                           slow memory 22.8%, handlers 19.9%
    double         0.55    1.06    3252    1.3%   98.7%   handlers 71.0%, dispatch 23.0%,
                                                           form 2.3%, code fetch 2.2%

Here `dispatch` includes `interpret_loop_tc_body`, `cp_probe`, and
`cp_continue`; `form` includes `cp_emit`, `cp_finish`, and `cp_write_hook`;
slow memory includes translation, refill, verified-TLB publication, TLB
flushes, and the slow RAM accessors. These are sampled current-PC buckets, not
inclusive call-tree costs.

The named symbols sharpen the diagnoses:

- `regs`: `interpret_loop_tc_body` alone is 10.4% of total time. Outside JIT,
  the largest interpreted handler is `C_SDSP` at 2.1% of total, while slow
  memory/TLB machinery is 3.2%. The larger measured problem remains inside
  JIT: LD/SD tag probes were 28.3% of total time in the unambiguous stencil
  profile.
- `memcpy`: interpreted `BNE` is 8.1% of total, `LBU` 3.2%, and `SB` 2.7%.
  Code-fetch miss and crossing paths are another 9.6%. Thus its RVVM loss is
  both the in-JIT generic data probe and failure to keep the byte-copy loop in
  generated code, not stack traffic.
- `int64`: only 6.9% is outside JIT, so outside-JIT work cannot explain a 2.21x
  RVVM loss. Its diagnosis stays inside the trace: `cp_li` is 15.3% of JIT
  samples, of which immediate-capable ALU successors account for 11.2%.
- `zlib`: interpreted `BNE` alone is 10.2% of total and `LBU` is 4.5%. Combined
  with only 55.6% JIT coverage, trace coverage/continuity is a larger problem
  than its 21.5%-of-JIT byte/halfword tag probes.
- `matrixprod`: the dispatcher alone is 21.1% of total. The largest interpreted
  buckets are `C_SDSP` 4.1%, `BGE` 3.5%, shifts 2.6%, and integer remainder
  2.1%. Its primary remaining issue is coverage and unsupported/fragmenting
  integer control/soft-float support code, not its already-generated memory.
- `tree`: 24.3% of total time is in slow memory/TLB work. `read_ram_uint64` is
  9.4%, translation 4.1%, and TLB replacement/publication/flush paths make up
  most of the balance. This is real pointer-chasing miss/refill cost, unlike
  the in-trace tag-hit cost in `regs` and `sieve`.
- `sieve`: 93.5% is JIT, leaving no consequential outside-JIT culprit. The
  earlier exact stencil attribution remains decisive: LW/SW tag loads are
  48.1% and tick guards 14.4% of JIT time.
- `double`: the generic double-precision handler `FD` is 50.3% of total time,
  `FLD` another 6.4%, and the dispatcher 22.5%. This is overwhelmingly missing
  FP compilation coverage.

### Stack-page reach measurement

A temporary measurement build counted successful generated-code memory
operations whose effective virtual address was on the same 4 KiB page as the
live guest `x2`. Before every generated memory stencil, a dirty cached `x2`
was synchronized to the architectural register file; the semantic wrapper
incremented its counters only after the hit-or-bail operation succeeded. Thus
the totals exclude repeated miss attempts and compare against an exact stack
page even while `x2` is register-cached. Counts below subtract an identically
instrumented `true` boot. Workload multipliers match the statistical-profile
runs; they change total counts, not the classification.

    workload     loads caught   stores caught   all memory ops caught
    nop               63.31%          70.13%              66.64%
    regs              82.29%          87.05%              84.57%
    branch             5.90%          44.99%              10.37%
    tree              21.31%          52.92%              30.10%
    qsort             31.67%          43.26%              35.42%
    memcpy            24.40%           0.22%              13.99%
    zlib               0.68%          28.57%               3.04%
    hash              12.15%          64.19%              22.70%
    syscall           12.47%          15.86%              13.92%
    double            47.97%          84.85%              74.86%
    sieve              0.06%           0.10%               0.08%
    int64              0.32%           0.17%               0.25%
    matrixprod        81.37%          98.86%              87.51%

The exact raw counts repeated bit-for-bit for `regs` and `int64`. The result
supports stack-page specialization as a strong `regs` and `matrixprod` lever,
but not as the broad explanation for the competitive memory band: it catches
only 14.0% of memcpy, 0.08% of sieve, and 0.25% of int64 memory operations.

Putting reach beside the current compete matrix makes that boundary clearer.
Ratios below are copy-patch time divided by the competing emulator time, so a
ratio above one is a copy-patch loss. The host column is the median native
ARM64/Darwin time normalized to the matrix's exact bogo-op count.

    workload     stack caught   cp/rvvm   cp/qemu   host seconds   cp/host
    nop                66.64%      0.73      0.86        0.2231       1.7
    regs               84.57%      2.63      1.88             -         -
    branch             10.37%      0.59      0.29        0.1984       4.4
    tree               30.10%      1.33      0.62        0.2526       7.1
    qsort              35.42%      1.05      0.41        0.0319      44.8
    memcpy             13.99%      2.58      0.72        0.1964      18.6
    zlib                3.04%      1.89      0.99        0.6409       6.2
    hash               22.70%      1.03      1.02        0.2869       6.9
    syscall            13.92%      0.86      0.59             -         -
    double             74.86%      0.55      1.06        0.1015      17.9
    sieve               0.08%      1.16      1.22        0.8687       2.5
    int64               0.25%      2.21      0.34        0.2010       3.7
    matrixprod         87.51%      1.43      0.52        0.0023     522.0

The association is strong only for `regs`: high reach coincides with a large
loss to both RVVM and qemu. It does not explain the broad RVVM gap. `memcpy`,
`zlib`, and `int64` are respectively 2.58x, 1.89x, and 2.21x slower than RVVM,
but a stack page catches only 14.0%, 3.0%, and 0.25% of their memory operations.
`sieve` loses to both RVVM and qemu with 0.08% reach. Conversely, `nop` and
`double` have high reach without a corresponding RVVM loss; `double` spends
only 1.7% of its sampled time in generated code. `matrixprod` is the other real
stack-page candidate, but copy-patch already beats qemu there and its RVVM gap
is much smaller than `regs`.

A deliberately optimistic Amdahl estimate also limits the prize. In `regs`,
tag probes are 28.3% of all `cm_run` samples; weighting that by 84.57% reach
puts about 23.9% of total time in scope. Making every caught probe free would
therefore yield at most about 1.31x, moving 3.32 seconds to roughly 2.53 --
still behind qemu at 1.77 and RVVM at 1.26. The same estimate is about 1.10x
for `matrixprod` and 1.05x for `memcpy`. These are rough ceilings: sampled cost
need not be distributed exactly like dynamic memory-operation counts.

The host experiment used stress-ng 0.17.06 at the benchmark's recorded commit
`e6bda983cb48a201b6af173204372c7b37d6411f`, built natively with MacPorts GCC
15. Each row used a calibration run followed by three runs scaled to about 1.5
seconds, then divided by the scale factor to suppress process-startup noise.
This is a useful native-throughput reference, not a strict mathematical bound:
the host executes ARM64/Darwin code with a different ABI, libc, kernel, and
architecture-specific stress-ng conditionals rather than the guest's static
RISC-V/Linux instruction stream. Native `regs` has no trustworthy result: the
Clang build disables it, while both GCC 14 and GCC 15 fail stress-ng's own
register self-check. Native `syscall` also has no comparable row because the Darwin
stressor does not terminate at the requested bogo-op count and exercises a
different syscall set.

## Done

- Stencil pipeline (2026-08-20): tools/cp-gen-stencils.lua emits
  cp-stencils.c (713 stencils: add 8x8x8, addi/beq/ld 8x8, li 8,
  store-exit). tools/cp-extract.lua parses the ELF object, fail-closed
  validation, emits cp-stencils-tables.h + manifest. src/cp-stencils-test.c
  executes copied+patched chains against a C reference (500 random programs,
  adversarial constants, all guard outcomes) in a MAP_JIT heap with the
  Apple-Silicon W^X discipline. `make CP_CLANG=clang-mp-22 test-cp-stencils`
  drives generate/compile/extract/build/run. copy_patch=yes is declared in
  src/Makefile, mutually exclusive with lightning=yes, requires tailcall=yes.
  Use MacPorts clang-mp-22 (or the toolchain clang), not Apple cc.

## x86-64 stencils (2026-08-20)

- Same stencil source compiles for x86-64 with the default small code model
  plus a per-symbol `__attribute__((model("large")))` on the value holes:
  continuations stay direct rel32 jmp/jcc (R_X86_64_PLT32/PC32, addend -4,
  patchable and elidable at 5 bytes for a trailing e9) while holes become
  movabs with R_X86_64_64. A blanket -mcmodel=large is wrong there: it
  lowers the musttail continuations to indirect jumps through movabs and
  moves code to .ltext sections. preserve_none x86-64 argument order is
  r12, r13, r14, r15, rdi, rsi, rdx, rcx for the first eight slots.
- ABS64 relocations carry addends (store-exit rematerializes the hole per
  store), so patch records carry an addend field; AArch64 kinds require
  addend zero.
- All 713 stencils extract and validate for both arches; the execution test
  passes natively on the aarch64 host, and 5/5 deterministic passes for the
  amd64 binary under qemu-x86_64 (arm64 container, qemu-user), which is the
  preferred amd64 test vehicle from this Mac: QEMU TCG is deterministic and
  strict about code-page rewrites, and its gdbstub plus gdb-multiarch works
  where ptrace under Rosetta does not.
- Same-compiler rule, enforced in the Makefile: CP_CC defaults to the
  emulator compiler, so the platform compiler builds caller and callees
  alike (clang on AArch64, GCC on Linux/x86-64). GCC-16 stencils compile
  with -mcmodel=medium -mlarge-data-threshold=1 -fno-pic and sized hole
  arrays (movabs + R_X86_64_64, folded constants arrive as relocation
  addends and the imm+addend patch rule absorbs them); all 713 validate
  through the same fail-closed extractor and the gcc-built test passes
  under qemu. GCC's six preserve_none argument registers are r12-r15,
  rdi, rsi (clang's first six), so the amd64 stencil contract caps at six
  register slots; mixing compilers across the boundary crashes (measured)
  and is refused.
- Debugging postmortem for the record: an earlier "Rosetta translation
  cache" theory for amd64 crashes was wrong. The crashes were AArch64
  stencil bytes executing on x86: `#include "cp-stencils-tables.h"`
  searches the source directory before -I paths, and container builds
  compiled from the mounted src/ picked up the aarch64-generated header
  left by a host make run. Builds compiled from copies outside src/ got
  the intended x86-64 header, which produced the "layout-sensitive"
  illusion. When cross-testing, compile from a directory containing only
  the intended arch's generated header. The membarrier SYNC_CORE call in
  the test predates this diagnosis and stays: it is the Linux
  cross-modifying-code contract that aarch64-Linux hosts require.

## Verified toolchain facts the design rests on

- Stencils compile with `--target=aarch64-unknown-linux-gnu -fno-pic
  -mcmodel=large -ffunction-sections -fomit-frame-pointer
  -fno-stack-protector`. The ELF object is parsed, never linked, so this
  works on macOS. Relocations come out exactly patchable:
  R_AARCH64_JUMP26 (bare `b` continuations, elidable on fallthrough) and
  R_AARCH64_MOVW_UABS_G0_NC/G1_NC/G2_NC/G3 (movz/movk chains for arbitrary
  64-bit values, 16-bit field at bits 5-20).
- preserve_none AArch64 argument order is x20-x28 then x0-x7 (probed, 14
  args). First eight u64 params = guest cache slots in x20-x27. Argument
  positions 3, 4, 5, 7 are x23, x24, x25, x27 = the interpreter's pinned
  fast pc, countdown, fetch tag, and tc_context. The backend signature can
  therefore carry the interpreter hot state at the arg positions matching
  its pinned registers, making trace entry/exit plain branches. The current
  generic 8-slot test contract predates this and the real backend signature
  must reassign slots around the pinned positions.
- Clang applies value substitution inside guard stencils (after r0 == r1 it
  may forward one register for the other). Semantics-preserving; the
  extractor validates relocations and patch sites, not instruction
  sequences.
- Guard stencils with s1 == s2 collapse to unconditional branches
  (degenerate variants, tolerated, tested).

## Emitter measurements (scratch/emitter-bench)

lightning ~910 ns/guest-insn (~12 MB/s), full current pipeline ~4.6 us,
RVVM rvjit ~35 ns (~470 MB/s), copy-patch memcpy+patch bound ~10-14 ns
(2+ GB/s). Always-compile volume (RVVM maps: ~39k traces, ~375k guest
insns, 17 MB per boot+workload) costs ~1.7 s via the current pipeline,
~5 ms at the copy-patch bound.

## Integration map for interpret-cp.cpp (next)

- Entry hook analog: tc_hook_site in interpret-tc.cpp is the shape to
  replace. RVVM-policy version: exact-map lookup -> enter (loop/root
  entries require matching code_vf_offset, call entries go through the
  call_fn-style validated entry), else if no trace and not compiling ->
  request compile-start via the context (recorder setup stays out of
  handlers, the outer loop starts it), no hotcounts, no blacklists.
- Formation: while compiling, handlers append stencils per executed
  instruction (the TC_ONLINE one-instruction-chain recording shape),
  inline taken branches as guards, end at JALR/uncompilable/size cap.
- Write hook: a.get_penumbra().write_hook_ctx pattern near the end of
  interpret-tc.cpp is the store-invalidation registration point.
- Exits leave through tc_fetch_miss / the fetch-tail continuation with the
  pinned contract live, as the lightning backend does.
- Stencil families still to add to the generator for a running backend:
  entry tick guard, exit stub (materialize pc + pending mcycle constants,
  branch to fetch tail), lookup tail (pc-to-trace probe), hot TLB
  load/store families, helper bridge.

## Engine increment 1: CORRECTED status (2026-08-20 night)

The earlier "first gates green" entry below was wrong: make does not
rebuild objects on flag changes, so every "stock" control binary in
those runs still contained the copy-patch backend, and the
"hashes match through 2 Gi" result was the engine compared against
itself. The compete hang WAS a backend bug. With forced rebuilds and a
true stock reference:

- Bug 1 (the hang): cp_record wrapped the selection include in
  switch (label) { ... } while cp-select.inc opens its own switch, so
  the inner switch was an unreachable statement inside a caseless outer
  switch: nothing was ever emitted and no end condition ever fired
  (76-byte empty traces recording to the 256 cap, guest state corrupted
  into a store-fault trap loop). One-line fix. With it, boot HALTS in
  0.11 s with 4,513 traces, 2.1 MB emitted, 393k entries: real
  RVVM-scale formation.
- Bug 2 (open): cp halts at mcycle 31,249,856 vs stock 55,293,806.
  Bisected to a single shadow-TLB word (page 0x3000, offset +640):
  stock ffffffff80132000 vs cp ffffffff80232000, same direct-mapped
  slot, registers identical at the checkpoint, kernel mode, window-size
  dependent (needs in-trace execution; per-cycle stepping suppresses
  it). Leading theory: the ported hot write-TLB eviction induces
  re-verification traffic whose shadow-TLB replacements differ from
  stock's, and the shadow TLB is hashed state. Lightning runs the same
  eviction and gates bit-exact, so its promotion path must avoid the
  shadow write difference in a way the cp path does not yet; find that
  difference next. Debug tooling in place: CP_DEBUG per-record
  classification prints, CP_DUMP_CODE trace dumps, hash-tree bisection
  via get_node_hash, and the win*.lua exact-history harnesses in the
  job tmp dir.
- Build hygiene: flag changes MUST touch/remove interpret-tc.o; the
  gates protocol needs per-config build trees or a config stamp file.

## Superseded (wrong controls): engine increment 1 first status

The engine runs. interpret-cp.inc (formation, install, invalidation,
flush, hook, continuation) + cp-context.hpp + cp-select.inc +
TC_COPY_PATCH seams in interpret-tc.cpp, built via tailcall=yes
copy_patch=yes. Verified against a SAME-HEAD stock build: root hashes
match at every checkpoint through 2 Gi mcycles of boot, wall time
identical, 63 traces installed, 139k generated-code entries.

Findings and fixes on the way:
- The first "divergence at mcycle 1" was reference skew: the old
  compete-stock prefix has different uarch pristine RAM than HEAD. Gate
  only against same-HEAD builds.
- cp_heap_protect_flush now flushes from a watermark, not the whole
  heap (the per-finish whole-heap sys_icache_invalidate was quadratic).
  Increment 3 must lower the watermark when links patch older traces.
- Ported the hot write-TLB eviction from tc_online_finish after
  installing a trace; without it, stores to traced pages through
  pre-established write slots are invisible to invalidation (soundness).
- Exit stubs take signed fast-pc displacements, not absolute values
  (the typed fast pc is position-encoded); cross-page exit deltas are
  legal because the fetch tail decodes vaddr = fastpc - vf_offset
  algebraically.
- Trace entry is suppressed while recording (Apple per-thread W^X: the
  heap is writable during an emission episode, so JIT pages are not
  executable on this thread).
- Open oddity, not ours: compete.lua's single run(1<<62) hangs on the
  CURRENT HEAD tree even under the stock build (the old prefix builds
  halt in ~6 s). The stepped-run differential is unaffected. Machine
  tests and the full canon still owed once the tree question clears.
- Formation volume is far below RVVM's (63 traces per boot vs 39k):
  hooks only exist at backward branches and call sites, entries only at
  matching-mapping loop heads in increment 1, and there are no counters
  for begins/aborts yet. Add counters, then increments 2-4 grow reach.

## Superseded in-progress note

Done so far: cp_far_jump island (two-hole sum defeats the direct-branch
fold), cp_gxl/cp_gxs guest-register transfer families (one baked-offset
x-file access each), widened extractor two-index tables, all validating
(10,882 stencils); and src/cp-select.inc, the formation selection switch
over TC case labels covering the integer, branch, load/store, and
compressed sets, decoding through the interpreter's insn helpers with
fused labels discriminated by funct7. The label enum and the runtime
classification come from re-expanding interpret-tc-cases.inc
(enum class tc_label) and interpret-tc-table.inc (a 65536-entry
cp_label_table indexed by insn_get_id) with different macro definitions,
so classification is single-source with the dispatch. Still to build:
cp-context.hpp, interpret-cp.cpp (formation primitives f.reg3/reg2i/li/
load/store/branch/jump/end, install, flush, write hook), the
TC_COPY_PATCH seams, the copy_patch=yes emulator build, and the
increment-1 gates.

## Done: memory stencil families, single-source, hit-or-bail

The generator emits cp_mem_access (slot-bound register file, all TLB
and memory methods plus the exception surface forwarded to the real
state_access bit-cast from the sa parameter) and load/store wrappers
instantiating execute_LB..LD/execute_SB..SD with synthetic imm=0 words.
The slow path is intercepted by requires-constrained twins of
read/write_virtual_memory_slow (the unconstrained ADL overload lost
partial ordering; constrained same-signature templates win
deterministically), and the lazy hot-slot init, an out-of-line cold
member the extractor rejected as a stray call, is treated as a plain
miss: uninitialized slots bail and the interpreter initializes them
portably. Result verified by disassembly: cp_ld_2_3 is the committed
14-instruction context-indexed probe with baked emulator-layout offsets,
host load straight into the slot register, and hit/bail continuations,
60 bytes, two branch patches. 10,447 stencils validate on both
architectures (extraction green on amd64 gcc too); the ALU/branch/
structural execution tests stay green on both. Runtime-tested by
src/cp-machine-test.cpp (make test-cp-stencils runs it): builds a real
machine, warms read and write hot TLB slots through the interpreter's
own read/write_virtual_memory (the test TU includes interpret.cpp with
TC_TRANSLATION_UNIT and links the libcartesi object set, so the flags
must match the tree's build config), then verifies LD hit value, LB
sign extension, the bail continuation on a cold slot with slots intact,
SD visibility through the machine API, and an SW+LWU round trip. Green
on AArch64.

## Done: contract carries the state access at parameter 1

The stencil signature is now (sa, r0, r1, pc, cd, fetch, r2, tcc, r3,
r4, r5, r6): parameter 1 is the state access pointer, matching the
interpreter handler contract's x20 so trace entry stays zero-move, and
giving memory stencils the accessor directly instead of re-deriving it
from tcc through penumbra.owner. Seven guest cache slots remain
(placement tables are [7]-dimensioned, extractor digit patterns 0-6).
9,957 stencils, green natively on AArch64 and 3/3 under qemu on amd64.

## Memory-family design (next, single-source like the ALU set)

Diego's check "don't we have these snippets in interpret.cpp too"
holds for memory: execute_L/execute_S bodies plus read_virtual_memory /
write_virtual_memory contain the committed hot TLB probe entirely as
accessor calls (read_tlb_ctx_slot_base, read_tlb_vaddr_page,
init_hot_tlb_slot, verify_cold_tlb_slot, read_tlb_pma_index,
read_tlb_vf_offset, read_memory_word), with the slow path already an
outlined call (read_virtual_memory_slow) and an existing staging hook
(stage_read_virtual_memory) that the lightning collector uses. The
memory stencil wrappers therefore instantiate execute_L/execute_S with
an accessor that binds x reads/writes to slots and forwards the TLB and
memory surface to the real state_access, constructed in the wrapper
from the tcc parameter (processor state at a constant offset; layout
correct because the TU compiles with the emulator's own compiler).
Design resolved for increment one (hit-or-bail, no helper calls):

- Slow path: the miss call is intercepted by an ADL overload. The
  semantic TU defines read_virtual_memory_slow / write_virtual_memory_slow
  overloads taking cp_mem_access (found by argument-dependent lookup at
  instantiation, preferred by partial ordering over the generic
  template) that mutate nothing and return failure. The wrapper maps a
  non-success execute status to the bail continuation, and the
  interpreter re-executes the instruction portably, running the true
  slow path there. No helper-call relocations exist in increment one;
  the helper-bridge patch class is deferred until profiling says a
  trace-resident slow path pays.
- mcycle: the hot path never reads it (only the intercepted slow path
  takes it), so the wrapper passes zero and no cp-context header is
  needed yet.
- The 12-bit load/store immediate cannot be a value hole in the
  Mach-O semantic TU, so increment one bakes imm=0 into the synthetic
  word and formation pre-adds the immediate into a scratch slot
  (li + add + memop). Encodable-immediate memory shapes are a later
  measured optimization like the ALU immediates.
- Accessor: cp_mem_access holds the real state_access (bit-cast from
  the sa parameter) plus the slot bindings; do_read_x/do_write_x go to
  slots, and the TLB and memory surface (ctx slot base, vaddr page,
  init/verify slot, pma index, vf offset, read/write_memory_word)
  forwards to the real accessor, so the emitted probe is the committed
  one against the emulator's own layout.

Original consequences list (now partly superseded):

- The outlined slow-path call appears in the stencil as a call
  relocation to a mangled emulator symbol. Patch model gains a helper
  ordinal class: CALL26/JMPREL32 patched at emission to the helper's
  runtime address. AArch64 range is +-128 MB, so the emitter needs
  branch islands (movz/movk + br through x16/x17, the linker-veneer
  scratch) when the JIT heap lands far from emulator text, or the heap
  must be mapped near it.
- mcycle is a value parameter of execute_L/S: the wrapper derives it
  from tcc->mcycle_tick_end minus the countdown parameter, the same
  materialization the trace machinery already defines.
- A failed access (slow path returns failure / raises) must leave for
  the bail continuation with exact state, which is the helper-bridge
  contract from the doc.

## Done: single-source semantic stencils on both architectures

The correction is complete. The generator emits two TUs: structural C
(value holes, bare-metal ELF) and cp-stencils-semantic.cpp, whose
wrappers instantiate the interpreter's own execute bodies. The extractor
was rewritten with two container formats (ELF64 full patch-kind set,
Mach-O arm64 restricted to BRANCH26 with symbol-boundary extents, true
size at last relocation plus four, validated trailing padding) and
multi-object merge with duplicate rejection. The test dropped the
immediate families (immediates route through li plus reg-reg, mirrored
in the random programs) and passes with 14,795 merged stencils natively
on macOS (Mach-O semantic TU plus ELF structural TU, 13 s pipeline) and
3/3 under qemu on amd64 with both TUs compiled by gcc-16 (native ELF).
The hand-written semantics table is gone.

Portability trap fixed on the way: g++ silently ignores
__attribute__((preserve_none)) when it precedes the extern "C" linkage
specifier (clang accepts either position), producing plain-SysV
stencils that misplace every slot. The generator emits
extern "C" CONT and the attribute survives both compilers; the failed
run also confirmed the differential test catches convention drift.

## Superseded status note (2026-08-20, evening)

tools/cp-gen-stencils.lua now emits two files: the structural C TU
(store/tick-guard/exit-stub/li/ld scaffold, value holes, none-elf) and
cp-stencils-semantic.cpp, whose 14,720 wrappers instantiate the
interpreter's own execute bodies (28 reg-reg ops x 512 placements via
execute_ADD<cartesi::rd_kind::xN> and kin with synthetic words rd=3
rs1=1 rs2=2; 6 branches x 64 via execute_Bxx against a dummy pc with a
+8 synthetic offset, taken read off the folded pc). The accessor stubs
the branch bodies' statically-instantiated exception surface (mtvec,
medeleg, mepc writes and kin), dead under the aligned offset. Native
compile: 8 s, zero errors, __text carries ONLY BRANCH26 relocations
(19,088) and only _cp_* symbols; the 14k ARM64_RELOC_UNSIGNED all sit
in __compact_unwind, which extraction ignores. cp_beq from execute_BEQ
folds to the identical cmp/b.ne shape the hand-written stencil had.

Next, in order: (1) extractor Mach-O mode plus multi-object merge.
Parse spec: magic 0xfeedfacf, header 32 B (magic cputype cpusubtype
filetype ncmds sizeofcmds flags reserved), iterate load commands
(cmd u32, cmdsize u32); LC_SEGMENT_64=0x19 carries section_64 records
(80 B: sectname[16] segname[16] addr u64 size u64 offset u32 align u32
reloff u32 nreloc u32 flags u32 + 3 u32), find (__TEXT,__text) and
count its 1-based ordinal across all segments for nlist n_sect;
LC_SYMTAB=0x2 gives symoff nsyms stroff strsize; nlist_64 is 16 B
(n_strx u32, n_type u8, n_sect u8, n_desc u16, n_value u64). Extents:
_cp_* symbols in the text ordinal sorted by n_value, end at next start
or section size; true stencil size = last BRANCH26 offset + 4, trailing
bytes to the next symbol must be padding, at least one reloc required
(every semantic stencil ends in b). Relocation entries at reloff, 8 B
(r_address i32, then u32 = symbolnum:24 | pcrel bit24 | length bits
25-26 | extern bit27 | type bits 28-31); accept only type 2
ARM64_RELOC_BRANCH26 with extern=1 length=2 pcrel=1, symbol _cp_cont_0
or _cp_cont_1, emit as CP_P_JUMP26. Fail closed on anything else.
(2) Makefile: cp-stencils-semantic.o native $(CXX) rule (flags as the
verified compile: -O2 -ffunction-sections -fomit-frame-pointer
-fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
plus the interpreter include set), extractor consuming both objects.
(3) Test: drop imm_ops (immediates now route through li + reg-reg at
formation), reg/branch tables come from the semantic TU. (4) Delete
the superseded hand-written semantics from the C TU emission. Then
amd64: both TUs native ELF under gcc-16, existing extractor mode.

## Superseded correction note: stencil semantics must come from interpret.cpp

Diego flagged that the RV64IM families below violate the plan: their
semantics are a hand-written expression table in the generator, a second
RISC-V implementation the doc forbids, and the test references mirror the
same table (circular on the axis that matters). The replacement
architecture is spiked and validated (cp-spike.cpp): a C++ stencil TU
does `#define TC_TRANSLATION_UNIT` and includes interpret.cpp (the same
single-semantic-source pattern as interpret-tc.cpp; the define already
suppresses the instantiation tail), defines a minimal cp_slot_access
(CRTP i_state_access + i_accept_scoped_notes, do_read_x/do_write_x bound
to wrapper locals, do_get_name, fast_addr = uint64_t), and each wrapper
instantiates the interpreter's own execute_FOO with a synthetic constant
instruction word (rd=3, rs1=1, rs2=2) so the decode folds. Verified: the
result compiles to the identical two instructions the hand-written
stencil produced, semantics from interpret.cpp's text. Consequences:

- Triples and object formats, settled after three rounds of Diego pushing
  back (linux triple -> extracted sysroot -> native): the C structural TU
  (value holes: li, exit stub, store exit) compiles under the bare-metal
  aarch64/x86_64-unknown-none-elf triples, no headers needed, because
  only ELF has the movz/movk 64-bit-hole relocations. The C++ semantic
  TU compiles NATIVELY with the host compiler and SDK, like every other
  object in the build: its only relocations are continuation branches,
  and Mach-O's ARM64_RELOC_BRANCH26 patches the same B field as ELF's
  JUMP26 (verified: identical bytes, one BRANCH26 to _cp_cont_0).
  Native is also the CORRECT choice, not just convenient: semantic
  stencils bake structure offsets that must match the running emulator's
  layout, and same-compiler-same-SDK removes the mixed-toolchain layout
  hazard tail-call.md documented. The extractor gains a Mach-O mode
  restricted to BRANCH26, fail-closed on anything else; Mach-O has no
  function sections, so extents come from nlist symbol boundaries
  (underscore-prefixed names, ignore __compact_unwind, consider
  -fno-unwind-tables). On Linux hosts both TUs are native ELF and the
  question disappears. The extracted-sysroot and container approaches
  are dead ends recorded only in session history, not fallbacks.
- Remaining semantic-TU details from the earlier bullets that stay
  true: immediate ops route through cp_li plus reg-reg stencils with
  formation-time decode via the interpreter's insn_*_imm helpers,
  branch guards read taken/fallthrough off a folded dummy-pc update,
  and the generator keeps only placement wrappers plus the synthetic
  encoding table.

## Done, superseded by the correction above: RV64IM integer stencil families (2026-08-20)

The generator now emits the full RV64IM integer set on the backend
contract: 28 register-register ops (base ALU, shifts with RISC-V amount
masking, W forms with sign extension, comparisons, the M extension with
high multiplies and the division zero/overflow rules branch-free of
calls inside the stencil), 13 immediate forms with 64-bit hole
materialization (encodable-immediate shapes deferred to a measured
optimization), and all six branch conditions. 15,627 stencils, 12.6 s
full pipeline on the M3 Max, extractor placement tables discovered
generically from names. The test differentially checks every family over
random programs with adversarial operands (division corner cases
included) and all branch conditions over sign boundaries; green natively
and on the all-GCC amd64 binary under qemu. Not yet emitted: hot TLB
load/store families (need the interpreter probe shape and context
offsets), the lookup tail, and helper bridges.

## Done: backend-contract stencil library (2026-08-20)

The generator now emits every stencil on the decided positional signature
(guest slots plus pc/countdown/fetch/tcc at the pinned positions), with
two backend families added: cp_tick_guard (signed countdown-vs-pending
compare, bail on continuation 1, elidable fallthrough body) and
cp_exit_stub (patched architectural pc, patched pending charge against
the countdown, branch to the fetch-tail continuation). The execution test
threads fixed pinned-role values through every chain and verifies
pass-through, both tick-guard outcomes, and the exit stub's pc/cd
updates. 715 stencils validate and pass on native AArch64 and on
amd64 (GCC both sides) under qemu.

## Decided: backend stencil signature (2026-08-20)

Purely positional, no register globals in stencil code. Clang preserve_none
argument order does not skip -ffixed-reserved registers (interpret-tc.cpp
pins starting at x23 for exactly this reason), so the stencil signature
places parameters so the pinned roster falls at its own registers:

  AArch64: (g0 x20, g1 x21, g2 x22, pc x23, countdown x24, fetch x25,
            g3 x26, tcc x27, g4 x28, g5 x0, g6 x1, ...)

pc/countdown/fetch/tcc are pass-through parameters updated where a stencil
semantically writes them (countdown by the exit stub's pending constant,
pc by exits and control transfers). Entry from a TC handler and exit into
the fetch tail are plain branches: the interpreter's pinned registers and
the stencil's parameter registers coincide. x86-64 caps at six register
slots (r12-r15, rdi, rsi shared by GCC and clang), so its signature is a
narrower arrangement of the same roles; decide it when the amd64 backend
lands. Guest cache slot count on AArch64: six to eight from the free
positions, final count set by what the emitter scratch needs.

## Done: increment 1 correctness gates green (2026-08-20)

The engine now boots Linux bit-identically to stock (halt at mcycle
55293806, identical root hash and exit) and passes all 267 machine tests
and both stencil test binaries. Two replay-divergence bugs were found by
bisecting checkpoint hashes to a window, then diffing instrumented event
streams (shadow-TLB fill log, trace entry/record/finish log, trap log)
between the stock and copy_patch builds under identical history.

Bug 1: traces were not page-local. Recording follows execution across a
contiguous guest-page crossing (the fetch segment keeps the mapping
offset constant), so a trace could span pages. Replaying it skips the
fetch at the crossing, and with it the code-TLB replacement the
interpreter performs, and the shadow TLB is hashed state. The symptom was
a single stale shadow code-TLB word. Fix: recording ends before any
instruction not wholly inside the head page. In-trace crossings return in
increment 2 through the validated-entry translation node, which probes
the hot code TLB and bails to the interpreter fetch on miss, preserving
the fill sequence. Entry validation also latches and checks the
translation context (ctx_slot_base) alongside code_vf_offset.

Bug 2: a trap during recording corrupted the exit target. cp_record runs
before its instruction executes, and the stop conditions assigned
rec_end_vaddr = vpc, so when a recorded store page-faulted (demand
paging), the next record call arrived at the trap vector and the trace
was installed with the handler as its straight-exit target. On replay the
page is mapped, nothing faults, and the trace exits into the kernel
vector from user mode (observed as a bogus fetch page fault at stvec,
which shifted execution 469 cycles against stock). Fix: rec_end_vaddr is
maintained as the architectural successor only (fallthrough at
classification, jump target, resolved branch direction), the stop paths
never overwrite it, and a record call arriving anywhere else finishes the
trace with the successor it already holds. The recorded body stays valid
because memory ops are guarded and branch directions validated.

Debug tooling that stays: TLB_FILL_LOG builds also expose TRAP_LOG (env)
printing cause/pc/mcycle at raise_exception; CP_LOG (env, one-time getenv)
prints trace entries, begins, records, and finishes.

Boot statistics after both fixes: 6721 traces installed, 115 heads marked
interpreted, 727 invalidated by the write hook, 0 flushes, 3.1MB emitted,
672k trace entries.

## Done: increment 2, validated call entries (2026-08-20)

Ported from lightning's call_fn (the translation node), read line by line
before writing: probe the hot code-TLB slot of the head page under the
recorded context, require vaddr_page to match the head page and vh_offset
to match the recorded code_vf_offset, establish the fetch mapping (pc and
fetch re-encode, penumbra.fetch_vf_offset, tcc fetch page, pma_index read
from the shadow slot at entry time), and fall into the ordinary entry.
Any miss falls back to the interpreter fetch, whose fill is the hashed
behavior.

The port splits the work differently than lightning because of a C
boundary constraint found in TC_HOOK_CALL: TC_SYNC rewrites the pinned pc
from the handler local after the hook returns, and a countdown expiry
between hook and entry returns to the outer loop, so the pc encoding and
penumbra.fetch_vf_offset must never disagree across any C boundary.
Validation therefore runs in the C hook (context check first, then the
probe), and establishment runs atomically in a generated prologue emitted
before each trace's tick guard. Because the hook only enters when
vh_offset equals the recorded code_vf_offset, every established value is
an install-time constant, so the prologue is three two-hole structural
stencils (two cp_store_imm, one cp_call_establish) with no entry-time
loads. The pma_index publish stays in the hook: safe early, since the
stale fetch tag keeps missing until the prologue re-encodes, and every
miss path recomputes it.

Ordering note flagged while reading the original: lightning's call_fn
establishes the mapping and then reaches the translation-context guard,
whose bail leaves through the fetch tail with the recorded partition's
mapping established even though the current context differs. The cp port
checks the context before establishing anything. Whether the lightning
ordering can skip a current-partition fill on that path was not measured,
only noted.

Gates: boot bit-identical to stock, all 267 machine tests, stencil tests.
Coverage effect on boot: entries 672k to 1408k, 738k of them call
entries; installed 6697, emitted 3.8MB, 0 flushes.

## Done: increment 3, same-page pending links (2026-08-20)

The RVVM block_links analog on the planned allocation-free shape: each
straight trace has one trailing link site (the terminal exit stub's
branch to the island), a pending table open-addressed by successor pc
chains waiting predecessors through link_next, and linking happens when
either end installs. Only same-page successors link, and they retarget
directly to the successor's tick guard. This is sound without vf or ctx
equality checks, unlike lightning's links, because exits are pc-relative
(vf-independent) and cp trace bodies probe the TLB with the runtime
context (lightning bakes the recorded partition into its probes, so its
linked entries need the generated ctx guard). Cross-page successors keep
the island: their fetch fills belong to the interpreter or the validated
call entry.

Mechanics worth remembering: cp_heap_lower drops the icache watermark to
any patched site in already-published code, and cp_finish now protects
and flushes once at the end so link patches ride the same flush. The
write hook severs links into killed traces (retarget to the island); it
pairs unprotect/protect_flush only when no recording is open, because a
mid-recording flush would move the watermark past the open trace's tick
site and later repatches would miss the icache flush.

Gates: boot bit-identical to stock, all 267 machine tests, stencil
tests. Boot: 148 links, 4 severed; entries 1408k to 1405k (linked
transitions skip the hook). Modest by design: most straight traces end
at uncompilable instructions or page crossings, and the coverage machine
for those is the increment 4 lookup tail.

## Done: increment 4, self-validating entries and the lookup tail (2026-08-20)

Two steps, per the cold-paths-stay-behind-exits rule: hot work lives in
generated code, every miss and validation failure exits to the
interpreter, and nothing in a trace touches pc encoding, fetch state, or
the countdown in a way the tail-call interpreter would not.

4a: call-entry validation moved from the C hook into the generated
prologue, making call_fn self-contained like lightning's: a chain of
two-hole structural stencils (cp_cmp_mem_imm for the context guard and
the hot-slot vaddr_page and vh_offset probes, cp_copy_mem for the
entry-time pma publish, then the existing establishment). Every compare
bails to the island with the caller's deposit pc untouched. The hook now
just hands call_fn over.

4b: the RVVM jtlb tail. JALR, C.JR and C.JALR compile as dynamic
terminals with the interpreter's exact semantics ((x[rs1] + imm) & ~1,
link written after the target read, so rd aliasing rs1 is safe): stores,
countdown charge (elided-fallthrough exit stub), cp_deposit_pc re-encodes
the pinned pc as vaddr plus the current fetch_vf_offset (the deposit
execute_jump would produce), then cp_lookup probes the direct-mapped
front cache, (v >> 1) & 255, chaining a hit straight into the target's
self-validating call entry and leaving for the island on miss. The front
cache holds {vpc, call_fn}, filled at install and hook call entries,
purged on kill, reset on flush, with pc = 1 (odd, never an architectural
target) as the empty sentinel. A stale entry degrades to a cold exit,
never wrong execution, because the callee entry revalidates and bails
with the deposit intact.

Chained transitions bypass the hook, so entry statistics no longer see
them; the effect lands in the increment 5 wall-clock protocol instead of
a hot-path counter. Boot evidence the tail is live: empty-marked heads
dropped 115 to 77 (JALR-headed trips now compile), emitted bytes rose to
5.2MB, hook entries dipped.

Gates: boot bit-identical to stock, all 267 machine tests, stencil tests.

## Done: correctness gate on the balanced 13-workload board (2026-08-20)

Protocol: bench-balanced.lua (boot 256 Mi mcycles untimed, run exactly
1 Gi further, root hash at that exact mcycle), images from
scratch/tracing-experiment/images. The copy_patch build (increment 4,
8397c97e) matches a fresh stock build on all 13 workloads: identical
mcycle 1342177280, identical root hash, identical exit reason. The
recorded bench-balanced-3way.txt canon no longer applies to the current
image pair (a stock control reproduced none of its hashes), so the gate
ran against freshly produced stock references.

With boot, the 267 machine tests, and the stencil tests, the correctness
leg of the differential gates is complete. Next: the performance
protocol (repetitions with warmup against the lightning build and the
committed RVVM column, with trace counts, emitted bytes, compile time,
flushes, and coverage reported).

## Done: measured optimization round, RVVM parity mechanisms (2026-08-21)

Counter-driven, each step selected by the previous measurement.

1. Register eviction (the refinement the plan deferred until measured).
   Hash regressed +136 percent; entry counters cleared both storm
   hypotheses (1 percent front-door rejects), exit counters attributed 97
   percent of entries to productive short straight terminals, and the
   formation counters plus the failing-instruction log showed recordings
   dying every 2-10 instructions on ordinary covered opcodes: the
   eighth-distinct-register rule. LRU eviction of unlocked slots (spill
   if dirty) with per-bail slot_guest snapshots fixed it; the first
   attempt lost spilled registers by restoring only the heap cursor in
   the uncompilable rollback, so the allocator bookkeeping is now
   snapshotted and restored with it. Hash went to -52 percent vs stock
   and every workload improved (geomean -44 percent).

2. Probing exits (RVVM parity A). Guard bails with pending > 0 and
   cross-page straight terminals now charge the countdown, load the
   static successor vpc into slot 0, and probe the front cache, chaining
   into the target's self-validating entry; only real misses reach the
   interpreter. Zero-retirement bails must stay cold: only the
   interpreter slow path fills the TLB, so re-entering loops without
   progress (found as a livelock, fixed by routing pending == 0 bails to
   the cold continuation).

3. Dispatcher continuations (RVVM parity B). cp_continue now implements
   RVVM's dispatcher: an installed trace at the exit pc is entered
   through call_fn, a genuine miss trips compilation (return
   continuations and off-path resumption points now form traces), and
   only interpreted-marked heads resume the fetch tail. Validation and
   tick bails route to cp_continue_cold, which never re-enters, so a
   failing entry is attempted at most once per exit.

Gates after each step: boot bit-identical, all 13 workloads identical
mcycle/hash/exit vs fresh stock, 267 machine tests, stencil tests.

Board after A+B (single repetition): geomean -61 percent vs stock,
lightning -62 percent: parity with the full lightning backend. cp wins
qsort (-38 percent vs lightning), zlib (-30), hash (-14), sieve, int64,
tree; parity on nop and branch; behind on regs (+83, 0.229 vs 0.125,
improved from 0.779 by chaining alone), memcpy (+56), syscall (+24),
matrixprod (+15), double (+13). Hash steady state: 20.7k traces, 6.4M
hook entries (from 41.5M), 771k dispatcher enters, 14k dispatcher
trips, one pool flush.

Remaining measured levers, in observed order: loop-carried slots across
the cyclic back edge (regs band, first beyond-RVVM step), immediate-
folded ALU stencils (memcpy band, body length and eviction pressure),
per-block code quality. Stale traces pinned by first-wins heads are
bounded-cost now (one failed entry hop per exit) but flush-only
reclamation remains the policy.

## Done: two soundness bugs flushed out by the cross-emulator matrix (2026-08-21)

The five-emulator matrix (compete harness, a different kernel and a musl
stress-ng) crashed the copy_patch guest 42M cycles into boot: a workload
class the canon never reaches. Both bugs were found by the entry-budget
bisect (CP_MAX_ENTER refuses entries past N, so a hash bisect over N
isolates the exact corrupting trace execution, and CP_PROBE dumps the
register file at the bisected attempt in the with/without pair).

1. Guarded-load destinations leaked into bail stores. load() marked the
   destination dirty at alloc_dst before emit_guarded snapshotted the
   dirty set, so a first-execution TLB-miss bail stored the uninitialized
   slot register into the guest register file. Invisible on hit-and-refill
   paths (the re-executed load overwrites the clobber), architectural when
   the load page-faults, where rd must stay unchanged: musl strlen
   scanning into a demand-paged page. Fix: a freshly bound destination is
   excluded from the bail's dirty set; an aliased destination keeps its
   bit, since its slot still holds the architecturally current value.

2. Same-page links did not prove content equality. A trace recorded at
   the same virtual address in an earlier mapping epoch (another process,
   another host page) stays alive, correctly, because its own host page
   was never written. The link pass patched a new trace's terminal
   straight into that stale body, replaying the old mapping's code. Fix:
   links require successor and predecessor code_vf_offset equality in
   both directions: same page plus same vf proves the same host bytes.
   This corrects the increment-3 note that claimed links need no vf
   check. Lightning's same-page link_fn patching appears to carry the
   same latent assumption and deserves an audit.

Gates after both fixes: compete guests retire identical mcycles to stock
(nop, hash, syscall checked end to end), Linux boot bit-identical, all
13 balanced workloads identical, 267 machine tests, stencil tests.
Debug switches kept: CP_MAX_ENTER (entry budget), CP_PROBE (register
dump at attempt N and N+1), cp-trip/cp-contenter log lines.

## Done: FP-CSR stencil families, the matrixprod lever (2026-08-21)

The measured matrixprod diagnosis (soft-float long-double routines
shattering at their fflags syncs, 15.3M island round trips) is fixed by
extending compilation coverage to the three FP CSRs. Three baked-CSR
wrapper families (csrrw/csrrs/csrrc for fflags/frm/fcsr, plus a shared
read-only family for the rs1=x0 forms, which must not write the CSR),
each instantiating the interpreter's own execute bodies with the CSR
index in the synthetic word. rd=x0 needs no special form: a scratch
destination slot is architecturally invisible.

Two interception pieces in the semantic TU, both the established
pattern: a requires-constrained raise_illegal_insn_exception override
that mutates nothing and reports failure (the FS-off trap becomes the
bail continuation, and the interpreter re-executes and raises
architecturally), and requires-constrained read_csr/write_csr overrides
that dispatch only the three baked CSRs to the interpreter's per-CSR
helpers, failing closed otherwise. The narrowed dispatch exists because
clang would not inline the full CSR switches even under flatten, and
the fail-closed extractor rejected the out-of-line call, exactly as
designed. The selection sends every other CSR to f.end() as before;
satp/mstatus-class CSRs must never compile this way (TLB flushes and
context changes mid-trace).

matrixprod 1.330 to 0.413 (stock 1.628, lightning 1.166): from -17 to
-75 percent vs stock. hash improves slightly, double unchanged (real FP
arithmetic, the separate FP-family lever). Gates: boot bit-identical,
all 13 balanced workloads identical, 267 machine tests, compete guest
mcycle-identical, stencil tests.

## Done: the five-emulator matrix, copy-patch ahead of lightning (2026-08-21)

Full cross-emulator board (bench-harness/compete/matrix5.py, fixed
bogo-ops, one shared musl stress-ng, per-emulator boot baseline
subtracted, 3-rep medians, 78/78 cells, no failures), wall seconds:

    workload    stock  light   cp    qemu-sys qemu-icnt rvvm
    boot         0.14   0.15  0.17    0.37     0.37     0.11
    nop          4.10   0.45  0.43    0.43     0.61     0.52
    regs        13.84   1.98  3.51    1.74     1.87     1.24
    branch       0.75   0.75  0.92    2.99     3.04     1.43
    tree         2.57   2.00  1.85    2.85     2.87     1.29
    qsort        3.94   2.45  1.69    3.45     3.57     1.32
    memcpy       7.85   2.47  3.57    4.95     5.46     1.42
    zlib         9.06   4.80  4.21    3.93     4.15     2.10
    hash         4.95   2.58  2.13    1.79     1.92     1.90
    syscall      1.03   0.48  0.50    0.78     0.82     0.55
    double       1.79   1.58  1.85    1.66     1.67     3.26
    sieve       11.88   2.09  2.45    1.70     2.05     1.75
    int64        2.86   1.56  0.89    2.18     2.26     0.34
    matrixprod   3.60   2.25  1.31    2.27     2.37     0.83
    geomean      3.80   1.63  1.57    2.00     2.17     1.17

Copy-patch leads lightning for the first time (geomean 1.57 vs 1.63),
wins seven workloads against it outright (nop, tree, qsort, zlib, hash,
int64, matrixprod), and beats qemu-system across the board. RVVM's
remaining lead (1.17) concentrates where lightning also leads cp: the
register-carry band (regs, sieve, partly memcpy) and FP arithmetic
(double). Boot: cp 0.17 vs stock 0.14, the compile-on-first-miss volume
finding, still open.

Remaining measured levers, unchanged in ranking: loop-carried slots
across the cyclic back edge, FP arithmetic stencil families (the
mechanism the CSR families just proved), immediate-folded ALU, boot
formation volume.

## Done: loop-carried slots, mechanism landed, reach measured (2026-08-21)

The emission-log replay: every body emission is logged (stencil, two
immediates, guard ownership, hoistable-load marker; 128KB formation
scratch, rolled back with the per-instruction snapshot), and an eligible
cyclic close discards the first-pass tick and body and re-emits with
first-use loads hoisted to a preheader, fresh loads synthesized for
write-only registers (every guest-bound slot holds its architectural
value at the tick), the tick guard after the preheader with a bail block
that publishes the cumulative dirty set, all body bails switched to the
cumulative set under the (stable, by eligibility) final mapping, and a
back edge that only charges the countdown and re-checks the tick. The
slot registers carry across iterations in the pinned contract;
per-iteration memory traffic drops to zero.

Eligibility is guest/scratch slot-set disjointness: a preheader-loaded
value must survive the whole body, and an eviction spill would republish
stale slots on later iterations. alloc_scratch now prefers reusing a
freed scratch slot over consuming a fresh one, keeping scratch churn
confined and fresh slots available for guest bindings. cp-nocarry log
lines name the disqualifier.

Gates: boot bit-identical, all 13 balanced workloads identical, 267
machine tests, stencil tests. Board times neutral to slightly better;
about 215 traces carry per workload.

Measured reach, the fork for the next step: the flagship loops do not
qualify. memcpy's and sieve's hot loops bind an eighth distinct guest
register (guest-rebind), beyond any 7-slot contract; the lever is slot
capacity (aarch64 preserve_none has five unused argument positions, so
NSLOTS could go 7 to 12 at about 5x stencil-table growth; amd64 stays
narrow). regs' and int64's hot loops fragmented across installed heads
into linked two-trace cycles the carry cannot see; the lever is
pass-through recording (lightning's starved-head lesson) or carrying
across same-page links.

## Done: constant compaction in the emitter (2026-08-21)

The seam-glue diagnosis against RVVM: our linking reproduces theirs (a
loop that does not single-trace-cycle degrades to RVVM's own
linked-block shape), but every patched constant costs a 4-instruction
movz/movk chain where RVVM's emitter pays one instruction, and on tight
linked loops the seams are the workload. cp_emit now compacts: a movk
whose 16-bit field is zero only re-clears bits the chain's movz already
zeroed, so it becomes a NOP (sizes and offsets unchanged, so no patch
bookkeeping moves). cp_repatch_imm skips compacted sites, sound because
repatched holes only carry values below 2^16 (the tick pending).

Board effect: 3 to 7 percent across the seam-bound band (regs 0.230 to
0.214, hash 0.571 to 0.550, sieve 0.314 to 0.301), about 30 lines.

A/B against the loop-carry mechanism (CP_NO_CARRY switch, both sides
with compaction): carry contributes memcpy ~5, hash ~4, sieve ~2.5,
int64 ~1 percent, regs nothing (its loop never qualified). Honest
verdict: compaction alone captured a comparable share of the day's win
at a fraction of the machinery; the carry is the substrate the capacity
or pass-through fork would make pay, and stays pending that call.

Gates: boot bit-identical, all 13 balanced workloads identical, 267
machine tests.

## Done: CP_NSLOTS build parameter, 10 slots on aarch64 (2026-08-21)

Slot demand was measured before choosing the number: the hot loops that
disqualified from loop carry need 8-10 slots (memcpy ~8, sieve 8-9, the
regs/int64 fragment unions 8-10), and nothing measured wants 12. The
guest cache slot count is now a per-arch build parameter threaded
through the generator (slot names generated past the pinned roster into
the free aarch64 preserve_none positions), the extractor (family
patterns and table dimensions, fail-closed against out-of-range
indices), one header define with a 7 default, and the two stencil test
binaries. Callers are unaffected: extra slot registers arrive as
garbage at entry and are defined before use, exactly like the old tail
slots. aarch64 builds at 10 (2.9x tables, full pipeline rebuild 36s);
amd64 keeps 7 until its contract lands.

Effect: memcpy's and sieve's hot loops flip carry-eligible, including
sieve's 75-instruction body (memcpy 0.388 to 0.375, sieve 0.301 to
0.286, hashes identical). regs and int64 unchanged, confirming their
blocker is fragmentation across installed heads, the pass-through
fork, not capacity.

Gates: boot bit-identical, all 13 balanced workloads identical, 267
machine tests, stencil tests at the widened contract.

## Done: fused call prologue, current-context probe (2026-08-21)

The seam analysis against RVVM split the ~45-instruction call prologue
into a per-transit irreducible core and compile-time data materialized
badly. Both fixed at once: the emitter's immediate-hole budget went
from two to four (cp_imm64_2/3, format-agnostic ordinals), and the
seven-stencil validate-and-establish chain collapsed into two fused
stencils. cp_call_probe probes the hot code-TLB slot of the CURRENT
translation context (the interpreter's own per-transit fetch probe,
reproducing its hashed fill sequence; the vh compare supplies content
identity), re-encodes the pc from the incoming deposit (vpc plus caller
vf, the universal entry convention, so no pc hole), publishes the
mapping base-relative, and hands the computed slot index to cp_call_pma
in slot r0 (dead at entry) for the shadow pma publish. Probing the
current partition also removed the recorded-context equality
restriction: a same-content entry from another context now legally
hits, exactly as stock would.

Layout facts baked as generator literals (slot sizes, the
vf-next-to-ctx adjacency, two tc_context offsets) are pinned by
static_asserts next to the emission, so drift fails the build; the
first build did exactly that and the asserts caught the wrong guess.

The call-heavy band moved 10-15 percent: int64 0.377 to 0.333, qsort
0.786 to 0.693, matrixprod 0.413 to 0.352, syscall 0.514 to 0.461,
hash 0.550 to 0.532. Gates: boot bit-identical, all 13 balanced
workloads identical, 267 machine tests, stencil tests.

## Done: 1024 MHz guest clock as default (2026-08-21)

The old 1024 MHz experiment (tail-call.md item 19) was remeasured on
the current tree because its conclusion was stale: the ~4 percent it
found was measured while SUM-toggle flush storms dominated, and those
have since been fixed by the context-partitioned TLB. The remeasured
tick cost stands on its own: cp at 1024 MHz gains a consistent ~4
percent geomean over cp at 128 MHz (nop -15, regs -7.9, tree -6.7,
matrixprod -4.2, hash -3.7), stock gains similarly, and the
correctness story is complete on the forked canon: stock and
copy-patch are bit-identical to each other at 1024 MHz through boot
(halt 55407040) and all 13 balanced workloads, and both pass the 267
machine tests. RTC_CLOCK_FREQ_DEF is now 1024000000 by default.

Consequences, stated plainly: machine state hashes change (the DTB
advertises timebase-frequency = clock/divisor, now 125000), so every
fixed-cycle hash recorded earlier in this campaign describes the
128 MHz machine. uarch.bin, the solidity step and risc0 verify_step
stay consistent as long as they build from the same tree, since the
constant has a single source. Downstream artifacts that pin machine
template hashes see this as a breaking canon change.

Found along the way and committed separately: stock builds were
running the stencil pipeline through an unconditional interpret-tc.o
dependency, and a failed extractor run there could leave a stale
cartesi.so to be mistaken for the fresh build. The pipeline is now
gated behind copy_patch and CP_NSLOTS is defined unconditionally.
Build-log checks must grep make-level Error, not only compiler
error lines; the miss briefly mislabeled a binary in this experiment.

## Done: the matrix at the 1024 MHz default (2026-08-21)

Full five-emulator board rerun at the new default clock, all three
cartesi columns rebuilt and mutually hash-verified on the new canon
(78/78 cells, 3 reps, medians, wall seconds):

    workload    stock  light   cp    qemu-sys qemu-icnt rvvm
    boot         0.14   0.14  0.17    0.36     0.37     0.11
    nop          4.06   0.40  0.38    0.44     0.63     0.52
    regs        13.70   1.89  3.32    1.77     1.90     1.26
    branch       0.74   0.72  0.87    3.03     3.14     1.47
    tree         2.58   2.16  1.80    2.89     3.16     1.35
    qsort        3.90   2.49  1.43    3.52     3.61     1.36
    memcpy       7.80   2.54  3.66    5.05     5.52     1.42
    zlib         8.87   4.84  3.97    4.01     4.20     2.10
    hash         4.90   2.44  1.99    1.96     2.22     1.94
    syscall      1.04   0.47  0.48    0.81     0.84     0.56
    double       1.79   1.63  1.82    1.71     1.69     3.28
    sieve       11.64   2.18  2.14    1.75     2.07     1.85
    int64        2.85   1.55  0.75    2.23     2.26     0.34
    matrixprod   3.58   2.39  1.19    2.30     2.35     0.83
    geomean      3.77   1.62  1.46    2.06     2.23     1.19

Copy-patch: geomean 1.46 (was 1.57 at 128 MHz), ahead of lightning on
nine of thirteen (sieve flipped), fastest emulator in the matrix on
nop, three-way parity with qemu-system and RVVM on hash, within 5
percent of RVVM on qsort. RVVM's remaining lead concentrates in regs
and memcpy (the pass-through fragmentation case) and the int64 and
matrixprod tails (in-block density).

## Done: nop compilation and chain-start entries (2026-08-21)

The regs diagnosis, driven entirely by measurement and corrected once
by it. Sampling attributed 21 percent of compete-regs time to the
interpreted C_MV handler; the first theory (241 canonical-nop
uncompilable ends shattering traces and marker-poisoning heads) was
implemented and smoke-tested: correct, hash-clean, kept (rd0
arithmetic now records as an architectural no-op, nothing emitted,
retirement accounted), but regs did not move and C_MV stayed at 194
samples, so the theory died.

The counters then closed the real chain: compete regs shows
tick-bails 2,065,180 against 16.9G / 8192 = 2.06M chains, exactly one
tick bail per chain (the divisor still bounds device polls at the new
clock). The pathology is after the bail: the outer loop started every
fresh chain with no entry check, so straight-line code re-interpreted
through its own installed traces once per chain, and stress-regs is
one huge straight-line body.

Fix: the outer loop's chain start probes cp_hook_site<call> at the
resume pc and dispatches into the returned self-validating call entry
instead of the jump table, tripping compilation on a genuine miss
with the pc unchanged. One seam, the handler entry pattern verbatim,
one hash probe per chain.

Measured: interpreted C_MV samples 194 to 67, compete regs 3.42 to
3.22s (mcycle identical), installed traces 14.6k to 24.2k as the
formerly invisible stretches compile. That overflowed the 16384-trace
pool once mid-run (one flush): max_traces is now a measured dial for
the list. Gates: boot bit-identical, all 13 balanced workloads
identical, 267 machine tests, stencil tests.

## Open decisions
- Whether the pc-to-trace cache keys on virtual pc + mapping validation
  (current exact-map shape, notes say keep) with a direct-mapped front
  cache like RVVM's jtlb.

## Done: x86-64 native execution -- the positional contract never crossed architectures (2026-08-21)

First native x86-64 run of the backend (Linux, gcc-16, the same tip as the
five-emulator board). It had never worked: the first entry into generated
code corrupted the guest pc and mcycle, measured down to a c.addi immediate
surfacing as the guest pc (trip fast-pc 1 and -16, host-shaped vpc after
the vf conversion). The self-tests missed it because they call stencils
directly with the full twelve-parameter signature; the board missed it
because it ran on AArch64.

Two independent defects, both against the positional stencil contract:

- Register positions. The contract places pc at position 4, countdown at
  5, fetch tag at 6 so that on AArch64 they coincide with the pinned
  roster (x23, x24, x25) and every transfer is a plain branch. On x86-64
  nothing is pinned and the state travels as arguments: every interpreter
  signature places pc at position 3, where the stencils read guest cache
  slot r1. Verified against cp_store_exit's disassembly: positions 1-6 are
  r12-r15, rdi, rsi under GCC preserve_none, positions 7-12 are stack.
- Stack positions. A musttail branch from the interpreter provides no
  argument area, so stencil positions 7-12 aliased the suspended
  interpreter frames: guest cache slots r2-r6 and every stencil's
  pass-through stores read and wrote live interpreter locals. TC_PAGE_
  SEGMENT experiments only moved the first failure (cycle 68 to 45222)
  because they permuted which garbage landed where.

Fix (x86-64 only, AArch64 untouched): trace entry is a normal call through
the full stencil signature (cp_enter_call), which allocates a private
argument area at the stack positions, so all seven guest cache slots stay
legal; the exit islands land on bridges of the stencil signature
(cp_continue_bridge, cp_continue_cold_bridge) that fold the roster back
into the interpreter chain, whose eventual return unwinds to the call
site. Trace-to-trace links and the front-cache lookup tail remain
stencil-level branches; stack depth is bounded by the entries in one tick.

Second blocker, the W^X fallback: without MAP_JIT's per-thread toggle the
generic path flips the whole heap RW/RX per formation and issues a
SYNC_CORE membarrier. strace: 26652 mprotects, 3.7 of a 4.0 second boot.
The x86-64 heap is now permanently RWX (no icache on x86; own-thread
stores are seen after the branch to published code; migration serializes
at the context switch). Boot 0.56s against stock's 0.47s.

Gates: boot halts at mcycle 39633495 bit-identical to stock and lightning;
all 13 balanced workloads retire identical mcycles and root hashes against
stock, run twice (before and after the heap change); both self-tests pass.
Native x86-64 cp-vs-lightning numbers follow in the next entry.

## Done: first native x86-64 board -- cp trails lightning at 1.26x, wins the lightning pathology rows (2026-08-21)

Same tree, gcc-16, repo bench.lua fixed-work protocol (boot untimed, 1<<30
mcycles timed), 3 reps interleaved, medians; 117/117 cells, all builds and
reps retiring one mcycle+hash per workload.

    workload    stock  light   cp    cp/light
    nop          1.61   0.09  0.11    1.24
    regs         3.00   0.39  1.00    2.58
    branch       3.30   3.08  3.28    1.06
    tree         8.38   6.90  8.41    1.22
    qsort        4.17   2.93  2.92    1.00
    memcpy       3.35   0.74  1.56    2.11
    zlib         3.86   2.71  2.61    0.96
    hash         3.59   1.49  2.07    1.39
    syscall      3.85   1.47  2.19    1.49
    double       7.76   6.58  7.94    1.21
    sieve        3.28   0.79  1.30    1.64
    int64        4.19   1.78  1.71    0.96
    matrixprod   4.36   3.17  1.87    0.59
    geomean      3.89   1.54  1.94    1.26

Unlike the AArch64 board (cp 1.57 vs light 1.63, cp ahead), lightning
leads by 26% here: the x86-64 lightning carries the whole register-ranking
campaign and its register-carry band (regs 2.58x, memcpy 2.11x, sieve
1.64x) is where cp loses. Where cp wins or ties is exactly where lightning
is known to leave time on the table: matrixprod 0.59x (the cyclic-
truncation foreclosure; the AArch64 board shows the identical ratio,
1.31/2.25 = 0.58, a strong functional-equivalence check on the port), and
zlib 0.96x / qsort 1.00x / int64 0.96x -- the three side-exit-blacklist
workloads of bench-harness/xmap/SIDE-EXIT-BLACKLIST.md, where lightning
escapes generated code through never-linked hot side exits. cp has no
blacklist machinery to hit; its RVVM-style compile-on-miss covers those
paths.

Not established: whether the 1.26x gap is the call-based entry's cost or
the missing register-carry optimizations -- separating those needs a
per-entry counter A/B, not run here.

## Done: lightning emission-graceful truncation -- the four-build board (2026-08-21)

The residual layer under the (already upstream-fixed) side-exit starvation:
compile aborts that permanently blacklisted heads were measured with a
per-site failure-reason tag as emission-only failures -- 36/44 scratch-stack
exhaustion on the staged atomics' RMW trees, 8/44 OP-FP guard-bail exits the
discovery budget does not count -- plus sub-floor truncations ahead of
CSRRS time / FENCE. Fix (`10d2226e` + `44a1068d`): the emission pass
truncates at the failing entry and recompiles the prefix, straight traces
only; floor 2 by measurement (floor 8 concentrates a +26% cost on syscall's
kernel-AMO seam; a reason-3-only gate loses matrixprod's win).

Final board, bench.lua fixed work, 3-rep medians, 156+39 cells, every
build and rep retiring one mcycle+hash per workload:

    workload    stock  light  light-fix   cp    fix/base
    nop          1.59   0.09   0.09      0.12    1.011
    regs         2.99   0.38   0.38      1.00    1.008
    branch       3.36   3.03   3.03      3.26    0.999
    tree         8.68   7.01   7.37      8.56    1.051 (reps overlap)
    qsort        4.16   2.92   2.97      3.04    1.018
    memcpy       3.40   0.75   0.77      1.54    1.032
    zlib         3.72   2.55   2.52      2.75    0.987
    hash         3.59   1.51   1.48      2.01    0.980
    syscall      3.95   1.42   1.46      2.21    1.027
    double       7.53   6.56   5.50      7.82    0.839
    sieve        3.26   0.79   0.81      1.32    1.032
    int64        4.05   1.76   1.76      1.69    1.001
    matrixprod   4.11   3.25   1.54      1.92    0.474
    geomean      3.86   1.53   1.44      1.96    0.942

matrixprod 2.1x: its FP fragments used to abort whole; the truncated
prefixes now publish (this closes most of the tail-call.md item 22 gap from
the truncation side, without touching the cyclic policy). double -19% is
the reason-3 recovery. Fixed lightning now leads every backend on this
host, including cp on all four rows cp had taken from it.

Filed, not done: a depth-restart spill in emit_expression would let the
atomics' trees compile whole (no seam at all -- the syscall/memcpy tension
dissolves instead of being balanced); the prototype emitted wrong addresses
and was reverted, so it needs the full gate battery and a disassembly pass.

## Done: clang x86-64 bring-up on macOS, gated under Rosetta (2026-08-21)

The x86-64 backend fixes were developed and gated on Linux with GCC. This
entry ports the pipeline to clang targeting x86-64, cross-built on the
arm64 macOS host and executed under Rosetta, which is also the first time
the full gate battery ran for x86-64 on this machine.

One invocation now works end to end (the Makefile derives the target from
the compiler, not the host uname, for the pin flags, the slot count, and
the stencil cross target):

    make CC="clang -arch x86_64" CXX="clang++ -arch x86_64" slirp=no \
        PTHREAD_CFLAGS= PTHREAD_LDFLAGS= tailcall=yes copy_patch=yes \
        cartesi.so test-cp-stencils

What the port surfaced, each caught fail-closed by the extractor or the
compiler, none reachable by the aarch64 or the Linux GCC builds.

- clang folds value-position hole reads into sign-extended imm32 operands
  (a store immediate in cp_call_probe surfaced first) even with the
  large-model attribute on the hole symbols. GCC's medium-model large-data
  path never folds. Every value-position hole read in the generated source
  now goes through CP_VAL, an empty-asm register pin on x86 and identity
  elsewhere. The aarch64 stencil bytes are unchanged.
- clang's register allocator cannot compile the far-jump and lookup
  stencils at seven guest slots (twelve positional register arguments plus
  the probe temporaries exceed the fifteen usable GPRs, and musttail
  forbids the spills GCC places in the red zone). The clang x86-64 default
  is now six slots. GCC keeps seven.
- The semantic TU on macOS is Mach-O x86_64, which the extractor did not
  speak. It now parses the branch relocations (rel32 jmp/jcc with a zero
  stored field, recorded with the ELF minus-four addend the runtime
  patcher applies), accepts prefix-stacked long-NOP subsection fill, and
  sizes stencils whose cold blocks sit past the terminal branch (the idiv
  zero path) to the symbol limit instead of the last relocation.
- The exit bridges' musttail from the twelve-parameter roster into the
  five-parameter handler signature is a GCC-only liberty. They now tail
  through a copy of their own signature with the handler's five arguments
  moved into the leading positions, which both compilers accept.
- cp_enter_call inlined into preserve_none handlers starves clang's
  allocator the same way. It is now out of line, one plain-convention
  frame per entry.
- The chain-start dispatch postdates the Linux fix, so its entry into the
  self-validating call entry now routes through cp_enter_call under the
  same CP_CALL_ENTRY gate.
- Both stencil tests hardcoded a seven-slot roster. Guest-value arrays are
  now padded to at least seven entries (inert beyond the slot count) and
  the fixed program clamps its slot indices.

Gates, all under Rosetta on the arm64 host. cp-stencils-test (500 random
programs) and cp-machine-test pass. Boot halts at mcycle 55407040,
bit-identical to the aarch64 canon, and all 13 balanced boards retire
identical mcycles and root hashes against the same stockcmp canon the
aarch64 build gates on, which exercises the guaranteed cross-host
determinism directly. All 267 machine tests pass. The native aarch64
battery was rerun after every shared-source change and stays green
(boot 55407040, 13 boards, both stencil tests).

Rosetta timing is meaningless (translated JIT output), so no board is
recorded. Native x86-64 numbers stay owned by the Linux campaign.

## Done: probe memoization falsified; slot count is the real regs lever (2026-08-21)

Two results, one measurement campaign.

### Probe memoization: built, gated, measured net-negative, parked

The memory-carried form went in whole: capture stencils store the
{vaddr, vh_offset} pair to a per-set penumbra slot after a proven hot
hit, cached accesses reach the pair from the state access at a fixed
offset (no patched address, so the semantic TU stays hole-free, which
Mach-O extraction requires) and guard with tlb_is_hit's exact folded
compare, per-set streams starting on the second consecutive same-base
access. One mechanism on both architectures. Fully gated: 13 boards
hash-identical, 267 machine tests, stencil tests, boot canon.

Attribution with an env kill-switch on the same 16-slot binary
(balanced boards, medians of 3):

    workload   memo on   memo off
    int64      0.337     0.323     (+4% cost)
    regs       0.129     0.131     (1.5% gain)
    memcpy     0.365     0.364     (flat)

The cost is not guard-failure bails (mem-bails 199376 -> 199907 of 890k
entries); it tracks the +3.7% emitted code and the captures executing
per iteration in hot cyclic bodies. The premise -- the 13-instruction
probe at 62% of the regs store bursts -- was measured before the
chain-start entries and did not survive them: the profiled hot regs
trace today has no probes at its hot offsets at all. Net loss, so the
work is parked on branch cp/probe-memo-parked (commit message carries
the numbers). If revisited, hoist captures into the loop-carry
preheader so cyclic bodies stop paying them per iteration.

### The regs bottleneck is slot-eviction churn; AArch64 default now 16

The same profile shows the hot regs trace (37% of samples, len 256) is
a repeating str/ldr pair against the guest x-file around every ALU op:
stress-ng regs keeps ~30 guest registers live against the 10-slot
cache, so every instruction pays a spill and a fill. The slot count is
a build parameter, so the sweep was direct (balanced regs, medians):

    slots   regs    notes
    10      0.199   old default
    12      0.209   dead zone: the working set still misses and the
                    allocation shifts
    14      0.130
    16      0.128   new default; tree and memcpy a hair better, the
                    rest flat, formation evictions 78845 -> 17843

All hashes identical at every count. amd64 cannot follow: its
preserve_none argument registers bound the roster at 6 slots under
clang (register allocation fails above) and 7 under GCC, so its
default stays put and the churn ceiling remains there; the first
amd64 lever if it matters is restructuring the far-jump and lookup
stencils to branch through memory so clang reaches 7.

Both test harnesses previously hardcoded rosters (first seven, then
ten slots); they now derive slot positions from the count and name all
sixteen entry arguments, inert beyond the built count, with a loud
error above sixteen.

### Found in passing: the chain-start entries regressed branch by 67%

Retiming the full board surfaced branch at 2.07 against its 1.27
record. Bisection by rebuild: the commit before the chain-start
entries (matrix record) runs branch at 1.24 on today's host; every
build after them runs ~2.07 regardless of slot count or memoization.
The chain-start change was gated on hashes and a regs smoke only, and
the recorded matrix predates it, so the regression shipped unmeasured.
Not caused and not touched by this commit; investigation pending (the
suspect is the per-chain-start probe cost on a workload that breaks
chains constantly).

Final board on this commit (16 slots, no memoization, medians):
regs 0.132, int64 0.323, memcpy 0.365, tree 1.912, syscall 0.414,
qsort 0.679, nop 0.027, with syscall and qsort also improved against
their records and branch carrying the pre-existing regression above.

## Done: matrix rerun at the 16-slot tip -- cp geomean 1.57 -> 1.46 (2026-08-21)

Full five-emulator rerun (compete protocol, fixed musl stress-ng
bogo-ops, boot-subtracted, medians of 3, all columns fresh on the same
host state):

    workload     cp-new  cp-old   light    rvvm    qemu  icount
    nop            0.38    0.43    0.40    0.52    0.44    0.63
    regs           3.32    3.51    1.89    1.26    1.77    1.90
    branch         0.87    0.92    0.72    1.47    3.03    3.14
    tree           1.80    1.85    2.16    1.35    2.89    3.16
    qsort          1.43    1.69    2.49    1.36    3.52    3.61
    memcpy         3.66    3.57    2.54    1.42    5.05    5.52
    zlib           3.97    4.21    4.84    2.10    4.01    4.20
    hash           1.99    2.13    2.44    1.94    1.96    2.22
    syscall        0.48    0.50    0.47    0.56    0.81    0.84
    double         1.82    1.85    1.63    3.28    1.71    1.69
    sieve          2.14    2.45    2.18    1.85    1.75    2.07
    int64          0.75    0.89    1.55    0.34    2.23    2.26
    matrixprod     1.19    1.31    2.39    0.83    2.30    2.35

    geomeans: cp 1.46 (recorded prechain 1.57), light 1.62, rvvm 1.19,
    qemu-system 2.06, qemu-icount 2.23. cp beats lightning on 8/13.

Two reconciliations against the balanced-board findings, both traced to
the fact that the two protocols run different stress-ng builds (the
compete matrix runs a static musl binary, the balanced boards run the
rootfs build), whose stressor kernels differ:

- The chain-start branch regression is confined to the rootfs branch
  stressor. The compete branch actually improved (0.92 -> 0.87) and
  keeps its standing: ahead of rvvm (1.47) and qemu (3.03), behind
  lightning (0.72), exactly as before. The balanced-board +69% remains
  real and pending, but it is not a competitive-row loss.
- The slot raise barely moves the compete regs (3.51 -> 3.32): the musl
  regs stressor does not have the rootfs build's ~30-register working
  set, so its 1.75x gap against lightning (3.32 vs 1.89) is NOT
  eviction churn and still lacks a profile-backed diagnosis. The
  balanced regs win (0.199 -> 0.128) stands for the rootfs build.

The broad wins (qsort 1.69 -> 1.43, sieve 2.45 -> 2.14, int64
0.89 -> 0.75, matrixprod 1.31 -> 1.19, zlib, hash, tree, nop) come from
the chain-start entries plus the slot raise combined; memcpy gave back
a little (3.57 -> 3.66). Remaining lightning losses: regs, memcpy,
double, branch, syscall (by a hair). rvvm still leads the geomean.

## Future FP avenue: integer-valued JavaScript numbers

Add a V8-like benchmark whose hot arithmetic operands are boxed FP values
but remain exact integers. The current zero-or-normal/result guard is safe,
but it does not exploit this common narrower domain. Compare two candidate
specializations against the existing guarded hard-FP path:

- classify both input bit patterns as exactly representable integers and
  validate the result the same way;
- clear and test the host inexact status around the candidate operation.
  AArch64 exposes cumulative inexact as FPSR.IXC; SSE/AVX exposes it as
  MXCSR.PE. Preserve the caller's complete status on both paths.

Measure the status-register traffic explicitly. AArch64 needs FPSR system
register reads/writes and amd64 normally needs MXCSR memory transfers, so a
per-operation exact-flag probe may cost more than bit classification. Keep
this out of the default guard until the benchmark establishes the profitable
shape and threshold on both hosts.

## Done: full AArch64 matrix after guarded FP coverage (2026-08-23)

Commit `bcca04f1`, compete protocol, fixed musl stress-ng bogo-ops,
boot-subtracted, three interleaved repetitions. All 234 workload samples
completed; there were no failed cells. The three freshly built Cartesi
columns also smoke-booted to the same mcycle (39580227). Median seconds:

    workload      stock  light     cp  qemu-sys  qemu-icount  rvvm
    nop            5.585  0.394  0.370    0.467        0.635  0.516
    regs          13.417  1.891  2.002    1.784        1.913  1.263
    branch         0.950  0.738  1.165    3.041        3.050  1.468
    tree           2.616  2.099  1.796    2.938        2.964  1.318
    qsort          3.969  2.485  1.478    3.542        3.617  1.270
    memcpy         9.544  2.440  3.303    5.036        5.537  1.423
    zlib           8.171  4.771  3.893    3.940        4.196  2.108
    hash           5.938  2.505  1.810    1.826        1.932  1.913
    syscall        1.097  0.471  0.476    0.827        0.838  0.553
    double         1.667  1.598  1.794    1.675        1.718  3.272
    sieve         13.509  2.178  2.142    1.725        2.046  1.776
    int64          3.976  1.545  0.777    2.207        2.245  0.335
    matrixprod     3.684  1.569  1.125    2.275        2.398  0.838
    geomean        4.193  1.563  1.408    2.052        2.200  1.177

CP beats Lightning on 8/13 workloads. The rerun resolves the old CP process-
population anomaly in favor of the separately reproduced values: regs is
2.002 rather than 3.322 and branch is 1.165 rather than 0.874. Against the old
matrix CP also improves memcpy 9.6 percent, hash 9.2 percent, and matrixprod
5.6 percent. Compete double moves only 1.3 percent (1.818 to 1.794), so the
6.3 percent fixed-cycle rootfs A/B does not transfer to this musl stressor.

Build SHA-256 identities: stock
`f6098625a4b3762ab7ca0198cfdadfc594729214a4e0d4e1e5a716d04c6b55c4`,
Lightning `3fe1454589c0824e0b77ca5900a8dd7734bd32ab4d6f0d0d37ec1c6ef3b09220`,
CP `3ba9b1ba6eb519693474cd064d94ef4809eb4e0ed865871409dd66109ec646f4`,
and RVVM
`08a8e42949caa7e904ee78af8dcc2131f666b9de439e7411f774cec8d8744bcb`.
The refreshed raw result file SHA-256 is
`1129939d6f5e74c7c327cfe6afe34dd3a18e92288b38fc83f5e00d178d654acf`.

## Rejected: chain-start front-cache pre-check (2026-08-23)

Tested a direct lookup in the existing 256-entry `{vpc, call_fn}` cache before
the exact head map, with a same-binary `CP_CHAIN_FRONT_DISABLE=1` control.
Compete boot-subtracted medians of three interleaved repetitions were branch
1.130 vs 1.165 seconds (3.0 percent better), while regs, qsort, and sieve moved
less than 0.3 percent. On the rootfs fixed-cycle board, however, branch was
2.062 vs 2.053 seconds: no recovery on the stressor where chain-start entry
caused the large regression. All mcycles and root hashes matched.

Temporary counters measured only 37.8 percent positive-cache hits on rootfs
branch and 51.6 percent on compete branch. Misses pay both the new probe and
the unchanged map lookup. Negative entries for interpreted heads added only
23 hits on rootfs and none on compete. They also require a callable miss-island
sentinel because generated lookup stencils consume the same cache and jump to
every matching entry.

No code was retained. The simple pre-check is falsified; another chain-start
optimization must remove or throttle the full-map miss path rather than put a
mostly-missing lookup in front of it.

## Rejected: direct cross-page successor links (2026-08-23)

Linked a trace ending at a guest-page boundary directly to an already compiled
successor through its `call_fn`. The same-binary control showed no useful win:
memcpy was 3.339 seconds with linking disabled and 3.328 enabled, while boot
regressed by about 0.10 seconds. Counters confirmed that the links worked
(terminal exits 506385 -> 426533 and lookup misses 358206 -> 345769), but the
saved dispatch traffic did not repay the added formation and boot cost. All 13
fixed-cycle workloads retained identical mcycles and root hashes. No code was
retained.

## Done: semantic direct ADDI/ADDIW stencils (2026-08-23)

ADDI, ADDIW, and their compressed forms now patch the guest immediate directly
into a semantic stencil instead of emitting `li scratch` followed by a
register-register add. The generator instantiates the existing interpreter
`execute_ADDI` and `execute_ADDIW` bodies with a sentinel immediate. Extraction
accepts only the exact AArch64 ADD/SUB-immediate or amd64 ADD/LEA-imm32 compiler
shape and otherwise fails the build. There is no handwritten host implementation
of the guest operation. `CP_IMM_DISABLE=1` retains the old two-stencil path as a
same-binary benchmark control.

Rootfs fixed-cycle same-binary medians, boot-subtracted, were memcpy 3.302 ->
3.102 seconds (-6.1 percent), int64 0.768 -> 0.742 (-3.4 percent), and matrixprod
1.143 -> 1.128 (-1.3 percent). On the balanced 13-workload gate, every candidate
run reached mcycle 1342177280 with the baseline root hash and stop reason.

Coverage includes every source/destination slot combination at both widths and
the signed-immediate boundaries -2048, -1, 0, 1, and 2047: 2560 direct cases on
AArch64 and 360 on amd64, followed by the existing randomized stencil and
machine differential tests. Extraction validated 136366 AArch64 and 10202 amd64
stencils.
## Done: the semantic stencil TU needed the interpreter's FP flags (2026-08-23)

Guarded floating-point execution added the FP sqrt stencil families, and on
Linux/x86-64 with GCC the copy-patch build stopped working entirely:

    cp-extract: cp_fp_sqrt_s_rne_0: JMPREL32 to unexpected symbol sqrtf

CP_SEMANTIC_CXXFLAGS never inherited `-fno-math-errno`, so GCC compiled the
hard-float sqrt body as a call into libm. The call is neither a continuation
nor an immediate hole, so the extractor has nowhere to put it. The
requirement was already written down one block up in src/Makefile, on
INTERPRET_CXXFLAGS: "bare sqrt instructions without errno bookkeeping". The
semantic TU simply never got the flags. AArch64/clang emits the instruction
inline and never produced the relocation, which is why this survived to here.

Fixed by giving CP_SEMANTIC_CXXFLAGS both `-ffp-contract=off` and
`-fno-math-errno`. All 14994 stencils validate again.

### Falsified: contraction was not costing the FP rows

The x86-64 compete board recorded matrixprod as a 1.51x loss to lightning,
where it is cp's signature win elsewhere (0.50 on the AArch64 compete board,
0.59 on the earlier x86-64 bench.lua board). The obvious suspect was the
`-ffp-contract=off` just added: it forbids FMA fusion in the semantic
stencils, and matrixprod and double are exactly the two FP-heavy rows that
regressed. A/B against a cp build carrying `-fno-math-errno` alone, same
host, same guest work:

    workload      -ffp-contract=off   errno-only   mcycle
    double              5.314            5.453     854657094  (both)
    matrixprod          4.230            4.237     2415138991 (both)

matrixprod is flat to 0.007s and double is marginally *slower* without the
flag. Identical mcycles confirm the work is the same. Contraction is not the
mechanism and the correctness flag is free; keep it.

Note for the AArch64 side: those stencils are presumably still built without
`-ffp-contract=off`, so their arithmetic may contract where the interpreter's
does not. That is a correctness question there, not a performance one, and it
is unmeasured.

What still explains matrixprod's inversion is open. It is confounded: the
0.59 board predates the 16-slot raise, so it ran at CP_NSLOTS=7 as this one
does, which rules slot count out as the separator and leaves architecture and
protocol. The two protocols run different stress-ng builds whose stressor
kernels differ -- the same argument already used to reconcile the chain-start
branch discrepancy -- so a bench.lua matrixprod run at this tip is the cheap
next measurement, not another x86-64 compete rerun.

### The cross-architecture comparison: a uniform tax, not a mechanism

Against the AArch64 16-slot board where cp led (cp 1.46, light 1.62), every
comparison is a within-board ratio; the hosts differ so absolute seconds are
not comparable.

    cp/light        aarch64   x86-64   swing
    nop                0.95     1.33    1.40   flipped to loss
    regs               1.76     2.48    1.41
    branch             1.21     1.48    1.23
    tree               0.83     1.09    1.31   flipped to loss
    qsort              0.57     0.97    1.68
    memcpy             1.44     1.38    0.96
    zlib               0.82     1.11    1.35   flipped to loss
    hash               0.82     1.10    1.34   flipped to loss
    syscall            1.02     1.32    1.30
    double             1.12     1.62    1.45
    sieve              0.98     1.67    1.70   flipped to loss
    int64              0.48     0.80    1.65
    matrixprod         0.50     1.51    3.03   flipped to loss
    geomean            0.90     1.32    1.47

    cp wins 8/13 on aarch64, 2/13 here.

Twelve of thirteen rows move against cp, none moves toward it, and the median
swing is 1.40x. memcpy alone is flat (0.96), plausibly because it is already
cp's worst register-carry loss on AArch64 and saturated on that bottleneck.

That uniformity is the finding. A mechanism-specific cause -- a stencil
family, the chain-start entries, FP contraction -- would hit a subset of rows.
A flat tax across nop, hash, zlib, sieve and matrixprod alike is what a global
per-operation cost looks like, which is what the two structural x86-64
differences predict: CP_NSLOTS=7 against 16, and cp_enter_call against
AArch64's plain-branch transfer. This is evidence on the question left open by
the first native x86-64 board, and it favours "both, uniformly" over either
single cause.

The competitive loss is larger against the other emulators than against
lightning:

    geomean cp/rvvm   1.22 -> 1.45
    geomean cp/qemu   0.71 -> 1.39

cp led qemu-system by 29% on AArch64 and trails it by 39% here, a 1.96x swing.
That, not the lightning ratio, is the headline.

Two rows sit outside the uniform tax and should not be read with it:

- matrixprod's 3.03x swing is more than double the median, so something
  specific is on top of the global cost. The FP-contraction hypothesis is
  falsified above; this is unexplained.
- tree's cp/rvvm goes 1.33 -> 0.14, cp now 7x faster than RVVM. That is
  entirely RVVM's x86-64 tree pathology, not a cp gain, and reading it as a
  win would be an error.


## Corrected: what the emission-truncation fix actually did to matrixprod (2026-08-23)

The `19b94bc0` commit message attributed matrixprod's 2.1x gain to FP
fragments hitting the exit budget, and a later correction of mine
reattributed it to scratch-depth exhaustion at `CSRRS fflags`. Both were
inferred from abort logs. Profiled properly, neither description was right,
and two further claims of mine were wrong.

Method: perf 6.8.12 at `/usr/lib/linux-tools-6.8.0-137/perf` (the
`/usr/bin/perf` wrapper refuses only because the running kernel is 6.18;
`perf_event_paranoid=2` permits user-space sampling). Generated code is
symbolised by writing `/tmp/perf-<pid>.map` from the `TC_LIGHTNING_STATS`
publication lines, which already carry head, size and address -- no emitter
needed. Driver is bench.lua with a 4Gi-mcycle window and no root hash, so
the untimed boot and the 512MB Merkle hash do not swamp the profile. Both
builds retire mcycle 4,563,402,752.

    build                     wall    interpreter  generated  compiled traces
    pre-fix  (ed955187)       9.89s      96.12%      2.85%         432
    post-fix (HEAD)           5.09s      78.65%     19.73%         352

matrixprod was running essentially interpreted. The fix moved 7x more time
into generated code, and did it with *fewer* traces.

Per-trace attribution, post-fix (map resolves ~100% of the JIT bucket):

    trace_7fffa33034ec   8.03%   <- half of all generated-code time
    trace_7fffa3301afc   2.30%
    trace_7fffa3303702   1.41%
    trace_7fffa3301bc2   1.18%
    trace_55557b791524   1.01%

The end-to-end chain for the dominant trace, each step measured:

- Pre-fix, head `7fffa33034ec` never compiles: 0 occurrences among the 432
  published traces.
- Pre-fix it aborts three times at emission (`ABORT-collect`, recorded
  lengths 211, 209, 219) -- it is tried and thrown away, not merely unseen.
- Post-fix it truncates once (`ETRUNC cut=207 reason=3`) and publishes.
- Post-fix it is the hottest generated trace at 8.03%.

`trace_7fffa3301afc` compiles in both (1.50% -> 2.30%) and is the control:
the win is the traces that did not exist before.

### Three of my claims this refutes

- **Not FP.** Both builds report `longest-fp-chain 0 (0 fp)`: no matrixprod
  trace contains staged floating point either side. The hot interpreter
  symbols pre-fix are integer -- `C_LDSP` 7.4%, `ADD_MUL_SUB_rdN` 6.8%,
  `SRLI_SRAI_rdN` 6.3% -- i.e. soft-float emulation. "FP fragments" was
  wrong.
- **Not reason 2.** My correction claimed scratch-depth exhaustion at the
  `fflags` CSR write dominated. Those heads do appear (`bc2` 1.18%, `379e`
  0.52%) but are minor; the dominant trace is a **reason-3** exit-overflow
  truncation, so the original commit message was closer than my correction.
  The instruction at its cut is a conditional branch, not an FP op.
- **Not more coverage.** Published traces fall 432 -> 352. The fix converts
  aborts into truncated publications and those happen to be the hot ones:
  7x the time from 19% fewer traces. Another instance of instruction
  coverage not being time coverage.

### Still open

matrixprod remains 78.65% interpreted after the fix, so most of its time is
still outside generated code -- the headroom that cp's 1.87s (against
lightning's pre-fix 3.17s on the bench.lua board) was presumably reaching.
Also unexplained: the pre-fix head aborts three times rather than once,
though an emission abort is supposed to blacklist permanently on the first
failure; the penalty table is hash-indexed and a colliding head can evict
the entry, which is a candidate but is not measured.
