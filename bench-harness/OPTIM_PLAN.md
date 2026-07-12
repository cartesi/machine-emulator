# Interpreter Optimization Plan

Host: Intel i9-14900K (Raptor Lake: 8 P-cores + 16 E-cores, L1d 48KiB/P-core, L2 2MiB/P-core, L3 36MiB).
Build: gcc -O2, NDEBUG for interpret.cpp, computed-goto dispatch.

## Design constraints (from GOAL.md philosophy + README)

Every experiment must respect: **low complexity, determinism, portability, security,
verifiability**. Concretely for this work:

- No JIT or JIT-like dynamic code generation; no host-FP acceleration (softfloat results
  must stay bit-exact); no multi-core interpretation.
- Portable standard C++ only — no x86-specific intrinsics; must keep working on 32-bit /
  RISC-V / WASM hosts (the plain-switch fallback when computed goto is unavailable must
  keep working).
- interpret.cpp is instantiated for several STATE_ACCESS classes (fast `state_access`,
  uarch bridge, record/replay for fraud proofs, zk runtimes) — changes must not alter
  observable state-transition semantics for any of them.
- Prefer simple, auditable changes; an optimization that wins a few % but complicates the
  code materially is a bad trade here.

## How the hot path works (study summary)

Per guest instruction, `interpret_loop` does:

1. **Inner loop check**: `mcycle < mcycle_tick_end` (add + cmp, predictable).
2. **Fetch**: `fetch_cache_is_hit(pc, last_vaddr_page)` (page-local fetch cache, ~5 host insns
   on hit) → misaligned 4-byte load at `pc + vf_offset`.
3. **Dispatch**: `goto *insn_jumptable[insn & 0xFFFF]` — a **64Ki-entry × 8B = 512KiB** table
   indexed by the low 16 bits (opcode[0:6] + rd[7:11] + funct3[12:14] + rs1-bit[15]),
   giving free rd0/rdN specialization and compressed-insn decoding.
4. **Execute**: handler body (`FORCE_INLINE`, registers in `a.read_x/write_x`), sets `status`,
   `pc += 4` or `pc = new_pc`.
5. **Epilogue**: `goto NEXT_INSN` → status check (`status > success` unlikely) → `++mcycle` → loop.

Loads/stores go through a direct-mapped 256-slot hot TLB per set (code/read/write), 16B/slot
(`vaddr_page`, `vh_offset`); hit path = index → compare → `vaddr + vh_offset` → host load.

## Baseline (unpinned, 2026-07-12)

bench-insns highlights (MIPS): addi 1309, lui 1686, non-taken branches ~1400,
**taken branches ~383, jal 423, jalr 373**, loads ~870-910, stores ~755-800,
fadd.d 225, fmul.d 232, fmadd.d 182, amo* ~600, csrr* ~350. Average 686.

bench-stress (MIPS): nop 1735, regs 1269, memcpy 1003, branch 991, fp 904, heapsort 899,
crypt 776, randlist 594, tsearch 579, tree 544, cpu 525, **malloc 298, matrix-3d 233**.

## Key diagnosis

- **Taken control flow is 3.7× slower than sequential** (383 vs 1400 MIPS). Taken jumps
  serialize the critical chain: load insn → extract imm → new_pc → next fetch address →
  next insn load. Sequential code breaks the chain because `pc += 4` doesn't depend on the
  loaded insn value. ~10 host cycles/insn ≈ measured 383 MIPS.
- **Real workloads add indirect-branch mispredicts**: objdump shows GCC merges the ~93
  handlers' dispatch into only **9 indirect jump sites**, so the indirect predictor must
  disambiguate everything by global history at few sites.
- **Dispatch table D-cache footprint**: 512KiB table; entries for one static insn are spread
  by rd/rs1 bits (64 entries = 8 cache lines per opcode+funct3 combo). Real code touches a
  large, sparse working set of this table, competing with hot TLB + machine state for L1d.
- Slowest stress benches (matrix-3d 233, malloc 298) are load/store + FP + pointer-chasing
  heavy — dominated by dispatch mispredict + memory-path latency + softfloat cost.

## Ranked experiments

### E0. Profile with perf (diagnosis, no code change) — do first
`perf stat` + `perf record` on 2-3 stress workloads (e.g. cpu, malloc, matrix-3d): IPC,
branch-miss rate, L1d/L2 misses, hotspot annotation. Validates the diagnosis above and gives
a mispredict/cache-miss budget for E1/E2. Also: re-baseline with `taskset` pinning to a
P-core (14900K P/E scheduling adds noise; all future runs pinned).
**Cost: tiny. Risk: none.**

### E1. Replicated dispatch (threaded interpreter)
Make `INSN_BREAK()` perform the epilogue + fetch + `goto *insn_jumptable[...]` inline at the
end of **each** handler instead of jumping to the single `NEXT_INSN` funnel. Each handler
gets its own indirect-branch site → the predictor learns per-predecessor patterns
(classic direct-threading win).
**Expected: 5-20% on stress benches; ~0 on microbenches (already predictable). Risk: L1i
pressure from ~93 replicas of epilogue code; GCC may re-merge them (need `objdump` check).
Constraint: implemented in the INSN_* macro layer so the portable plain-switch fallback
(WASM etc.) keeps its current single-dispatch shape unchanged.**

### E2. Shrink dispatch-table footprint 8× (two-level table)
Keep the 16-bit index but store `uint8_t` label ids (64KiB) + a ~256-entry label→address
table (2KiB, L1-resident). One extra dependent load in dispatch, but it's behind a predicted
indirect branch, so latency is mostly hidden; footprint per opcode+funct3 combo drops from
8 cache lines to 1. Implementable entirely in interpret.cpp by re-expanding the generated
header's initializer with different macros (no regeneration needed).
**Expected: 3-10% on stress benches with big insn working sets; possibly slightly negative
on microbenches. Risk: low; composes with E1.**

### E3. Shave the taken-jump dependency chain
Attack the serial chain for jal/jalr/taken branches: cheaper imm extraction (fewer dependent
ops after the insn load), e.g. bit-manip alternatives for `insn_B_get_imm`/`insn_J_get_imm`,
and checking the generated code for avoidable latency (e.g. sign-extension stalls).
**Expected: up to ~10% on jump-heavy code (each cycle removed from a ~10-cycle chain ≈ 10%
of taken-branch cost); helps all workloads a little (branches are ~15-20% of real code).
Risk: low, localized.**

### E4. Load/store TLB-hit path latency audit
Objdump-audit `read/write_virtual_memory` hit paths: confirm `verify_cold_tlb_slot` and
`pma_index` loads are dead for `state_access`, check the compare+load scheduling, consider
loading the 16B hot slot in one go. Loads at 870 vs addi at 1309 MIPS says the hit path has
~3-4 spare cycles vs ALU ops.
**Expected: 2-8% on load/store-heavy benches (memcpy, malloc, tree, tsearch). Risk: low.**

### E5. Softfloat hot-path optimization
matrix-3d (233 MIPS, slowest) is double-precision heavy; fadd.d/fmul.d/fmadd.d are 4-7×
slower than ALU ops. Inspect soft-float.hpp for cheap wins in the common normal-number path
(branchless classification, clz-based normalization, fused rounding). Softfloat only — host
FP is off-limits by design; results must stay bit-exact on all platforms.
**Expected: uncertain; potentially 10-30% on FP-heavy benches only. Risk: medium — needs the
FP test suite as gate, and any change must stay simple/auditable.**

### E6. Macro-fusion of hot compressed pairs (likely out of scope)
Detect very hot 2-insn idioms at dispatch (e.g. `c.add`+`c.ld`, auipc+addi) with fused
handlers via extended table ids. Flagged for completeness, but it conflicts with the
low-complexity design goal (bigger generated table, more handlers to audit, semantics
duplicated across fused/unfused paths) — recommend not pursuing unless profiling shows
dispatch is still dominant after E1/E2 and the win is large.
**Expected: unknown. Risk/effort: high — last resort.**

## Round 2: ranked next experiments (after E0-E4 results)

E1-E4 established that dispatch, dispatch-table layout, imm extraction and the TLB-hit
paths are all at their practical optimum. The remaining headroom, per E0's per-workload
profiling, is in the *slow paths* and *softfloat*:

### N0. Stats-instrumented profiling (diagnosis, do first)
Build with `make -C src DUMP_DEFS=-DDUMP_STATS` (counters already exist: tlb.cmiss/rmiss/
wmiss/hits, fence_vma, outer/inner loop) and collect per-workload counts for malloc, tree,
tsearch, randlist, cpu. Sizes N1/N2 precisely: how many walks/flushes per 1G insns each
workload actually does. **Cost: tiny (one rebuild + one bench run). Risk: none.**

### N1. Host-side second-level translation cache in the TLB-miss slow path
`translate_virtual_address` is 11% of malloc cycles (plus 5.8% in the rvm/wvm slow-path
wrappers). The 256-slot direct-mapped architectural TLB covers only 1MiB/set, so heap-heavy
workloads walk page tables constantly. Add a *host-only* (non-committed, purely an
interpreter acceleration) larger/associative translation cache consulted in
`read/write_virtual_memory_slow` + `fetch_translate_pc_slow` before walking. Committed
state transitions stay bit-identical: the cache is only a memoization of the walk, entries
usable only when the walk would not mutate state (PTE A/D bits already set — the common
case), and it is invalidated exactly where the architectural TLB is flushed (sfence.vma,
satp/mstatus changes, PTE-affecting paths already flush). Determinism/verifiability
preserved; complexity is real but self-contained.
**Expected: +5-10% on malloc/tree/tsearch/randlist class; 0 elsewhere. Effort: medium-high.
Risk: invalidation correctness (must mirror existing flush points exactly).**

### N2. Cheaper TLB flush (sfence.vma path)
sfence.vma microbenches at 2.3 MIPS (~2500 host cycles): `flush_all_tlb` loops 3×256 slots
through per-slot `write_tlb` (and `mark_write_tlb_dirty_page` shows at 1.9% of malloc
cycles). For the fast `state_access` only, specialize a bulk flush (contiguous stores over
hot + shadow sets, dirty-marking pass only over genuinely valid write slots); record/replay
instantiations keep the per-slot logged path. Final state identical.
**Expected: +2-4% on malloc-class workloads, more if N0 shows high fence_vma counts.
Effort: low-medium. Risk: low.**

### N3. Softfloat hot paths (= old E5)
matrix-3d (225 MIPS, worst bench) and fp are pure softfloat compute: ~121 host insns/guest
insn, IPC 5.3, zero stalls — only fewer instructions helps. Focus: fadd.d/fmul.d/fmadd.d
common-case (both operands normal, no traps): branchless classification, clz-based
normalization, avoiding redundant (un)packing in fma. Bit-exactness gated by the FP test
suite; softfloat only, no host FP.
**Expected: +10-25% on matrix-3d/fp only. Effort: medium-high. Risk: medium (semantics).**

### N4. Trap/CSR path shavings
csrr* ~350 MIPS, ecall ~310; read_csr/write_csr ~0.7% of malloc cycles. Kernel-heavy
workloads pay this on every syscall/trap. Audit `raise_exception`, csr read/write switch
ordering (hot CSRs first), and the mstatus recomputation.
**Expected: <1-2% on kernel-heavy workloads. Effort: low. Risk: low.**

### N5. Decoded-instruction page cache — IN FOCUS, see N5-PLAN.md
The only idea that attacks the ~11.6 cycles/insn integer floor structurally. Initially
flagged as conflicting with the low-complexity goal; now selected for exploration with a
determinism-preserving design (pure memoization of fetch+decode, exact store-side
invalidation, penumbra-resident, fast state_access only). Full phased plan with go/no-go
gates in `N5-PLAN.md`.

## Methodology (all experiments)

- Pin benchmark to one P-core (`taskset -c 2`), quiet machine.
- Quick signal: `bench-insns.lua` (full, ~1 min) + `bench-stress.lua -f '^(cpu|branch|malloc|matrix-3d|memcpy)$'`.
- Final numbers for accepted experiments: full bench-stress run.
- Gate: `make -C src` warning-free; run emulator test suite if the change touches semantics.
- Record every experiment (accepted or rejected) in `OPTIM_REPORT.md` with numbers + learnings.
- Keep a known-good `interpret.cpp` via `git stash` between experiments.
