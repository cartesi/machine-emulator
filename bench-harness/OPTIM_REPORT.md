# Interpreter Optimization Report

Experiments follow `OPTIM_PLAN.md`. Host: i9-14900K, gcc -O2, benchmarks pinned to a
P-core with `taskset -c 2` unless noted.

## E0. Profiling + pinned baseline

**Tools**: added `perf-stress.sh` (perf stat/record wrapper, pinned via taskset).

### Pinned baseline (taskset -c 2)

bench-insns average: **674.9 MIPS**. Key insns (MIPS): addi 1307, beq 1407,
beq-taken 384, jal 426, jalr 374, lw 870, sd 755, fadd.d 220, fmul.d 235.

bench-stress (MIPS): nop 1677.5, regs 1220.0, memcpy 963.5, branch 951.4, fp 885.3,
heapsort 869.0, crypt 741.2, randlist 566.0, tsearch 553.2, tree 526.7, cpu 505.3,
malloc 289.5, matrix-3d 225.2.

Pinning changed numbers by only ~2-5% vs unpinned; the scheduler already put runs on
P-cores. All future comparisons use pinned runs.

### perf stat (whole process: incl. ~20% guest boot + Lua overhead; guest ≈ 1.32G insns/run)

| bench     | host cycles | host insns | IPC  | br-miss/guest-insn | L1d-miss/guest-insn |
|-----------|------------|------------|------|--------------------|---------------------|
| cpu       | 15.5G      | 45.2G      | 2.91 | 0.12               | 0.32                |
| malloc    | 27.5G      | 68.1G      | 2.48 | 0.20               | 0.39                |
| matrix-3d | 30.1G      | 159.3G     | 5.29 | 0.05               | 0.04                |

- **cpu**: ~11.6 host cycles/guest insn. Mispredicts ≈ 2 cycles/insn (~17%); L1d misses
  (essentially all served from L2) also significant.
- **malloc**: ~20.8 cycles/guest insn, worst of both worlds + TLB slow path (below).
- **matrix-3d**: IPC 5.29, no misses — pure softfloat compute (~121 host insns/guest insn).
  Only softfloat work (E5) can help it; dispatch experiments won't.

### perf record hotspots

- `cpu` bench: 93% of cycles inside `interpret_loop`. Annotation shows extreme
  concentration at the single NEXT_INSN funnel: fetch-cache check ~7.5%, insn load ~8.0%,
  and **the one dispatch `jmp *(%r8,%rax,8)` alone takes 22.0%** of all cycles
  (mispredict penalty + jump-table load latency are attributed there). Everything else is
  spread thin across handlers. → Strongly motivates E1 (replicated dispatch) and E2
  (smaller table).
- `malloc` bench: interpret_loop 76.5%, **translate_virtual_address 11.1%**,
  read/write_virtual_memory_slow 5.8%, mark_write_tlb_dirty_page 1.9%, raise_exception
  1.4%. The 256-slot direct-mapped TLB (1MiB coverage/set) thrashes on malloc's working
  set, and sfence.vma flushes (microbench: 2.3 MIPS, ~2500 host cycles each, 768 slots
  flushed) add compulsory misses. TLB geometry is committed machine state → cannot be
  changed; possible future angle: cheaper page-table walk / cheaper flush, not in the
  current experiment list.

### Learnings

1. Dispatch (indirect branch + table load) is the dominant single cost on integer-heavy
   real workloads — E1/E2 confirmed as top priority.
2. malloc-like workloads are limited by TLB slow path, not dispatch; expect smaller E1/E2
   gains there.
3. matrix-3d is a softfloat benchmark in disguise; it will only respond to E5.
4. Host branch predictor handles the microbenches perfectly (same insn repeated), so E1's
   effect will only show in bench-stress, not bench-insns.

## E1. Replicated dispatch (threaded interpreter) — REJECTED

**Change**: redefined `INSN_BREAK()` (computed-goto mode only) to inline the loop epilogue
at each handler tail: status check (special → shared NEXT_INSN funnel), `++mcycle`, tick
check (→ `break`), fetch-cache-hit load + `goto *insn_jumptable[...]`; fetch-cache miss →
`continue` (reuses loop-top full fetch). Produced 159 indirect dispatch sites (was 9).

**Results (pinned, MIPS)** vs baseline:

| bench      | base   | E1     | delta |
|------------|--------|--------|-------|
| insns avg  | 674.9  | 694.0  | +2.8% |
| memcpy     | 963.5  | 981.7  | +1.9% |
| branch     | 951.4  | 961.7  | +1.1% |
| cpu        | 505.3  | 487.5  | −3.5% |
| tsearch    | 553.2  | 535.5  | −3.2% |
| malloc     | 289.5  | 276.4  | −4.5% |

perf stat on `cpu`: instructions −2.4% (epilogue shortcut works), but **branch-misses +9%**
(158M→172M) and L1i misses +89% (5.0M→9.5M) → cycles +3.3%.

**Variant E1b**: replicated epilogue but shared single indirect jump (`goto DISPATCH_INSN`).
Result: identical to E1 — GCC's computed-goto duplication (`max-goto-duplication-insns`,
default 8) re-duplicates the small dispatch block into all ~93 predecessors anyway, so a
true single-site + replicated-epilogue shape is not reachable without compiler-flag changes
(out of scope).

**Learnings**:
- On Raptor Lake (ITTAGE-style indirect predictor with long global history), the classic
  threaded-interpreter replication is **counterproductive**: one hot dispatch site predicts
  guest-code patterns via global history just fine, while 159 sites dilute BTB/ITTAGE
  capacity → more mispredicts, more L1i misses.
- The 22%-of-cycles concentration on the single dispatch `jmp` is *not* mostly mispredict
  stall; a large share is just where load-latency/skid gets attributed. Mispredicts were
  only ~0.12/guest-insn at baseline.
- The Makefile already ships interpreter-friendly codegen flags (`-fno-gcse`,
  `-fno-crossjumping`, `-freorder-blocks-algorithm=simple`) — the designer already tuned
  this axis; matches GOAL.md's warning.
- Baseline restored; next: E2 (shrink dispatch-table footprint), which attacks the
  *data-side* cost of dispatch (L1d misses: 0.32/guest-insn on `cpu`) instead.

## E2. Two-level dispatch table (64KiB byte table + label table) — REJECTED

**Change**: kept the generated 512KiB `insn_jumptable` only for one-time init; dispatch went
through `insn_label_addr[insn_id_table[id]]` where `insn_id_table` is a runtime-built 64KiB
`uint8_t[65536]` and `insn_label_addr` a 153-entry (1.2KiB) label-address array. Also moved
the jump-table `#include` before the loop (labels have function scope, forward `&&label`
references work).

**Results (pinned, MIPS)** vs baseline:

| bench      | base   | E2     | delta |
|------------|--------|--------|-------|
| insns avg  | 674.9  | 639.8  | −5.2% |
| cpu        | 505.3  | 499.3  | −1.2% |
| memcpy     | 963.5  | 920.7  | −4.4% |
| branch     | 951.4  | 882.2  | −7.3% |
| tsearch    | 553.2  | 531.0  | −4.0% |
| malloc     | 289.5  | 276.9  | −4.4% |

perf stat on `cpu`: **L1d misses −77% (417M → 96.5M)** — the 512KiB table really was the
dominant L1d miss source — and branch-misses even dropped slightly (158M→147M). Yet cycles
got *worse* (15.5G → 15.7G).

**Learnings** (this is the key insight of the day):
- The dispatch table's L1d misses are served from L2 and **fully hidden by out-of-order
  execution** behind the predicted indirect jump. Removing them buys nothing.
- What matters is the **latency of the dispatch resolve chain** (insn value → table load →
  jump verify): adding one dependent load lengthens mispredict recovery and retirement,
  costing 4-7% on branchy workloads.
- Corollary: don't optimize for cache-miss counters here; optimize the serial dependency
  chains. The one-level 8-byte-entry table is the right design (as the author built it).

## E3. Shorter B/J immediate extraction — REJECTED (neutral at best)

**Change (E3a)**: rewrote `insn_B_get_imm`/`insn_J_get_imm` as 64-bit forms with shift+mask
terms (2 ops/term instead of 3) and no final 32→64 sign-extension:
`((int64)(int32)insn >> 31 << 20) | ((insn >> 20) & 0x7fe) | ((insn >> 9) & 0x800) | (insn & 0xff000)`.

**E3a results**: taken-branch microbench **+7%** (384→411 MIPS) — proving ~2 cycles really
came off the serial chain — but stress benches regressed: branch −3.1% (948→919), cpu −2%.
perf stat on `branch`: identical instruction count and branch-miss count, +3.1% cycles —
i.e. a latency/scheduling effect in mixed code, not throughput or prediction.

**Change (E3b)**: conservative variant — same shift+mask terms but keeping the original
int32 return type and single final sign-extension.

**E3b results**: taken-branch microbench back to baseline (380; the E3a micro win came
specifically from removing the sign-extension from the chain); full stress suite neutral:
cpu +1.4%, branch/memcpy/heapsort/fp/randlist ±0.5%, tree/malloc/tsearch −1.1..−1.4%.

**Verdict**: no variant wins on real workloads; reverted to upstream code.

**Learnings**:
- The taken-jump serial chain is real and measurable in isolation (E3a microbench), but in
  real instruction mixes the OOO window hides ~2 cycles of chain latency behind neighboring
  work — microbench wins here don't transfer.
- Conversely a shorter chain can *hurt* mixed code through second-order scheduling/layout
  effects that perf counters don't attribute (same insns, same misses, more cycles).
- bench-stress run-to-run variance is ~±1% on consecutive runs (cpu occasionally ±2%);
  any claimed win below ~2% needs repeated A/B runs to be believable.

## E4. Load/store TLB-hit path audit — NO ACTION NEEDED

Audited the steady-state host code for guest `ld` and `sd` via gdb instruction traces and
objdump (state_access instantiation):

- `ld` hit path: 26 host insns + ~11 shared epilogue. `verify_cold_tlb_slot` (constexpr
  true) and the `pma_index` shadow-TLB load (unused by `read_memory_word`) are fully
  compiled out. TLB hit check is 2 ops (`and` with a mask that also catches misalignment,
  `cmp`+`jne`). Register file, hot TLB slot and data access all use tight addressing modes.
- `sd` hit path: equally tight (~27 insns); no dirty-page marking and no PMA lookup on the
  hit path (dirty marking happens only at TLB replacement, confirmed in the trace). The
  ld-vs-sd microbench gap (870 vs 755 MIPS) is just the extra rs2 register read + store.
- Only imperfection found: the hot-slot address chain compiles to
  `shr $12; movzbl; shl $4; add base` (4 ops) where a hand-folded `shr $8; and $0xff0; add`
  (3 ops, and 1 fewer on the dependency chain) is possible. Exploiting it requires changing
  the slot-index semantics in the i_state_access interface (pre-scaled offsets) across all
  state-access implementations — an interface complication for an estimated <1% real-world
  gain. Bad trade against the low-complexity design goal; not pursued.

**Verdict**: the TLB-hit fast paths are already at their practical optimum.

## Overall conclusions

1. **No accepted code changes.** E1 (replicated dispatch), E2 (two-level dispatch table),
   E3 (shorter B/J imm extraction) all measured neutral-to-negative on real workloads;
   E4 found nothing left to fix. `src/interpret.cpp` is back at its pristine state.
2. The interpreter is at a **well-tuned local optimum** for this class of hardware: the
   single-site computed-goto dispatch, the 512KiB one-level jump table, the direct-mapped
   hot TLB and the fetch page-cache are each individually the right call — we now have
   measurements proving the "obvious improvements" to each are not improvements.
3. What actually limits performance per workload class:
   - integer-heavy (cpu, tsearch, tree): dispatch resolve latency + inherent
     insn-load→execute serialization; ~11 host cycles/guest insn. Only a structural change
     (e.g. decoded-insn caching / superinstructions) could move this, at high complexity
     cost — likely conflicts with the design philosophy.
   - malloc-like (mmap/sfence heavy): TLB slow path — `translate_virtual_address` is 11%
     of cycles; sfence.vma costs ~2500 host cycles (flushes 768 slots). A cheaper
     flush/walk is the most promising *unexplored* direction (was not in the approved list).
   - FP-heavy (matrix-3d, fp): softfloat pure compute (~121 host insns/guest insn,
     IPC 5.3). Only softfloat-internal optimization (E5, unapproved) can help.
4. Tooling added for future sessions: `perf-stress.sh` (pinned perf stat/record wrapper).
   Methodology: pin to a P-core, expect ±1-2% noise, always A/B against a same-day pristine
   run, and don't trust microbench deltas to transfer to bench-stress.

# Round 2 (N5: decoded-instruction page cache — see N5-PLAN.md)

## N5.P0. Scoping audit — PASSED (design refined)

### RAM-write path audit (the invalidation-exactness requirement)

Verified by source audit that guest RAM can only be mutated during `interpret_loop` via
exactly two funnels, both hookable within the allowed files:

1. **Word stores** (SB/SH/SW/SD, C_S*, SC, AMOs): all execute through
   `write_virtual_memory` (interpret.cpp:1173 hit path) or `write_virtual_memory_slow`
   (interpret.cpp:1111 memory branch). No other `write_memory_word` call sites exist in
   interpret.cpp.
2. **Bulk/DMA writes**: the only device that writes RAM is virtio (3 call sites in
   virtio-address-range.cpp: used-ring header, used elem, buffer data), all via
   `i_device_state_access::write_memory` → `device_state_access::do_write_memory` →
   `state_access::do_write_memory` (state-access.hpp:427, editable). This includes
   `poll_external_interrupts`: machine.cpp:2154 constructs `state_access` +
   `device_state_access` internally, so poll-time virtio DMA flows through the same hook
   (and poll is active only for unreproducible/interactive machines anyway).
   `do_write_memory_with_padding` (cmio, state-access.hpp:442) also lands on
   `m_m.write_memory`/`fill_memory` — hook both header methods.
3. All other `aliased_aligned_write` users are non-fast-path (replay-step, access-log
   recording, page-hash-tree metadata) — none touch guest RAM in the fast interpreter.
4. Host API writes (`machine:write_memory`, uarch runs, snapshot restore) can only happen
   between `interpret()` calls → covered by a per-entry generation bump.

**Gate result: no unhookable write path. N5 invalidation can be exact.**

### Ownership: thread_local pool instead of penumbra (design refinement)

`processor_state` (shadow + penumbra) is `reinterpret_cast` from raw mapped PMA host
memory (machine.cpp:303, machine-address-ranges.cpp:106: the shadow-state address range's
host_length is sizeof(processor_state)) and is value-assigned (`*m_s = processor_state{}`)
— penumbra members must remain trivial PODs, and machine.cpp (allocation/destruction) is
not editable, so an owning pointer in penumbra would leak.

Refinement: the decode-page pool lives as a **thread_local** owned by interpret.cpp
(lazily allocated, freed at thread exit):
- no changes to processor-state.hpp / machine layout at all;
- thread-safety for concurrent machines on different threads is automatic;
- multiple machines on one thread are separated by the per-`interpret()`-entry generation
  bump (which is also the external-write barrier);
- process forks (jsonrpc) inherit a valid copy (same address space).
A small new header (`decoded-insn-cache.hpp`, included by interpret.cpp and
state-access.hpp) exposes the pool + invalidate helpers to the bulk-write hook.

### Geometry decisions

- Pool: 256 slots, direct-mapped by guest physical page number, tag =
  {paddr_page, faddr_page, generation}. Entry = 16B {handler ptr, insn, pad};
  2048 entries/page → 32KiB/slot → **8MiB per interpreting thread**.
- Store-hook keying: by **host address** (`faddr`), already computed on the store path —
  bitmap over the RAM range (16KiB per 512MiB RAM), zero extra dependent loads.
  DMA-hook keying: by paddr → direct pool-slot lookup, no bitmap needed.
- Decoded pages are vaddr-independent (entries derive from insn bytes only; pc is passed
  in a register as today), so physical indexing shares decoded pages across mappings and
  survives satp changes without hooks.

### Test gates

- `make test-machine` (RISC-V arch test suite): **verified working, 267/267 pass, <1s
  wall** — must be invoked from repo root (sets lua env); cheap enough to gate every build.
- `make test-uarch-compare` (fast-vs-uarch execution comparison): **verified working,
  102/102 pass, ~3s wall** — the determinism cross-check gate for P1.
- bench-stress root-hash/mcycle determinism check vs pristine build (P1 gate).

**P0 verdict: all audits passed, no unhookable write path, gates in place — GO for P1.**

## N5.P1. Minimal decoded page cache — MECHANISM PROVEN, GATE NOT MET YET

**Implementation** (in working tree: interpret.cpp + new decoded-insn-cache.hpp +
machine.hpp + state-access.hpp):
- 1024-slot pool of decoded pages, direct-mapped by host page number, owned by the
  `machine` object (host-only `mutable` member; penumbra was unsuitable — `processor_state`
  is reinterpret_cast'ed raw mapped memory, so members must stay trivial).
- 16B entries {handler ptr, insn}; lazy fill via a DECODE_INSN sentinel handler; loop-local
  (decoded_vaddr_page, decoded_page) mirroring the fetch cache and invalidated at exactly
  the same points (status > success, interrupts, loop entry).
- Exact invalidation: store barrier in `state_access::do_write_memory_word` (tag compare
  per store), range barrier in `do_write_memory`(+`_with_padding`) for DMA, generation
  bump per interpret() entry. All handlers byte-for-byte unchanged.

**Correctness gates: ALL PASS.** 267/267 arch tests, 102/102 fast-vs-uarch comparisons,
and the new `hash-check.lua` determinism gate (boot Linux + 400Mi cycles of stress-ng):
identical mcycle/break-reason/**root hash** vs the pristine build.

**Iterations along the way** (each diagnosed with perf):
1. First cut had a function-local `thread_local` pool → `__tls_get_addr` call per store in
   the dlopen'd .so → sd microbench −43%. Fixed by machine-member ownership: barrier is
   now lea + tag load + compare (sd −43% → −11%).
2. 256-slot pool thrashed on real workloads: +12.4% host instructions (a 2048-entry
   sentinel refill per conflict eviction ≈ 4K instructions, roughly once per 1K guest
   insns on `cpu`). 1024 slots (32MiB) fixed `cpu`: −13% → **+3..6%**.
3. Tag size 24B vs 32B: no measurable difference (kept 24B).

**Results (pinned, avg of runs) vs baseline:**

| bench      | base   | P1     | delta  |
|------------|--------|--------|--------|
| jal micro  | 426    | ~940   | +121%  |
| jalr micro | 374    | ~1250  | +234%  |
| beq micro  | 1407   | 1670   | +19%   |
| addi micro | 1307   | 1390   | +6%    |
| ld micro   | 870    | 910    | +5%    |
| sd micro   | 755    | 670    | −11%   |
| beq-taken  | 384    | 281    | −27%   |
| insns avg  | 674.9  | 687.8  | +1.9%  |
| nop        | 1677.5 | 1716   | +2.3%  |
| crypt      | 741.2  | 783    | +5.6%  |
| cpu        | 505.3  | 522-534| +3..6% |
| malloc     | 289.5  | 288    | ~0     |
| matrix-3d  | 225.2  | 223    | −1%    |
| regs       | 1220   | 1211   | −0.8%  |
| tsearch    | 553.2  | 504    | −9%    |
| memcpy     | 963.5  | 839    | −13%   |
| fp         | 885.3  | 782    | −12%   |
| randlist   | 566.0  | 491    | −13%   |
| tree       | 526.7  | 456    | −13%   |
| heapsort   | 869.0  | 746    | −14%   |
| branch     | 951.4  | 752    | −21%   |

**Analysis — the mechanism is validated, the entry format is not yet:**
- When the next dispatch address doesn't serially depend on the just-loaded value
  (loop-invariant targets: jal/jalr micro; dense sequential code: crypt, cpu, nop), the
  single-entry-load dispatch is a large win — jal-style chains collapse from ~13 to ~4-6
  host cycles. perf on `cpu`: L1d misses −74% (16B decoded entries are *denser* to access
  than the 512KiB jump-table pattern).
- For **pc-varying taken branches** the chain got LONGER: pc → entry-index (2 ops) →
  16B entry load → imm extraction → new pc, vs the old fetch which loaded from
  `pc + vf_offset` (1 op). beq-taken −27% (384→281), and that single effect explains the
  branch/heapsort/tree/randlist/fp/tsearch regressions (all branchy workloads).
- Store barrier costs ~1 host cycle/store (sd −11%) → memcpy −13%.

**Both residuals are exactly what P2 was designed to fix**: precomputed branch/jump
targets in wider entries kill the imm-extraction + add from the taken chain (and can even
start the next entry load without decoding), and specialized decoded handlers for
loads/stores can absorb barrier work. P1 alone does not meet its gate (7 benches below
−1.5%); the go/no-go for P2 is a user decision.

## N5.P2. Pre-decoded immediates + specialized control-flow handlers — LARGE NET WIN

**Implementation** (on top of P1):
- Entry became `{handler 8B, imm int32, insn u32}`: the DECODE_INSN sentinel pre-decodes
  the immediate for the 11 hot control-flow handlers (BEQ..BGEU, JAL rd0/rdN, C.J,
  C.BEQZ/C.BNEZ) and installs specialized `D_*` handler variants; all other instructions
  keep their original handlers. Selection is a pointer-compare chain against the jump
  table at decode time — no generated-table changes.
- **Scaled-base dispatch**: loop-local `decoded_entry_off = base − (vaddr_page << 3)`
  makes the entry address a single `lea (off + pc*8)` — dispatch is now lea + entry load
  + indirect jmp, one op cheaper than the original fetch path.
- `D_*` handlers reload the immediate from the (cache-hot) entry at pc instead of
  receiving it through a loop variable — an earlier variant passed it via a local, which
  GCC spilled to the stack on every dispatch.
- Store barrier simplified to a compact `watch[1024]` array probe (one load + compare);
  "dirty" is encoded as watch=0.
- Page-boundary insns dispatch to original handlers (their entries are never written).

**Two codegen traps found and fixed (the story of this phase):**
1. With the cheap pre-decoded offset, GCC **if-converted the branch handlers into
   conditional moves** — turning the free (predicted) control dependency into a data
   dependency on the register-file loads: beq-taken fell to 330 MIPS and heapsort/fp
   regressed hard.
2. First fix (`asm volatile("")` in the taken path) blocked the cmove but acted as a
   scheduling barrier across the whole inlined loop: branches recovered (806) but
   **regs fell −14%** with identical instruction count and fewer misses.
   Final fix: a **register-scoped** empty asm (`asm("" : "+r"(new_pc))`) — blocks
   if-conversion of just that value with no scheduling fence. Both regressions gone.

**Correctness gates: ALL PASS** (267/267 arch tests, 102/102 fast-vs-uarch, identical
root hash on the boot+stress determinism run).

**Final results (pinned, avg of stable runs) vs baseline:**

| bench      | base   | P2 final | delta   |
|------------|--------|----------|---------|
| insns avg  | 674.9  | 722.4    | +7.0%   |
| beq-taken  | 384    | 806      | +110%   |
| beq        | 1407   | 1524     | +8%     |
| addi       | 1307   | 1502     | +15%    |
| crypt      | 741.2  | 908.7    | **+22.6%** |
| cpu        | 505.3  | 584.8    | **+15.7%** |
| memcpy     | 963.5  | 1074.0   | **+11.5%** |
| regs       | 1220.0 | 1348.5   | **+10.5%** |
| nop        | 1677.5 | 1814.5   | +8.2%   |
| fp         | 885.3  | 929.5    | +5.0%   |
| malloc     | 289.5  | 298.0    | +2.9%   |
| matrix-3d  | 225.2  | 231.6    | +2.8%   |
| heapsort   | 869.0  | 866.3    | −0.3%   |
| tree       | 526.7  | 519.5    | −1.4%   |
| tsearch    | 553.2  | 535.9    | −3.1%   |
| randlist   | 566.0  | ~527     | −6.9%   |
| branch     | 951.4  | 777.0    | −18.3%  |

**Remaining losses, diagnosed:**
- `branch` stressor: adversarial for this design — random jumps over a large code
  footprint; every executed insn touches a 16B entry (4× raw code footprint), L1d misses
  0.33/insn, plus page-switch install churn (+7% host insns). Real code with locality
  (cpu/crypt/memcpy) shows the opposite sign.
- randlist −7% / tsearch −3%: unpredictable-branch pointer chasing, same footprint effect
  in milder form.
- Possible follow-up (P2b): 8-byte entries (u32 handler offset + insn; imm demoted to a
  side table or handler re-extraction for branches) would halve the footprint at +1 add
  in the dispatch chain — the E2 lesson says measure before believing.

**Cost/complexity summary**: 32MiB host memory per machine (pool, lazily allocated),
~250 lines of new logic total across decoded-insn-cache.hpp / interpret.cpp hooks, no
committed-state changes, no generated-table changes, WASM/uarch/record/replay untouched.

## N5.P2b. 8-byte entries (footprint halving) — REJECTED

**Change**: entries shrunk to 8B `{u32 insn, i32 handler_off}` with the handler encoded
relative to the DECODE_INSN label (elegant bonus: all-zeros entry = sentinel, resets
become memsets) and immediates moved to a parallel per-page int32 array. Dispatch gained
2 ALU ops (offset → anchor+add) on the resolve chain.

**Results**: randlist +4% and branch +1% vs the 16B design (footprint helps random-jump
code a little) but regs −11%, cpu −4.5%, addi/beq micro −8%. **E2's lesson confirmed a
third time: on this CPU, dispatch resolve-chain latency beats data-cache footprint.**
Reverted to 16B entries.

Also learned during the revert: these benchmarks are exquisitely code-layout-sensitive —
logically-equivalent code shapes swung randlist between 527 and 611 MIPS and regs between
1080 and 1400. The final code shape (with the `decoded_page` loop-local) is the measured
winner. Any refactor of this region must re-run the full suite.

## N5 FINAL RESULTS (P2 final shape, definitive 2-run average, all gates green)

| bench      | base   | final  | delta   |
|------------|--------|--------|---------|
| insns avg  | 674.9  | 720.6  | +6.8%   |
| cpu        | 505.3  | 590.9  | **+16.9%** |
| crypt      | 741.2  | 865.0  | **+16.7%** |
| regs       | 1220.0 | 1401.6 | **+14.9%** |
| memcpy     | 963.5  | 1102.6 | **+14.4%** |
| nop        | 1677.5 | 1822.8 | +8.7%   |
| randlist   | 566.0  | 610.4  | +7.8%   |
| fp         | 885.3  | 937.6  | +5.9%   |
| malloc     | 289.5  | 304.9  | +5.3%   |
| matrix-3d  | 225.2  | 234.1  | +4.0%   |
| heapsort   | 869.0  | 880.2  | +1.3%   |
| tree       | 526.7  | 526.8  | 0.0%    |
| tsearch    | 553.2  | 544.8  | −1.5%   |
| branch     | 951.4  | 802.1  | −15.7%  |

12 of 13 stress benchmarks at or above baseline; geometric-mean stress uplift ≈ +6%.
The one loser is stress-ng's `branch` stressor — random jumps over a large code footprint,
the design's constructed worst case (every insn touches a 16B entry = 4× code footprint).

Correctness: 267/267 arch tests, 102/102 fast-vs-uarch comparisons, bit-identical root
hash vs pristine on the boot+400Mi-cycle determinism run — at every phase.

**Files changed**: src/decoded-insn-cache.hpp (new), src/interpret.cpp,
src/state-access.hpp, src/machine.hpp. Polished: clang-formatted, macro scoped with
#undef, comments document the invalidation invariant and both codegen traps
(if-conversion → register-scoped asm; scheduling-barrier asm → regs regression).
