# N5 Plan: Decoded-Instruction Page Cache

## Objective

Break the per-instruction fetch→decode→dispatch serial work that E0-E4 established as the
integer-workload floor (~11.6 host cycles/guest insn on cpu-class benches; ~13.5 for taken
jumps). This is the only remaining idea that attacks that floor structurally.

What it can move (hypotheses, to be validated per phase):
- integer/dispatch-bound stress benches (cpu, tsearch, tree, heapsort, branch): the target.
- taken-jump serialization (jal 426 / jalr 374 / taken-branches 384 MIPS): large microbench
  upside, especially in P2.

What it cannot move: matrix-3d/fp (softfloat-bound), malloc (TLB-slow-path-bound).

## Hard constraints (from design philosophy + E0-E4 findings)

1. **Bit-identical committed state transitions.** The cache must be a pure memoization of
   fetch+decode. Crucially this includes the **shadow TLB** (it is merkleized state): the
   design must NOT alter TLB replacement behavior in any way — an earlier idea of using
   write-TLB eviction as a write barrier is therefore ruled out.
2. **No JIT**: decoded entries are data (handler pointer + operands), never generated code.
3. **Exact invalidation, not fence.i-based**: today's interpreter re-fetches every insn, so
   a guest that writes code and jumps to it *without* fence.i still sees the new code, and
   record/replay/uarch see the same. The cache must preserve exactly that behavior, or
   fraud proofs diverge on such guests. Consequence: every path that can write RAM must
   invalidate affected decoded pages *before the next fetch* — no deferral.
4. **Scope**: cache active only for the fast `state_access` instantiation with computed
   goto. record/replay/uarch/WASM paths untouched (they keep today's fetch).
5. **Files**: src/interpret.cpp + headers it includes (processor-state.hpp,
   state-access.hpp, device-state-access.hpp are all in the include closure — verified).

## Core design

### Decoded page cache
- Pool of `N` decoded pages (default 256, ~8MiB), heap-allocated once, owned via pointer in
  `penumbra_state` (host-only, not serialized, survives process fork by COW — verified
  `processor-state.hpp:44-48` documents penumbra as runtime-only). Keep `processor_state`
  layout static asserts satisfied (add a pointer, adjust padding if needed).
- Direct-mapped by guest **physical** page number with a tag: `{paddr_page, generation}`.
  Physical indexing makes virtual aliasing a non-issue and survives satp/mapping changes
  without any sfence hooks.
- Each decoded page: 2048 entries (one per 2-byte slot, so compressed insns index
  naturally: `idx = (pc & 0xFFE) >> 1`).
- P1 entry format (16B): `{ const void *handler; uint32_t insn; uint32_t pad; }`.
  The handler pointer is a computed-goto label of `interpret_loop<state_access>` — legal to
  store in heap since only that one instantiation ever reads it.

### Dispatch flow (single funnel, per E1's lesson)
Loop-local "current decoded page" cache mirrors today's fetch cache
(`decoded_vaddr_page`, `decoded_base`). The NEXT_INSN funnel becomes:

```
status check (unlikely) → ++mcycle → tick check →
same-page check (pc vs decoded_vaddr_page; same cost as fetch_cache_is_hit today) →
entry = decoded_base[(pc & 0xFFE) >> 1]   // ONE 16B load
insn = entry.insn
goto *entry.handler                        // single indirect site preserved
```

vs today: insn load (5c) → `movzwl` → jumptable load (5c) → jmp. The serial chain loses one
dependent load and the decode op; handlers receive `insn` exactly as today — **all ~153
handlers stay byte-for-byte unchanged in P1**.

- Page miss / cross-page → full existing fetch path, then (for RAM pages) install/switch
  the decoded page and continue.
- **Lazy decode**: fresh pages are filled with a sentinel handler `DECODE_ME` (a new label
  in the switch). First execution of each slot decodes via the existing
  `fetch_insn` + `insn_jumptable`, writes the entry, re-dispatches. No upfront decode cost,
  no wasted work, and edge cases fall out naturally:
  - page-boundary-crossing insn at offset 0xFFE: DECODE_ME executes it via the generic
    path and leaves the sentinel in place (permanently generic; rare and correct).
  - non-RAM / non-cacheable code (flash, MMIO-adjacent): no decoded page → generic path.

### Exact invalidation protocol
A page's decoded copy must die before any modified byte of it can be fetched:

1. **Guest stores** (SB..SD, C_S*, SC, AMOs — all funnel through
   `write_virtual_memory`/`write_virtual_memory_slow`, verified): add one check on the
   store path against a **dirty-code bitmap** keyed by host address:
   `off = faddr - ram_host_base; if (off < ram_length && bitmap[off>>12]) invalidate(page)`.
   `faddr` is already in hand — no extra dependent load off the critical store chain; the
   branch is always-not-taken in practice. Bitmap: 1 bit per RAM page (16KiB for 512MiB),
   set when a page is decoded, cleared on invalidate/evict.
   Invalidation = refill entries with DECODE_ME (std::fill, ~µs) — memory is never freed or
   moved, so the loop-local `decoded_base` stays safe even when a store invalidates the
   page currently executing (its next dispatch hits DECODE_ME → re-decode → correct
   same-page self-modifying-code semantics, identical to today).
2. **Device DMA / bulk writes** (`device_state_access::do_write_memory` →
   `state_access::do_write_memory`, paddr-based, header-editable — verified): invalidate
   by paddr range against the bitmap (or generation-bump if range unknown).
3. **Between interpret() calls** (host API write_memory, uarch, snapshot restore):
   generation bump on every `interpret()` entry. Cheap (tag mismatch → lazy refill), and
   makes external mutation windows trivially safe.
4. **Eviction** (direct-map conflict): refill + bitmap clear.

No fence.i/sfence.vma hooks needed — correctness never depends on them (they may later be
*added* as generation bumps only if profiling shows pathological same-page store patterns,
but semantics never require it).

### Semantic equivalence argument (to include in code comments)
Every entry is either DECODE_ME (→ generic path, trivially equivalent) or was decoded from
the bytes at its physical location, and every write to those bytes (store funnel, DMA
funnel, external-API window) kills the entry before the next dispatch from it. Hence
`goto *entry.handler` with `entry.insn` is always exactly what fetch+decode would produce.
Committed state is never touched by the cache itself (penumbra only). Therefore all state
transitions are bit-identical to today's interpreter, for all guests including ill-behaved
ones.

## Phases

### P0 — Scoping audit (no perf code)  [~half session]
- Verify the full store/DMA funnel claim with objdump + grep (no other RAM-write path
  reachable during interpret: check HTIF, CMIO, uarch bridge, virtio queue processing).
- Verify processor-state.hpp edit ripples (static asserts, offsets) and that nothing
  serializes penumbra.
- Confirm test gates run locally: `make test` (or the tests/ lua harness), ideally the
  fast-vs-uarch equivalence tests.
- Decide pool size / bitmap geometry; write the design note into OPTIM_REPORT.md.
- **Gate**: any unhookable RAM-write path found → redesign or abort N5.

### P1 — Minimal decoded cache, handlers unchanged  [~1-2 sessions]
Entry = {handler, insn}; lazy DECODE_ME; store-hook + DMA-hook + entry-generation
invalidation; single-funnel dispatch swap.
- **Measure**: full bench-insns + full bench-stress, pinned, A/B same-day, 3 runs.
- **Expected if the theory holds**: taken-jump micro +20-40%; cpu/tsearch/tree/branch
  +3-8%; loads/stores micro ±0 (store-hook cost vs shorter dispatch); malloc/matrix-3d ~0.
- **Watch**: fetch-side D-footprint grows 4× (16B/insn-slot vs 4B) — check L1d counters;
  store-hook cost on memcpy bench.
- **Gate (go/no-go for P2)**: ≥+3% on ≥3 integer stress benches, no bench < −1.5%, full
  test suite green, fast-vs-uarch roots identical on a boot+workload run. Otherwise revert
  and write up (the E1-E3 pattern says this is a live possibility: predictions here have
  repeatedly failed to transfer).

### P2 — Pre-decoded operands + specialized handlers for hot insns  [~1-2 sessions]
Widen entries (24-32B): pre-extracted rd/rs1/rs2/imm and, for direct branches/jal,
**precomputed target pc** (and target entry index). Add decoded-specialized handler
variants ONLY for the hottest ~12-15 insns (addi, add, ld, sd, lw, sw, beq/bne/blt/bge,
jal, jalr, c.* equivalents) — bounded, auditable duplication; all other insns keep P1 shape.
- Taken-branch chain becomes: entry load → precomputed new_pc → next entry load (~7c).
- **Expected**: taken-jump micro up to +60%; cpu-class stress +8-15% cumulative.
- **Gate**: same structure as P1; also entry-size A/B (16 vs 24 vs 32B) to check the
  footprint/latency trade empirically before committing.

### P3 — Superinstruction fusion (optional, only if P1+P2 both land)
During DECODE_ME, recognize 2-insn idioms (cmp+branch, auipc+addi, lui+addi, slli+add,
paired c.ld/c.sd) and install fused handlers; the second slot keeps its own valid entry
(jump targets into the middle stay correct). Strictly additive; separate gate.

## Risks / open questions

- **The E1-E3 lesson**: every "obvious" win this round measured neutral-to-negative;
  phased gates + honest reverts are part of the plan.
- 8MiB/machine host memory (default) — acceptable for benchmarking; note for upstream
  (config knob or smaller default) if accepted.
- Store-hook cost is the one *hot-path tax* paid by all workloads for a benefit
  concentrated in integer code; memcpy/sd microbench is the canary.
- Label-pointer lifetime: entries valid only for interpret_loop<state_access> within one
  process; generation-bump on interpret() entry already covers .so-reload paranoia
  (pointers never survive the process anyway).
- clang-tidy/lint noise from computed-label storage; keep NOLINT scoped.
- Upstream acceptability is explicitly a philosophy trade (complexity vs ~10% integer
  perf); this experiment produces the data for that decision.

## Test gates (every phase)
1. `make -C src` warning-free.
2. Emulator test suite (tests/) green.
3. Boot-Linux-and-run-stress sanity: identical `machine:read_reg("mcycle")`/halt state and
   identical root hash vs pristine build for the same run (determinism check).
4. Full pinned bench-insns + bench-stress, 3× A/B.

---

# Round 2 (P4): decode-time sub-opcode resolution + richer payloads

P1/P2 landed (+6% geomean stress, 12/13 benches ≥ baseline). Two structural observations
enable the next round:

1. **The jump table only sees the low 16 insn bits** (opcode+rd+funct3), so multiplexed
   handlers (ADD_MUL_SUB, SLL_MULH, SRL_DIVU_SRA, SRLI_SRAI, AMO_W/D, FD, FMADD family,
   PRIVILEGED, csr address switches — 21 funct7/funct5 probe sites) re-inspect high insn
   bits at EVERY execution. DECODE_INSN sees all 32 bits and can install the exact
   operation's handler once. The multiplexed handlers are already thin wrappers over
   standalone execute_ADD/execute_MUL/... templates, so D_ stubs are one-liners.
   Exactness is free: decode only specializes valid encodings; anything else keeps the
   original handler (including its illegal-insn raise).
2. **The entry's 4-byte imm field is really a general payload** that each specialized
   handler can interpret its own way (pre-packed fields, pre-masked so unpacking is 1 op
   per field instead of 2), on top of the already-pre-decoded immediates.

## Phases (each: implement → gates → full 2× suite → keep/revert)

### Q0. Guest instruction histogram (diagnosis, ~30 min)
Build pristine with `DUMP_INSN_HIST` (`make dump=yes` machinery), run the stress subset,
and rank guest instructions by dynamic frequency per workload. This decides which
specializations matter and in what order — and gives the expected ceiling for each phase
(specializing an insn that is 0.1% of the mix cannot pay).

### Q1. Integer OP / OP-32 funct7 resolution (expected: the big one)
D_ADD, D_SUB, D_MUL, D_SLL, D_SLT, D_SLTU, D_XOR, D_SRL, D_SRA, D_OR, D_AND, D_DIV(U),
D_REM(U), D_MULH(SU/U) + the W-suffix family + D_SLLI/D_SRLI/D_SRAI splits, each calling
the existing single-op execute_* template. Kills a 1-2 branch chain + funct7 extraction
per ALU/M execution and shrinks the hot handler bodies.
**Watch: L1i pressure (~40 new small stubs); selection chain length in DECODE_INSN
(decode-time only, but keep it ordered by Q0 frequency).**

### Q2. Compressed-insn payload pre-decode
c.addi / c.li / c.lui / c.addiw / c.addi4spn / c.addi16sp / c.andi / c.slli / c.srli /
c.srai and compressed loads/stores (c.ld/c.sd/c.lw/c.sw/c.*sp): their scattered-bit
immediates cost 3-5 ops per execution today, and compressed insns are the most frequent
class in RV64GC code. Payload = pre-extracted imm (+pre-masked rd/rs1' where useful);
trivial D_ handlers. Also fixes the asymmetry that c.addi (762 MIPS baseline) is ~2x
slower than addi.

### Q3. Loads/stores/JALR packed payload {imm16, rs1, rd}
Pre-masked rs1 takes 1 op off the FRONT of the address chain (rs1 extract currently
feeds the x[rs1] load); imm/rd come along for free. D_LD/LW/LWU/LHU/LBU/LB/LH,
D_SD/SW/SH/SB, D_JALR. Loads+stores ≈ 25-30% of real mixes; expect 1-3% broad.
**Caution: the E2/E3/P2b lessons — an op saved off-chain is worth ~nothing; only the
rs1-extract saving is on-chain. Measure honestly.**

### Q4. AMO funct5 + FP funct7/fmt resolution
D_AMOSWAP/ADD/XOR/AND/OR/MIN/MAX/MINU/MAXU × W/D (kills the largest inner switch),
D_FADD/FSUB/FMUL/FDIV/FSGNJ*/FMIN/FMAX/FEQ/FLT/FLE/FCVT*/FMV*/FCLASS × fmt, FMADD-family
fmt resolution. Helps kernel/malloc (AMOs in spinlocks) and fp/matrix-3d margins;
softfloat still dominates FP cost, so expectations are modest.

### Q5 (optional). Hot-CSR address resolution
csrrw/csrrs on sstatus/sepc/sscratch/satp etc. run a NO_INLINE address switch per
execution inside read_csr/write_csr; decode knows the address. Install per-CSR D_
handlers for the ~6 hottest CSRs (Q0 histogram decides), keeping all permission checks
at execution time (semantics unchanged). Helps trap/syscall-heavy workloads (malloc).

## Standing risks/rules for this round
- Code layout luck swings randlist/regs by ±10%: never compare across refactors without
  a full re-run; keep the measured-winning shape.
- The if-conversion trap: any new D_ handler whose branch guards a cheap pc update needs
  the register-scoped `asm("" : "+r"(new_pc))` pattern (ALU stubs don't branch — safe).
- Selection chain in DECODE_INSN grows to ~60 compares: decode-time only, but order it
  by Q0 frequency and consider splitting by opcode class first (one switch on
  insn_get_id-derived class, then small chains).
- Keep entry at 16B (P2b proved footprint < resolve latency, three times now).
