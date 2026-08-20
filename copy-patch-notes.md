# Copy-and-patch implementation notes

Working notes for the copy-patch-rvvm.md implementation. Status and verified
facts, updated as the work proceeds.

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

## Open decisions
- Whether the pc-to-trace cache keys on virtual pc + mapping validation
  (current exact-map shape, notes say keep) with a direct-mapped front
  cache like RVVM's jtlb.
