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

## Open decisions
- Whether the pc-to-trace cache keys on virtual pc + mapping validation
  (current exact-map shape, notes say keep) with a direct-mapped front
  cache like RVVM's jtlb.
