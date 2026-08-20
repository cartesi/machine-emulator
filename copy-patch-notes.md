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

## Open decisions

- Final backend signature: which arg positions carry state_access and the
  insn slot alongside the pinned x23/x24/x25/x27 roles, and how many guest
  cache slots remain (x20-x22, x26, x28, x0-x7 are the free positions).
- Whether the pc-to-trace cache keys on virtual pc + mapping validation
  (current exact-map shape, notes say keep) with a direct-mapped front
  cache like RVVM's jtlb.
