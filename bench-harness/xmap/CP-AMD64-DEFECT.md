# Copy-and-patch does not execute generated code on this x86-64 host

Measured 2026-08-21 against upstream `feat/tailcall-interpreter` tip
`ed955187`, in a clean worktree, gcc-16, Linux x86-64.

Written because the five-emulator board in `copy-patch-notes.md` records cp
ahead of lightning (geomean 1.57 vs 1.63), and that board could not be
reproduced here: cp corrupts guest state on its first entry into generated
code. No cp performance number is reported below, because none could be
obtained.

## Symptom

Same worktree, same compiler, same images, boot of the trivial entrypoint
(`compete.lua ... "true"`), reported as `elapsed mcycle reason`:

    stock        0.427  39633495  1   (halted)
    lightning    0.450  39633495  1   (halted)
    cp           0.003       -21  5   (reached target mcycle)

`reason 5` is `REACHED_TARGET_MCYCLE` against a `1 << 62` target: mcycle has
underflowed below zero and wrapped past the target, so `run()` returns
immediately. Stock and lightning agree with each other exactly, so the
worktree and the images are not implicated.

## Minimal reproduction

A fresh machine and a single `run(68)`:

    stock      mcycle=68   pc=0x80000084
    lightning  mcycle=68   pc=0x80000084
    cp         mcycle=-21  pc=0xffff80c71dc20f30

`run(67)` is correct. Stepping one cycle at a time (`run(1)`, `run(2)`, ...)
is correct through at least 200, so the fault needs a tail-call chain long
enough to enter a trace, not any single instruction.

## Isolation: entering generated code is the trigger

cp ships a `CP_MAX_ENTER` knob that caps entries into generated code.

    CP_MAX_ENTER=0   mcycle=68   pc=0x80000084     correct
    CP_MAX_ENTER=1   mcycle=-21  corrupt pc        broken

A full boot with `CP_MAX_ENTER=0` reaches mcycle 39633495 -- bit-identical
to stock and lightning -- for both cp builds below. cp's recorder and
interpreter path are therefore correct; the defect is confined to executing
the emitted code.

`CP_LOG=1` names the trace: a cyclic trace at head `0x80000080`, len 11,
entered at mcycle 56, which immediately trips with
`vpc=ffff804b35a20f30`. The corrupt pc's high bits differ on every run
(`...c71dc...`, `...d8bee...`, `...b3308...`, `...eff28...`), tracking host
ASLR, so a host address is reaching a guest pc.

## Partial fix: TC_PAGE_SEGMENT

`src/Makefile` adds `-DTC_PAGE_SEGMENT=1` on non-AArch64 hosts *only* inside
the `lightning=yes` block, with the comment that the x86-64 four-slot
`preserve_none` contract "requires the page-segment shape". The
`copy_patch=yes` block never sets it, although cp uses the same
`preserve_none` contract on x86-64 (capped at six register slots per
`copy-patch-notes.md`).

Building cp with `MYINTERPRET_CXXFLAGS=-DTC_PAGE_SEGMENT=1`:

    run(68)      mcycle=68  pc=0x80000084          fixed
    full boot    mcycle=-139960489320784           still broken

So the define is necessary but *not* sufficient. With it, the first failing
single-run target moves from 68 to 45222 (bisected, last good 45221), where
the guest takes an instruction access fault:

    mcause=0x1  mepc=0xffff80b568c00000  mstatus=0x8000000a00007800

Again a host-shaped, ASLR-dependent address in a guest pc.

## Hypotheses tested and refuted

- **Stale generated header.** `copy-patch-notes.md` documents this exact
  failure mode (`#include "cp-stencils-tables.h"` searches the source
  directory before `-I` paths). Refuted: the worktree and main-repo headers
  are byte-identical, md5 `4638b1e2af80b357819061d89edd139d`.
- **Truncated relocations on the value holes.** Refuted: the stencil object
  carries 47 `R_X86_64_64` against the hole symbols plus 30 `R_X86_64_PLT32`
  / 30 `R_X86_64_PC32` for continuations, and was compiled with the
  documented `-mcmodel=medium -mlarge-data-threshold=1 -fno-pic`.
- **Wrong toolchain.** Refuted: `copy-patch-notes.md` names GCC on
  Linux/x86-64 as the platform compiler, which is what was used (gcc-16,
  `CP_CC` defaulting to `CC`).
- **Guest image.** Refuted: fails identically on the canonical
  `images/cartesi/linux.bin` + `rootfs-bench.ext2` and on
  `tests/build/images`.
- **Build health.** The shipped self-tests both pass:
  `cp-stencils-test: PASSED`, `cp-machine-test: PASSED`. The stencil test
  runs in its own heap, which may sit at addresses where a truncated host
  pointer would not be observable.

## Not established

- Whether upstream's board was produced on this architecture. Its absolute
  numbers (lightning geomean 1.63) are roughly half those measured on this
  host for the same protocol, consistent with different hardware, and
  `copy-patch-notes.md` describes the x86-64 stencils as verified under
  `qemu-x86_64` user-mode rather than by a native boot. This is a
  possibility, not a finding.
- The actual root cause of the surviving cycle-45222 fault. Only its shape
  (a host address in a guest pc) is measured.
- Whether `TC_PAGE_SEGMENT` belongs in the `copy_patch` block as a matter of
  design, or whether its absence is a symptom of a different contract
  mismatch.
- Any cp performance number on this host.

## Reproduction

    git worktree add <wt> ed955187
    cp uarch/uarch-pristine-{ram,hash}.c <wt>/uarch/
    cp -r third-party/downloads/lightning <wt>/third-party/downloads/
    make -C <wt>/src cartesi.so CC=gcc-16 CXX=g++-16 -j4 \
         tailcall=yes copy_patch=yes
    cd bench-harness/compete
    LUA_CPATH="<wt>/src/?.so;;" lua5.4 compete.lua \
        images/cartesi/linux.bin rootfs-bench.ext2 "true"

Add `MYINTERPRET_CXXFLAGS=-DTC_PAGE_SEGMENT=1` to the make line for the
partially-fixed build. `CP_MAX_ENTER=0` in the environment makes any cp
build boot correctly.
