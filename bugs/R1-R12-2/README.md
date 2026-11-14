# R1-R12-2: every TLB flush rewrites all 768 slots through a non-inlined ecall wrapper (~22 uarch cycles per slot)

## What is asserted

`test.lua` encodes two bare-metal guests directly (no toolchain needed); both run in M-mode with bare translation.

1. Decisive, worst case. Pages 0..254 of RAM each start with `j next page` (256 code slots), page 255 loads from
   pages 256..511 and stores to pages 512..767 (256 read and 256 write slots), then runs `sfence.vma x0, x0; addi;
   j .`. The test checks that all 768 slots are valid before the `sfence.vma`, counts the exact uarch cycles of that
   mcycle and of the following `addi` (a code-TLB miss, the larger control) with `run_uarch`/`reset_uarch`, and asserts

       per_slot = (uarch cycles of sfence.vma - uarch cycles of addi) / 768 <= 8

   With a full TLB the semantics require 768 slot writes, i.e. 768 `write_tlb` ecalls; an inlined loop issues them
   in about 3 to 4 uarch cycles each, so the bound is about twice what is needed.
2. Diagnostic, not asserted. A guest alternating `sfence.vma` and `addi` (almost empty TLB); one flush is
   single-stepped and its `write_tlb` ecalls counted, with how many target an already invalid slot. Skipping those
   would only improve the average case, which section 8 puts out of scope, so it is not asserted.

The reviewer revised the test: the prover's version asserted only the almost-empty case, which a fix that skips
invalid slots would pass while leaving the worst case unchanged.

Cause: `flush_all_tlb`/`flush_tlb_vaddr` (`src/interpret.cpp`) write every slot unconditionally, and in the uarch each
write is a call to `ua_write_tlb_ECALL` (`uarch/uarch-ecall.c`), compiled to 14 instructions (12 register moves,
`ecall`, `ret`; `uarch/uarch-ram.elf.objdump` 0x600b90) from an 8-instruction loop body (0x602430-0x60244c). The
same cost is paid by satp writes and by every privilege change (`set_prv`), i.e. every trap and xRET.

## Requirement

THREAT_MODEL.md, R12: "Each of the following operations has a worst case in host time and memory that is bounded ...
They are an mcycle, a uarch cycle, ..., a uarch-level claim, ..."

Section 8, High: "A defect that lets the guest, or host load that the deployment was sized for, multiply the
worst-case cost of an operation listed in R12 by a constant factor, compared with the same operation without the
defect, while staying within what the deployment was sized for. A cost that the specified semantics require is not a
defect."

The semantics of `sfence.vma x0, x0` only require that every slot be invalid afterwards. A uarch-level claim hashes
the state after every uarch cycle, so the uarch cycles of an mcycle are its cost unit.

## Run

```sh
bugs/run.sh R1-R12-2
```

Under a second; needs only the in-tree emulator build.

## Expected output on audit/prt2

```
full TLB: 768 of 768 slots valid before sfence.vma, 0 after; sfence.vma 17492 uarch cycles, following addi 629
almost empty TLB (diagnostic): 1 slots valid before, 768 write_tlb ecalls, 767 of them to slots already invalid, 17492 uarch cycles
full-TLB flush cost over the control: 21.96 uarch cycles per slot (bound 8)
VIOLATED: R12 / section 8 High: ...
run.sh: R1-R12-2: exit 1 (bug present)
```

Exit 1 while the defect is present; exit 0 once a flush costs at most 8 uarch cycles per slot beyond the control
with a full TLB (for example by inlining the write_tlb ecall; skipping invalid slots alone does not pass). Any fix changes the uarch program and the
logged accesses, so it is a new protocol version (R13).
