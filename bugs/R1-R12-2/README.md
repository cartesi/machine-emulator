# R1-R12-2: every TLB flush rewrites all 768 slots through a non-inlined ecall wrapper (~22 uarch cycles per slot)

## What is asserted

A bare-metal guest (encoded directly by `test.lua`, no toolchain needed) runs in M-mode with bare translation:

```
loop: .rept 32
      sfence.vma x0, x0
      addi x0, x0, 0          # control
      .endr
      j loop
```

For 40 consecutive mcycles the test runs the pristine uarch program (`run_uarch` to halt, then `reset_uarch`),
records the exact uarch cycles of each mcycle (deterministic counts, no timing), and counts the valid slots of the
shadow TLB before it. For `sfence.vma` mcycles that start with at most 3 of the 768 slots valid it computes

    per_slot = (min uarch cycles of sfence.vma - max uarch cycles of addi) / 768

and asserts `per_slot <= 8`. The bound is twice what an inlined loop that still writes every slot needs (set the slot
index, `ecall`, increment, branch: 4 uarch cycles per slot); a loop that skips slots already invalid needs about the
same. As a diagnostic it single-steps one flush and counts the `write_tlb` ecalls and how many target an already
invalid slot.

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
addi mcycles: 20, uarch cycles max 629
sfence.vma mcycles (<= 3 of 768 slots valid before): 19, uarch cycles min 17492 max 17492
single-stepped flush: 1 slots valid before, 768 write_tlb ecalls, 767 of them to slots already invalid, 17492 uarch cycles
flush cost over the control: 21.96 uarch cycles per slot (bound 8)
VIOLATED: R12 / section 8 High: ...
run.sh: R1-R12-2: exit 1 (bug present)
```

Exit 1 while the defect is present; exit 0 once a flush costs at most 8 uarch cycles per slot beyond the control
(for example an inlined ecall loop, or skipping slots already invalid). Any fix changes the uarch program and the
logged accesses, so it is a new protocol version (R13).
