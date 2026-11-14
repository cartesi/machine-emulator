## R1-R12-2

**Title.** In the uarch program every TLB flush issues its 768 `write_tlb` ecalls through a non-inlined 14-instruction
wrapper, so a flush costs 17,492 uarch cycles (22 per slot) where about 3 to 4 per slot would do, even with a full TLB.

**Severity.** High (under the reading preferred here; Low under the alternative reading given at the end of Rating).

### Problem

A full TLB flush happens on `sfence.vma`, on every `satp` write and on every privilege change (`set_prv`, so on every
trap, interrupt and xRET). The interpreter writes all 768 slots (3 sets of 256), and in the uarch program each slot
write is a call to `ua_write_tlb_ECALL`. That function is compiled out of line (no LTO, separate translation unit) into
14 instructions: 5 moves of the arguments into temporaries, 2 instructions to load the ecall number, 5 moves back into
`a0`-`a4`, `ecall` and `ret`. The calling loop adds 8 instructions per slot, which rematerialize constants that do not
change between slots. A flush therefore costs 22 uarch cycles per slot, 17,492 uarch cycles per flush mcycle, against
629 for an `addi` that misses the code TLB. The cost is the same whatever the TLB holds.

With all 768 slots valid, the semantics do require 768 slot writes, and in the uarch the only way to write a slot is a
`write_tlb` ecall. Issued from an inlined loop (slot index, `ecall`, increment, branch, the other arguments kept in
registers), they need about 3 to 4 uarch cycles each, so about 2,300 to 3,100 uarch cycles plus the control's 629.
The out-of-line wrapper thus multiplies the worst-case uarch cost of a flushing mcycle by about 5 to 6. Flushing
mcycles are the most expensive mcycles in uarch cycles: 768 slot writes dwarf a page walk or a trap entry. A guest can
execute them back to back, for example across the 2^10 mcycles that one uarch-level claim spans (doc/README.md: a uarch
period is "at most 2^10" mcycle bundles of 2^20 uarch transitions). The honest operator executes and hashes every one
of those uarch cycles to build the uarch-level claim, and R12 bounds that work only "per run" for fixed-point
repetitions, not for executed cycles. So the defect multiplies the worst-case cost of an mcycle executed by the uarch
and of a uarch-level claim by a constant factor that the semantics do not require.

It does not break the goal by itself. It removes margin from the dispute clocks that A7 sizes "at the worst-case costs
of R12".

The other half of the original claim, that already invalid slots are rewritten, only affects the average case: with a
full TLB nothing can be skipped, and a check per slot would make the worst case slightly more expensive. Section 8 puts
"Average-case performance that does not change the worst-case cost of any operation listed in R12" out of scope, so
this entry does not count it as a defect, and the test does not assert it.

### Component, role and area

The uarch program, in its TLB-flush path: the interpreter's `flush_tlb_slot`, `flush_tlb_set` and `flush_all_tlb` as
compiled into the uarch, and the uarch bridge's `do_write_tlb` with `ua_write_tlb_ECALL`. AUDIT.md's components table
gives "Interpreter, state-access layers, devices, uarch program, ... `collect_uarch_cycle_root_hashes` ..." the role
"Honest operator". The native interpreter flushes the same way, but natively the per-slot cost is small and writing
the slots of a full TLB is required, so the native path is not affected in its worst case.

### Location

- `src/interpret.cpp`: `set_prv` (about line 380, calls `flush_all_tlb`), `flush_tlb_slot`, `flush_tlb_set`,
  `flush_all_tlb`, `flush_tlb_vaddr` (lines 885-937), and the callers at lines 500, 2279, 2341, 2858, 3592 and 3607
  (`satp`/`mstatus` writes, `sfence.vma`).
- `uarch/uarch-bridge-state-access.hpp`: `do_write_tlb` (line 190) calls `ua_write_tlb_ECALL`.
- `uarch/uarch-ecall.c`: `ua_write_tlb_ECALL` (lines 44-59), an out-of-line function whose `asm` moves each `"r"`
  operand into the clobbered argument registers.
- `uarch/uarch-ram.elf.objdump`: `ua_write_tlb_ECALL` at 0x600b90-0x600bc4 (14 instructions) and the flush loop body
  at 0x602430-0x60244c (8 instructions, `jal ra,600b90`), repeated for each of the three sets.

### Evidence and test

`bugs/R1-R12-2/` contains `test.lua` and `README.md`. The test builds two bare-metal guests from RISC-V encodings in
Lua, so it needs no toolchain and only the in-tree emulator build. Run `bugs/run.sh R1-R12-2`. It takes about one
second.

1. The decisive part, the worst case. Pages 0..254 each start with `j next page` (256 code slots). Page 255 loads
   from pages 256..511 and stores to pages 512..767 (256 read and 256 write slots), then runs `sfence.vma x0, x0;
   addi; j .`. The test checks that all 768 shadow-TLB slots are valid before the `sfence.vma`. It runs that mcycle
   and the following `addi` with the pristine uarch program (`run_uarch` to halt, then `reset_uarch`). Uarch cycle
   counts are exact, with no timing involved. It asserts `(sfence cycles - addi cycles) / 768 <= 8`, about twice
   what an inlined ecall loop needs.
2. A diagnostic, not asserted. A guest alternates `sfence.vma` and `addi` with an almost empty TLB. The test
   single-steps one flush and counts its `write_tlb` ecalls.

On audit/prt2 it prints the following and exits 1 (deterministic, two runs identical):

```
full TLB: 768 of 768 slots valid before sfence.vma, 0 after; sfence.vma 17492 uarch cycles, following addi 629
almost empty TLB (diagnostic): 1 slots valid before, 768 write_tlb ecalls, 767 of them to slots already invalid, 17492 uarch cycles
full-TLB flush cost over the control: 21.96 uarch cycles per slot (bound 8)
VIOLATED: R12 / section 8 High: flushing a full TLB costs 21.96 uarch cycles per slot (more than 8) beyond an addi; ...
run.sh: R1-R12-2: exit 1 (bug present)
```

The prover's test asserted only the almost-empty case, which a fix that skips invalid slots would pass while leaving
the worst case unchanged. The reviewer revised it so that the full-TLB worst case decides. That case fails for the
same reason, 21.96 uarch cycles per slot. In a manual measurement (not part of the test, timings noisy on a shared
host), running the full-TLB flush mcycle one uarch cycle at a time with a root hash after each, as
`collect_uarch_cycle_root_hashes` does, took about 5.8 s of host CPU, against about 0.01 s for an ordinary mcycle with
an empty TLB. Each extra uarch cycle costs a full step and a hash update. Found, proved and reviewed with
`claude-opus-5-5`; no fallback model was used.

### Trigger and reachability

Any guest code, at any privilege level, after it reads an input: `sfence.vma`, a `satp` write, or any trap or xRET
(even a U-mode `ecall` pays two flushes). The section 4 adversary "may then run any instruction stream at any
privilege level". The state is reachable, because the flush costs the same from every state. The worst case, a full
TLB, takes only touching 768 suitably spaced pages, which the test's guest does from a configuration-created machine.
An adversary steers a dispute to such an mcycle, or fills a uarch period with such mcycles, and forces the honest
operator to compute uarch-level claims over them (section 7: "Steer the dispute to any position of the honest
computation").

### Rating

1. Out of scope: no. "Average-case performance that does not change the worst-case cost of any operation listed in
   R12" does not apply, because the wrapper overhead is paid in the worst case (full TLB, flush every mcycle), as
   the test shows. It does apply to the "rewrites already invalid slots" part, which this entry therefore does not
   count. No other exclusion fits. The trigger is ordinary guest execution from a valid template, with no API misuse,
   snapshot, O1/O2 or A1-A8 violation.
2. Role: the uarch program, which AUDIT.md's table puts under "Honest operator". Section 3: "The transition function,
   its log producers, the computation-hash builders ... play this role in every deployment." That clause covers this
   component directly.
3. High and Medium cases: the section 8 High case applies: "A defect that lets the guest, or host load that the
   deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor,
   compared with the same operation without the defect, while staying within what the deployment was sized for. A
   cost that the specified semantics require is not a defect. When the sizing is unknown, rate such a
   constant-factor increase High." The operations are "an mcycle" (as executed by the uarch) and "a uarch-level
   claim" (R12). The factor is about 5 to 6 on a flushing mcycle, and on a uarch-level claim whose mcycles all flush.
   It is constant, because it is bounded by 768 slots per flush, and it stays far below the uarch cycle limit per
   mcycle (2^20 - 1). The 768 ecalls are required. The 21 extra instructions per ecall are not required by any
   semantics. The clause covers this component, because it speaks of any defect that multiplies an R12 operation's
   worst-case cost. The sizing is unknown, so the class is High.
4. Critical: not reached. It does not make any R12 operation unbounded, super-linear or larger than sizing.

The two readings differ in what counts as "a defect". The reading preferred here takes the clause's only stated
exception, "A cost that the specified semantics require is not a defect", as the test. On that reading, avoidable
per-slot overhead on the dominant worst-case path is a defect, and the class is High. An alternative reading holds
that "defect" means a mistake in logic, such as redundant or repeated work, and not code-generation efficiency of a
correct implementation; the comment in `flush_tlb_slot` records that writing every slot is deliberate. On that
reading this is a performance improvement, Low or not a defect. Two facts favor the first reading. The excess is
literally redundant work: 10 register moves that undo each other, plus constants rematerialized for every slot. And it
sits on the worst-case path, not spread over every instruction. What would decide it is whether the maintainers treat
the uarch cycle cost of the worst-case mcycle as a sized quantity under A7.

### Possible solution and risks

Make the uarch ecall wrappers `static inline` in `uarch-ecall.h`, binding the operands directly to `a0`-`a4`/`a7` with
register variables (`register uint64_t a0 asm("a0") = ...`) instead of `mv` from `"r"` operands, or enable LTO for the
uarch build. Optionally flush the write set first, and hoist loop-invariant arguments. The flush loop then costs about 3
to 4 uarch cycles per slot. Skipping already invalid slots is not needed for the worst case, and it would add a load
and a compare per slot.

Risks: any change to the uarch program changes its pristine hash, the uarch trajectory of every mcycle, and the
accesses each logged transition makes. That makes it a new protocol version (R13, A6). The regenerated
`machine-solidity-step` constants and the on-chain pristine hash must be updated together, and the new uarch must be
rebuilt reproducibly. Register-variable asm must keep the ecall's clobbers exact. Otherwise the compiler may assume an
argument register survives the ecall, which would be a uarch-versus-native divergence (R2) that the existing
differential tests should catch.

### Risk of not fixing it

Any input sender who takes control of the guest can make every mcycle of a dispute region cost about 17,500 uarch
cycles instead of about 3,000, and so make each uarch-level claim the honest operator must compute over such a region
about 5 to 6 times as expensive. The same holds for every proof of a uarch step there. That consumes margin in the
clocks that A7 sizes. If a deployment sized its uarch-level clocks without measuring flush-heavy mcycles, this factor
moves it toward the Critical case "larger than what the deployment was sized for". Outside the code, the mitigation is
to size the uarch-level clocks for the measured worst case: a period of 2^10 mcycles that each flush a full TLB.
