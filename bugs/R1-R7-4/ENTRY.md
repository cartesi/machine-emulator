## R1-R7-4

**Title.** A PLIC claim returns the highest pending source ID, but the RISC-V PLIC specification breaks ties between
equal-priority sources in favor of the lowest ID.

**Severity.** Medium

### Problem

The emulator hardwires every PLIC source priority to the same value: reads of `priority1` to `priority31` return
`PLIC_LOWEST_IRQ_PRIORITY` (1). The RISC-V PLIC specification says a claim returns "the ID of the highest-priority
pending interrupt for the target". It also says "Ties between global interrupts of the same priority are broken by
the Interrupt ID; interrupts with the lowest ID have the highest effective priority." Since all priorities are equal,
a claim must return the lowest pending source ID. The emulator computes `irq_id = ilog2(ipmask)` (`31 - clz`), which
returns the highest one. With sources 1 and 2 pending, two claims return 2 then 1, not 1 then 2.

The manual lists the device as the "Platform-Level Interrupt Controller (PLIC)" at `0x40100000-0x404fffff`, and its
device tree declares it `compatible = "riscv,plic0"`. The manual documents no claim order and no deviation from the
PLIC specification. So this is an undocumented departure from the device as documented, which R7 forbids. The
behavior is deterministic, and native interpretation and the uarch agree on it.

The security goal of section 1 is not affected. Only VirtIO devices raise PLIC sources, and VirtIO needs an
unreproducible machine. No correct guest relies on the order of equal-priority claims for isolation or data
integrity. The Linux PLIC driver claims in a loop until the claim register returns 0, so it serves every pending
source in either order. The defect is a rule violation without effect on the goal.

### Component, role and area

The PLIC device of the interpreter. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ...":
Honest operator. Area: device semantics (R7, R13 "The device behavior"), the PLIC claim/complete register.

### Location

`src/plic-address-range.cpp`, `plic_read_claim_complete()`: `const uint32_t irq_id = ilog2(ipmask);`, with
`ilog2(v) = 31 - __builtin_clz(v)`. The same source compiles into the uarch interpreter, so the uarch and the
regenerated on-chain step share the behavior.

### Evidence and test

`bugs/R1-R7-4/` contains `test.lua` (the test), `README.md` (how it works) and this entry. There are no other support
files: the guest is a 7-instruction M-mode program that the test assembles inline.

The test creates a reproducible machine (`iunrep = 0`) with 4 KiB of RAM and
`processor.registers.plic = { girqpend = 0x6, girqsrvd = 0 }` in its config, so sources 1 and 2 are pending. Setting
`girqpend` from the config stands in for two VirtIO devices raising interrupts at the same time. The guest reads
`priority1` and `priority2`, makes two 32-bit loads from the claim register at `0x40300004`, and spins. The test runs
the program natively, then runs it again one mcycle at a time through the uarch (`run_uarch` plus `reset_uarch`). It
checks that both paths agree and that both priorities are equal and nonzero, or it exits 2 as a setup error. It
exits 0 if the claims return 1 then 2, and 1 if they don't.

Run `bugs/run.sh R1-R7-4`. On audit/prt2 it prints the following and exits 1. The reviewer re-ran it three times with
the same result each time, in well under a second.

```
native: priority1=1 priority2=1 claim#1=2 claim#2=1
uarch:  priority1=1 priority2=1 claim#1=2 claim#2=1
VIOLATED: R7 / PLIC spec: with sources 1 and 2 pending at equal priority, claims must return 1 then 2 (lowest ID first); the emulator returned 2 then 1
run.sh: R1-R7-4: exit 1 (bug present)
```

With the fix suggested below, the first claim takes `ctz(0x6) = 1` and marks it served. The second claim sees
`ipmask = 0x4` and returns 2, so the test exits 0. The test asserts what the PLIC specification requires, not an
artifact of the harness. Opus 5.5 found, proved and reviewed it; no fallback model was used.

### Trigger and reachability

The trigger is two or more PLIC sources pending at once when the guest claims. In the code, only the VirtIO devices
set PLIC pending bits (`plic_set_pending_irq` in `src/virtio-address-range.cpp`). VirtIO needs an unreproducible
machine, and the manual says: "(in unreproducible machines only) one or more VirtIO devices". A guest cannot write
`girqpend`: PLIC writes other than claim/complete are ignored, and R8 keeps the processor shadow read-only. In a
reproducible machine, the only way to get pending bits is the configuration itself (`processor.registers.plic.girqpend`),
which the emulator accepts, as the test shows. Whether that configuration counts as a valid template depends on
whether the RISC-V specification and the manual "allow" a pending source that no device can raise. Neither
explicitly forbids it. The rating below doesn't rely on that.

### Rating

1. Out of scope: not excluded. The relevant exclusion is "Nondeterminism in unreproducible machines (R14)". It covers
   only nondeterminism, and this deviation is deterministic and identical natively and through the uarch. The
   settled reading applies: "a deterministic deviation in a feature that only unreproducible machines reach (VirtIO,
   PLIC sources) is not out of scope". No other exclusion applies. The trigger doesn't need an untrusted caller of the
   machine API, a non-valid snapshot, or a deployment that breaks A1 to A8. "The effect of a deliberate state change
   made through the machine API" doesn't cover it either: the defect is in the claim semantics, not in the config
   write.
2. Role: the PLIC device. The AUDIT.md row "Interpreter, state-access layers, devices, uarch program, ..." gives it
   the Honest operator role, and that clause covers this component. Section 3: "The transition function ... play[s]
   this role in every deployment." The uarch program and the regenerated step share the behavior. They agree with the
   native interpreter, so there is no divergence between paths (R2).
3. High and Medium cases: the Medium case "An undocumented deterministic deviation, consistent across all paths, in
   behavior that no correct guest relies on for isolation or data integrity (R7)" fits. It is undocumented: the
   manual describes the device only as a PLIC (`riscv,plic0`) and states no claim order. It is deterministic and
   consistent: native and uarch both return 2 then 1. And no correct guest relies on it: PLIC priority ties only
   decide the order in which pending sources are claimed, and a correct driver claims until 0. This case has no
   reachability condition (settled reading), so it applies even though only an unreproducible machine, or a
   config-set `girqpend`, reaches the state. The rule violated is R7: "The emulator implements the RISC-V
   specification and the devices as the manual documents them, departing only where the manual documents a
   deviation."
4. Critical: not reached, because step 3 matched.

Two readings give different classes. Under the reading preferred here, Medium: the PLIC claim order is device
behavior that falls outside R7's listed areas. Under the alternative reading, Critical: PLIC claim order counts as
part of R7's area "Traps and interrupts", where "any deviation lets an input subvert a correct guest", so the Medium
case would not apply. This reading also needs a reachable state, which means a reproducible configuration with
`girqpend != 0` must count as a valid template (its registers holding "only values that the RISC-V specification and
the manual allow"). Two facts decide between them. First, does R7's "Traps and interrupts" cover the external
interrupt controller's choice among equal-priority sources, or only the processor's trap and interrupt architecture
(`mip`/`mie`, delegation, trap entry)? Second, do the manual or the specification allow a reproducible template with
PLIC sources pending? Neither the manual nor the threat model says.

### Possible solution and risks

Select the lowest pending source: `const uint32_t irq_id = __builtin_ctz(ipmask);` (`ipmask != 0` is already checked).
This changes the device behavior, so it is part of the state transition function (R13): the uarch binary, its pristine
hash and the regenerated `machine-solidity-step` must be rebuilt. If it ships as a new protocol version, the
machine-identification registers should change too (R13, A6). Reproducible machines with `girqpend = 0` see no change
in any hash, because the claim register then returns 0 either way. The behavior of unreproducible machines with
VirtIO changes in the order interrupts are served, which the Linux driver tolerates. Alternatively, the manual could
document the highest-ID-first order as a deviation, which would also resolve the R7 violation.

### Risk of not fixing it

No risk to the security goal. Reproducible machines in deployments have no PLIC source that can become pending
through execution, and the guest cannot set one. In unreproducible development machines, a guest that relied on the
specified lowest-ID-first order would serve VirtIO interrupts in a different order than on standard hardware. That is
a fidelity and portability issue, not a safety issue. The only remaining problem is that the emulator departs,
without saying so, from the device the manual names.
