# R1-R7-4: PLIC claim returns the highest pending source ID instead of the lowest

**Component**: PLIC device, `plic_read_claim_complete` in `src/plic-address-range.cpp`
(`const uint32_t irq_id = ilog2(ipmask);`).

## What is asserted

The emulator hardwires every PLIC source priority to the same level (reads of `priority1..31` return 1). With
sources 1 and 2 pending at once, a claim must return the pending source with the highest effective priority. At
equal priority, the PLIC specification gives that to the lowest ID. The test asserts that two consecutive claims
return 1 and then 2.

Requirements:

- THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents
  them, departing only where the manual documents a deviation." The manual (`doc/README.md`, "The board also maps
  non-memory devices ... CLINT, HTIF, PLIC") documents no PLIC claim ordering and no deviation.
- RISC-V PLIC specification: "Ties between global interrupts of the same priority are broken by the Interrupt ID;
  interrupts with the lowest ID have the highest effective priority." A claim returns "the ID of the
  highest-priority pending interrupt for the target".

## How it works

`test.lua` creates a minimal reproducible machine from an in-test config: 4 KiB of RAM, with
`processor.registers.plic.girqpend = 0x6`, so sources 1 and 2 are pending. It writes a 7-instruction M-mode
program into RAM. The program reads `priority1` and `priority2`, does two 32-bit loads of the claim register
(`0x40300004`) into `a0` and `a1`, and then spins. The test runs the program natively. As a cross-check it also
runs it one mcycle at a time through the uarch (`run_uarch` plus `reset_uarch`). Native and uarch must agree,
otherwise the run is a setup error.

Setting `girqpend` through the config only stands in for two VirtIO devices raising interrupts together. In
practice only VirtIO devices set PLIC pending bits, and they require an unreproducible machine
(`iunrep != 0`). A guest cannot write `girqpend`. The device logic under test is the same either way.

## Run

```sh
bugs/run.sh R1-R7-4
```

Exits 0 if the claims return 1 then 2 (the fix, for example `__builtin_ctz` instead of `ilog2`). Exits 1 if
the first claim returns 2. Exits 2 on setup errors. Runs in well under a second.

## Expected output on audit/prt2

```
native: priority1=1 priority2=1 claim#1=2 claim#2=1
uarch:  priority1=1 priority2=1 claim#1=2 claim#2=1
VIOLATED: R7 / PLIC spec: with sources 1 and 2 pending at equal priority, claims must return 1 then 2 (lowest ID first); the emulator returned 2 then 1
run.sh: R1-R7-4: exit 1 (bug present)
```

The deviation is deterministic, and native interpretation and the uarch agree on it.
