# R9-SUBTLB-1: SRET from S to S clears MPRV without flushing the read/write TLB

`execute_SRET` (`src/interpret.cpp`) clears `mstatus.MPRV` when SPP < M, but flushes the TLB only through `set_prv`,
that is, only when the privilege changes. `execute_MRET` and `raise_exception` also flush the read/write TLB when the
effective data privilege changes while the privilege stays the same. SRET does not. For S-mode with MPRV=1 and MPP=U,
an SRET with SPP=S changes the effective data privilege from U to S and leaves the TLB as it was. Translations filled
at effective privilege U, including U pages, keep hitting in S-mode with SUM=0.

## What the test asserts

`test.lua` creates a machine from a configuration with iprv=S, `mstatus` MPRV=1, MPP=U, SPP=S and SUM=0, plus Sv39
`satp`. The configuration also sets stvec, sepc and medeleg. The guest (about 10 instructions) is hand-encoded in
the test, so no toolchain is needed. It works on a U page at VA 0xC0002000:

1. `ld` from the U page. At effective privilege U it succeeds and fills the read TLB.
2. `sret` with SPP=S. The guest stays in S-mode and MPRV becomes 0.
3. `ld` from the same U page. The test asserts that this load raises a load page fault: scause 13,
   sepc = the load, stval = the VA. It also asserts that the instruction after the load is not reached.

The control variant puts `sfence.vma` before step 3 and does fault. That shows a page walk refuses the access, so the
stale TLB entry is what lets the load through. The uarch path (`run_uarch` + `reset_uarch` per mcycle) runs the bug
variant too, and the test reports whether it agrees with the native run (informational only).

The test also passes (exit 0) under either of these alternative fixes:
- machine creation refuses iprv != M with MPRV=1;
- MPRV is ignored outside M-mode, in which case the first load faults.

## Requirement

THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents them,
departing only where the manual documents a deviation. ... In these areas, any deviation lets an input subvert a
correct guest, even a deviation that is consistent across all paths. ... Address translation and memory
permissions." RISC-V privileged specification, mstatus.SUM: "When SUM=0, S-mode memory accesses to pages that are
accessible by U-mode will fault." Also: "An MRET or SRET instruction that changes the privilege mode to a mode less
privileged than M also sets MPRV=0." The manual documents no TLB deviation.

Reachability: guest instructions cannot produce this state from an M-mode start. Only M-mode can write MPRV, and an
xRET to a mode below M clears it. The configuration is what produces it, and machine creation accepts it.

## Run

```sh
bugs/run.sh R9-SUBTLB-1
```

Expected output on audit/prt2 (exit 1, deterministic, well under 1 s):

```
native, no flush:            stage=3 trap=0 scause=0 sepc=0x0 stval=0x0 t0(1st ld)=0x1122334455667788 t2(2nd ld)=0x1122334455667788 MPRV=0 iprv=1
native, sfence.vma (control): stage=2 trap=1 scause=13 sepc=0x80000014 stval=0xc0002000 t0(1st ld)=0x1122334455667788 t2(2nd ld)=0x0 MPRV=0 iprv=1
uarch, no flush:             stage=3 trap=0 ... (same as native)
uarch and native agree on the bug variant
VIOLATED: R7 (address translation and memory permissions): after SRET clears MPRV, an S-mode load with SUM=0 from a U page must raise a load page fault (scause 13, stval = VA)
run.sh: R9-SUBTLB-1: exit 1 (bug present)
```
