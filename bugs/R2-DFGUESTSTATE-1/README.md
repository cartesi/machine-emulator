# R2-DFGUESTSTATE-1: satp accepts Sv48 although the manual documents Sv39 only

## What is asserted

`test.lua` builds a fresh 1 MiB machine, in M-mode, with the program `csrw satp, x5; csrr x6, satp;
ld x7, 0(x8)` at the start of RAM, and runs 3 mcycles. It asserts:

* unless the manual's section "The main processor" documents Sv48, writing satp with MODE = 9 (Sv48) has no
  effect: satp, and the guest's read-back, keep the previous value 0 (Bare).

Controls (exit 2 if they fail): a MODE = 8 (Sv39) write is accepted; a MODE = 10 (Sv57, compiled out) write is
ignored, which shows the interpreter applies the WARL rule to modes it does not support.

Information only (printed, not asserted):

* after the MODE = 9 write, an M-mode load with MPRV=1, MPP=S from VA `0x80_8002_0000` (non-canonical under
  Sv39, beyond every PMA in Bare mode) returns the data at PA `0x8002_0000` through a root-level 512 GiB
  terapage, so four-level walks are performed; the same load under Sv39 with the same table raises a load page
  fault (mcause 13);
* the uarch path (`run_uarch` + `reset_uarch` per mcycle) shows the same behavior: the deviation is consistent
  across paths (the hunter also checked the Solidity step; no divergence is claimed).

## Requirement

THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents
them, departing only where the manual documents a deviation. [...] Address translation and memory permissions."
Section 8: "A contradiction between the manual and the behavior on a security-relevant point is a defect in one
of the two. It takes the severity it would have if the manual were right."

The manual (doc/README.md, "The main processor"): "Cartesi Machines support the Sv39 mode of address translation
and memory protection. Sv39 provides a 39-bit protected virtual address space, divided into 4KiB pages,
organized by a three-level page table." The generated device tree says `mmu-type = "riscv,sv39"`. The RISC-V
privileged specification (satp): "if satp is written with an unsupported MODE, the entire write has no effect;
no fields in satp are modified." (The manual's flash-drive notes later reason about "the Sv48 address space";
they do not state that the processor supports Sv48.)

The test passes once either the interpreter rejects MODE = 9 (src/interpret.cpp `write_csr_satp`,
src/riscv-warl.hpp `WARL_satp`, src/translate-virtual-address.hpp), or the manual's "The main processor" section
documents Sv48.

## Run

    bugs/run.sh R2-DFGUESTSTATE-1

Runs in well under a second. Exit 0 = fixed, 1 = bug present, 2 = setup error.

## Expected output on audit/prt2

    control: write 0x8000000000080010 (Sv39) -> satp 0x8000000000080010 (accepted)
    control: write 0xa000000000080010 (Sv57) -> satp 0x0000000000000000 (ignored, WARL)
    probe:   write 0x9000000000080010 (Sv48) -> satp 0x9000000000080010, guest read-back 0x9000000000080010 (MODE 9)
    info:    MPRV load from VA 0x8080020000 (translatable only by Sv48): loaded 0x5356343821212121 from PA 0x80020000 via a root-level terapage
    info:    same load with the same table under Sv39: faulted (mcause=0xd, 13 = load page fault)
    info:    uarch path: satp 0x9000000000080010, read-back 0x9000000000080010, Sv48-only load translated
    manual, 'The main processor': documents Sv39 = true, documents Sv48 = false
    VIOLATION: satp.MODE=9 (Sv48) write took effect ...
    VIOLATED: R7: address translation as the manual documents it: ...
    run.sh: R2-DFGUESTSTATE-1: exit 1 (bug present)
