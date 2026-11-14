# R1-R7-2: Zcb compressed encodings execute although the documented ISA reserves them

## What is asserted

`test.lua` places one instruction at the start of RAM of a fresh 1 MiB machine, in M-mode with `mtvec` set, runs
one mcycle and checks whether it raised an illegal-instruction exception (`mcause` = 2, `pc` = `mtvec`). It probes
one encoding of each of the 12 Zcb instructions the interpreter implements (`c.lbu c.lhu c.lh c.sb c.sh c.zext.b
c.sext.b c.zext.h c.sext.h c.zext.w c.not c.mul`) plus `0x8000`, and, as references, the 32-bit Zbb/Zba
instructions `sext.b`, `zext.h`, `sext.h`, `add.uw`. Controls (`0x0000` traps, `nop` does not) guard the setup.

It asserts:

* (A) unless the manual documents Zcb (`doc/README.md` contains "Zcb"), every probed Zcb encoding traps;
* (B) `c.sext.b`, `c.zext.h`, `c.sext.h` (which Zcb defines only with Zbb) and `c.zext.w` (only with Zba) trap
  whenever their 32-bit prerequisite traps, documentation or not.

Each encoding is also run through the uarch (`run_uarch` + `reset_uarch`); this is printed for information only
and shows that the deviation is consistent across the native and uarch paths.

## Requirement

THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents them,
departing only where the manual documents a deviation." The manual (doc/README.md, "The main processor") says the
main processor "implements the `RV64IMAFDCZicsr_Zifencei` ISA"; its example DTB has `riscv,isa = "rv64acdfimsu"`.
In that ISA, quadrant-0 funct3=100 and quadrant-1 funct6=100111/funct2=1x are reserved, and executing them must
raise illegal instruction. The Zcb specification makes `c.sext.b/c.zext.h/c.sext.h` depend on Zbb and `c.zext.w`
on Zba, which this machine does not implement (the 32-bit forms trap).

## Run

    bugs/run.sh R1-R7-2

Runs in about a second. Exit 0 = fixed, 1 = bug present, 2 = setup error.

## Expected output on audit/prt2

All four 32-bit Zbb/Zba references trap; all 13 16-bit Zcb encodings execute (pc advances by 2, mcause untouched)
on both the native and the uarch paths; 17 `VIOLATION:` lines (13 for A, 4 for B), then

    VIOLATED: R7: reserved compressed encodings (Zcb, and Zcb forms of unimplemented Zbb/Zba) must raise illegal instruction unless the manual documents the extension
    run.sh: R1-R7-2: exit 1 (bug present)

A fix either makes these encodings trap, or documents Zcb in the manual and also implements (and documents) the
Zbb/Zba subset Zcb requires, or drops the Zbb/Zba-dependent Zcb encodings.
