# R3-VARSPEC-1: PMA first-word layout differs from the manual

**Asserted.** An M-mode guest loads each PMA `istart` word from the PMA array (`0x10000`), both natively and
through the uarch (the two must agree with each other and with `read_word`, otherwise it is a setup error). The test
decodes each word with the bit table that `doc/README.md`, section "PMAs", gives for the first word. It parses that
table from the manual, so a fix to either the code or the manual makes the test pass. It then requires:

- no entry has more than one of `M`, `IO`, `E` set;
- RAM (`0x80000000`) has M=1, IO=0, E=0, R=W=X=1, DID=`PMA_MEMORY_DID` (1);
- a read-only flash drive (`0x100000000`) has M=1, E=0, R=1, W=0, X=0, DID=`PMA_FLASH_DRIVE_DID` (3);
- the cmio rx buffer (`0x60000000`) has M=1, E=0, R=1, W=0, X=0, DID=`PMA_CMIO_RX_BUFFER_DID` (7).

**Requirement.** THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the
manual documents them, departing only where the manual documents a deviation." (area "Address translation and
memory permissions"). R13 counts "The state layout" as part of the transition function. Section 8 says: "A
contradiction between the manual and the behavior on a security-relevant point is a defect in one of the two."
The manual describes the first word as `start(63-12) DID(11-8) IW(7) IR(6) X(5) W(4) R(3) E(2) IO(1) M(0)`, "readable
both internally and externally", with M/IO/E mutually exclusive. `src/pmas-constants.hpp` packs
`M=0 IO=1 R=2 W=3 X=4 IR=5 IW=6 DID=7..11` and has no E bit.

**Run.** `bugs/run.sh R3-VARSPEC-1` takes about 1 s. To check that a manual-side fix is accepted:
`MANUAL_OVERRIDE=<edited README.md> bugs/run.sh R3-VARSPEC-1`. With the table rewritten to the code's layout,
the test exits 0.

**Expected on audit/prt2.** Exit 1. Decoded with the manual's table, every entry has E=1 together with M or IO.
RAM decodes with DID=0. The read-only flash drive decodes as not readable, executable, DID 1. The rx buffer decodes
as not readable, executable, DID 3. For example, the guest reads RAM's word as `0x800000fd`.
