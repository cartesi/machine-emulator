# R3-VARSPEC-3: CLINT has an undocumented active `msip` register at 0x02000000

## What is asserted

The manual (`doc/README.md`, `#### CLINT`) says:

> The Core Local Interruptor (or CLINT) controls the timer interrupt. The active addresses are `0x0200bff8`
> (`mtime`) and `0x02004000` (`mtimecmp`).

THREAT_MODEL.md R7:

> The emulator implements the RISC-V specification and the devices as the manual documents them, departing only
> where the manual documents a deviation. [...] Traps and interrupts.

`src/clint-address-range.cpp` also implements `msip0` at CLINT offset 0 (32-bit accesses only): an odd store sets
`mip.MSIP` (and returns `success_and_serve_interrupts`), an even store clears it, and a load reads it back. The
manual's CLINT section does not mention it. (The generated device tree in the manual lists `riscv,clint0` with
`interrupts-extended = <... 0x03 ... 0x07>`, which a reviewer may weigh as documentation.)

The test passes (exit 0) if either:

1. the manual's `#### CLINT` section mentions `msip`, `0x02000000` or "software interrupt"; or
2. on both the native interpreter and the uarch (run_uarch + reset_uarch per mcycle), a bare-metal M-mode
   `lui t0,0x2000; li t1,1; sw t1,0(t0)` raises a store/AMO access fault (`mcause` 7, `mtval` 0x02000000) and
   leaves `mip.MSIP` clear.

A control in the same run checks that a store to an inactive CLINT offset (0x02000010) does fault that way
(otherwise exit 2).

## Run

    bugs/run.sh R3-VARSPEC-3

No harness artifacts needed beyond the in-tree emulator build (the guest is 4 hand-encoded instructions).

## Expected output on audit/prt2

    manual CLINT section documents msip: false
    control: store to 0x02000010 -> store access fault (mcause 7), MSIP clear
    native: after 'sw 1 -> 0x02000000': mip=0x8 (MSIP=true) mcause=0x0 mtval=0x0 pc=0x8000000c
    uarch : after 'sw 1 -> 0x02000000': mip=0x8 (MSIP=true) mcause=0x0 mtval=0x0 pc=0x8000000c
    VIOLATED: R7 / manual '#### CLINT': ...
    run.sh: R3-VARSPEC-3: exit 1 (bug present)

The behavior is the same on both paths (deterministic, consistent), so this is a manual/behavior contradiction,
not a path divergence.
