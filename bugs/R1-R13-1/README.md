# R1-R13-1: the on-chain step verifier cannot be regenerated from audited source (undeclared `TLB_NUM_SETS`)

## What is asserted

`test.sh` regenerates machine-solidity-step v0.17.0-test1, the pinned referee verifier, from this branch, the way
the project does it, without hand edits. Then it builds the result:

1. It copies the untouched pinned checkout (`bugs/harness/work/solidity-step/released`, or `$MSS_DIR`) to a temp
   dir.
2. It runs `make generate-constants generate-step generate-reset generate-send-cmio-response generate-prod` with
   `EMULATOR_DIR` pointing at this repo's `src/`.
   - The constants come first, which gives the fixed point of the project's `make build` order.
   - `generate-constants` runs the project's `generate_EmulatorConstants.lua` with the in-tree Lua module, via a
     `docker` shim, instead of inside the emulator image. The harness has checked that the two give identical
     constants.
3. It runs `forge build --use 0.8.30`. This is the project's build: `src/` plus the `test/` contracts that import
   it.
4. It checks that the TLB constants that the generated `UArchStep.sol` relies on (`TLB_NUM_SETS`, `TLB_SET_SIZE`,
   `TLB_SLOT_LENGTH`) are defined in `EmulatorConstants.sol` and equal the emulator's values
   (`cartesi.TLB_NUM_SETS`, `TLB_SET_SIZE`, `SHADOW_TLB_SLOT_SIZE`). `TLB_SET_SIZE` and `TLB_SLOT_LENGTH` are
   hand-coded in the template.

Exit 1 if the build fails or a constant is missing or differs. Exit 0 if the verifier builds and the constants
agree. Exit 2 on setup errors (no pinned checkout, no forge or gpp, no in-tree module, generation failure, or a
build failure that is not a compiler error).

## Requirement

THREAT_MODEL.md R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes on-chain
must be reproducibly buildable from audited source." Also A6: every verifier, the uarch program and every honest
operator implement the same state transition function.

## Cause

Commit afd5f9d added `if (set_index >= TLB_NUM_SETS || slot_index >= TLB_SET_SIZE)` to the WRITE_TLB ecall in
`src/uarch-step.cpp`.

- The pinned `generate_UArchStep.sh` qualifies with `EmulatorConstants.` only the names that
  `src/EmulatorConstants.sol` defines.
- Neither `generate_EmulatorConstants.lua` nor `templates/EmulatorConstants.sol.template` defines `TLB_NUM_SETS`.
- So the bare identifier stays in `UArchStep.sol`, and solc fails with `Error (7576): Undeclared identifier`.

The shared harness had to add `uint64 constant TLB_NUM_SETS = 3;` by hand
(`bugs/harness/solidity-step/patches/01-tlb-num-sets.sh`).

## Run

```sh
bugs/run.sh R1-R13-1               # about 1 s
MSS_DIR=/path/to/fixed/mss bugs/run.sh R1-R13-1   # test a candidate fix of the generator
```

## Expected output on audit/prt2

```
== regenerated UArchStep.sol: TLB bound check (generated from src/uarch-step.cpp)
   1090:                set_index >= TLB_NUM_SETS
== forge build --use 0.8.30 (...)
   Error (7576): Undeclared identifier.
       --> src/UArchStep.sol:1090:30:
FAIL (R13): the verifier regenerated from audited source with the pinned generator does not build
== TLB constants of EmulatorConstants.sol vs the emulator
   TLB_NUM_SETS: not defined in EmulatorConstants.sol (emulator: 3)
FAIL (R13): UArchStep.sol uses TLB_NUM_SETS, which EmulatorConstants.sol does not define
   TLB_SET_SIZE = 256 (emulator: 256) OK
   TLB_SLOT_LENGTH = 32 (emulator: 32) OK
run.sh: R1-R13-1: exit 1 (bug present)
```

## Controls

These were run during proving and are not part of the test.

- **Constant added (exit 0).** A copy of the pinned checkout whose template defines `TLB_NUM_SETS = 3`, which is
  the harness workaround. The line regenerates as `EmulatorConstants.TLB_NUM_SETS`, the build passes, and the test
  exits 0.
- **Wrong value (exit 1).** The same copy with `TLB_NUM_SETS = 4` builds, but the test exits 1 on the constant
  check.
- **Order matters.** With the fixed template but the project's literal `make build` order (`generate-step` before
  `generate-constants`, starting from the released `EmulatorConstants.sol`), the first pass still fails. A fix in
  the generator also has to handle that ordering.
