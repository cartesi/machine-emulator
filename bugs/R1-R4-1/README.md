# R1-R4-1: creation accepts a reproducible Keccak-256 configuration with a non-pristine uarch

## Requirement

THREAT_MODEL.md, R4 (Honest completeness):

> Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only
> register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A
> configuration that would not is rejected when the machine is created.

## What the test asserts

`test.lua` creates machines with `cartesi.machine(config)` from reproducible Keccak-256 configurations whose RAM is
the harness bare-metal guest `accept.bin`:

1. control: default uarch (must pass, otherwise exit 2);
2. `uarch.ram.backing_store.data_filename` = a 4 KiB file of `0xff` bytes (generated in a temp file);
3. `uarch.processor.registers.pc` = `UARCH_RAM_START_ADDRESS + 4` (an aligned pc inside uarch RAM).

For each, the requirement holds if creation raises, or if on the created machine
`collect_uarch_cycle_root_hashes(1, 0, tail)` and `log_step_uarch()` succeed and the uarch-path hash at mcycle 1
equals the native `run(1)` root hash. Exit 1 if a case is accepted and fails any of these.

## Run

```sh
bugs/run.sh R1-R4-1
```

## Expected output on audit/prt2

```
control (default uarch): accepted (uarch node pristine=true); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): ok; log_step_uarch: ok; uarch path agrees with native at mcycle 1
VIOLATED: R4 configuration clause: uarch.ram.backing_store.data_filename = 4 KiB of 0xff: accepted (uarch node pristine=false); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): error: microarchitecture is not pristine; log_step_uarch: error: illegal instruction
VIOLATED: R4 configuration clause: uarch.processor.registers.pc = 0x600004 (aligned, inside uarch RAM): accepted (uarch node pristine=false); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): error: microarchitecture is not pristine; log_step_uarch: ok
run.sh: R1-R4-1: exit 1 (bug present)
```

Both configurations are accepted. Native interpretation reaches mcycle 1. The honest operator's uarch-level claim
builder refuses the machine, and with the junk image the uarch traps on its first step. The test exits 1. A fix that
rejects these configurations at creation, as R4 asks, makes it exit 0. Loading a stored machine directory is a
separate path, and the test does not exercise it. (Case 3 counts only if a uarch pc of that value is a register
value "that the RISC-V specification and the manual allow". The manual places no constraint on uarch register values.)
Run time is under a second.
