# R1-R10-1: uarch-step verifiers accept uarch stores that the native uarch refuses as traps

## What is asserted

For four store addresses that the protocol layout fixes, the test builds a before-state from `baremetal-minimal`.
In each one the uarch is about to execute `sd rs2, imm(rs1)` from uarch RAM 0x600000. The four addresses are:

| case | store address | native refusal (`log_step_uarch`) |
|---|---|---|
| PMA array | 0x10000 | `attempted memory write to read-only PMAs` |
| shadow TLB | 0x1000 | `attempted memory word write to protected memory range shadow state` |
| HTIF tohost | 0x40008000 | `attempted memory write to HTIF device` |
| uarch x0 shadow word | 0x400018 (`sd x1,0x18(x2)`, x2 = 0x400000) | `register is read-only` |

For each case the test first checks that the native uarch refuses the step, which is a uarch trap. It then hand-builds
the step log in the access order of `src/uarch-step.cpp`, with every access carrying Merkle proofs of the before-state.
It requires that both verifiers **reject** that log:

- the regenerated machine-solidity-step (referee verifier): `StepVerifier.step` from the shared EVM harness's build
  (`bugs/harness/work/evm/out`). The test installs its runtime code with `anvil_setCode` on a private anvil, on a
  random port in 20000-29999, and stops that anvil at the end;
- the C++ replay verifier `cartesi.machine:verify_step_uarch` (support).

A control case is a legitimate store into uarch RAM at 0x600100. The native uarch must accept it, and both verifiers
must accept the same crafted log with the native after-hash. This check validates the log crafting; if it fails, the
test exits 2.

In every trap case the store address is computed from authenticated log data: rs1 comes from a logged register read,
and the immediate comes from the logged instruction word. The address falls in a range whose meaning the protocol
constants fix. The log therefore already authenticates the trap condition.

## Requirement (THREAT_MODEL.md, R3)

> The uarch traps when it executes an instruction it does not implement, an environment call it does not define or
> with arguments that call does not accept, an access that its memory map does not allow, or an abort it executes
> deliberately. [...] A verifier refuses a trap whenever the log it receives already authenticates the condition.

The definition of the state transition function says a state where the uarch traps "has no successor (R3)".

## How to run

```sh
bugs/run.sh R1-R10-1
```

Needs the in-tree emulator, `bugs/harness/work/configs/baremetal-minimal`, foundry (`anvil`, `cast`) from the harness,
`jq`, and the built StepVerifier artifact (`bugs/harness/solidity-step/evm/start.sh` must have run once). The test
takes about 10 s.

## Expected output on audit/prt2 (exit 1)

```
control: uarch RAM 0x600100        native: ok | C++ verify: accepted (= native) | EVM step: accepted (= native)
PMA array (0x10000)                native: TRAP (attempted memory write to read-only PMAs at address 0x10000(65536))
                                     C++ verify_step_uarch: ACCEPTED, after-hash 7bff4949...8397e
                                     EVM StepVerifier.step: ACCEPTED, after-hash 7bff4949...8397e
shadow TLB (0x1000)                native: TRAP (attempted memory word write to protected memory range shadow state ...)
                                     C++ verify_step_uarch: ACCEPTED, after-hash 700bad41...0c8a
                                     EVM StepVerifier.step: ACCEPTED, after-hash 700bad41...0c8a
HTIF tohost (0x40008000)           native: TRAP (attempted memory write to HTIF device at address 0x40008000 ...)
                                     C++ verify_step_uarch: ACCEPTED, after-hash 10be391c...7dbf
                                     EVM StepVerifier.step: ACCEPTED, after-hash 10be391c...7dbf
uarch x0 shadow word (0x400018)    native: TRAP (register is read-only)
                                     C++ verify_step_uarch: ACCEPTED, after-hash e852b425...ecbd
                                     EVM StepVerifier.step: ACCEPTED, after-hash e852b425...ecbd
VIOLATED: R3: ... 8 acceptance(s) of 8
run.sh: R1-R10-1: exit 1 (bug present)
```

Once both verifiers refuse these stores, the test exits 0.

These before-states have non-pristine uarch registers and uarch RAM. They are reached here through the machine API,
not from a valid template.
